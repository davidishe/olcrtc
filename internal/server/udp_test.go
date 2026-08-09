package server

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/socks5udp"
)

// pipeStream adapts a net.Pipe half to the io.ReadWriter the relay expects.
type pipeStream struct{ net.Conn }

// newEchoServer starts a UDP responder that mirrors payloads back.
func newEchoServer(t *testing.T, transform func([]byte) []byte) *net.UDPAddr {
	t.Helper()

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := buf[:n]
			if transform != nil {
				reply = transform(buf[:n])
			}
			if _, err := conn.WriteTo(reply, peer); err != nil {
				return
			}
		}
	}()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", conn.LocalAddr())
	}
	return addr
}

// runRelay wires a relay to one half of a pipe and returns the client half.
func runRelay(t *testing.T) (net.Conn, *udpRelay) {
	t.Helper()

	serverSide, clientSide := net.Pipe()
	relay := &udpRelay{
		stream: pipeStream{serverSide},
		dialer: &net.Dialer{Timeout: udpDialTimeout},
		flows:  make(map[string]*udpFlow),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = relay.run()
		relay.shutdown()
	}()

	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
		wg.Wait()
	})
	return clientSide, relay
}

func addrOf(t *testing.T, udp *net.UDPAddr) socks5udp.Addr {
	t.Helper()
	addr, err := socks5udp.EncodeAddr(udp.IP.String(), udp.Port)
	if err != nil {
		t.Fatalf("EncodeAddr() error = %v", err)
	}
	return addr
}

func TestUDPRelayRoundTrip(t *testing.T) {
	echo := newEchoServer(t, nil)
	client, _ := runRelay(t)

	addr := addrOf(t, echo)
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5udp.WriteFrame(client, addr, []byte("ping")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	gotAddr, payload, err := socks5udp.ReadFrame(client, make([]byte, socks5udp.MaxPayload))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want %q", payload, "ping")
	}
	if !bytes.Equal(gotAddr.Bytes(), addr.Bytes()) {
		t.Fatalf("reply address = %q, want %q", gotAddr.String(), addr.String())
	}
}

// Clients using mapped DNS match replies against the exact address they sent,
// so a domain destination must come back as that domain and not as the IP the
// relay actually resolved it to.
func TestUDPRelayEchoesRequestedAddress(t *testing.T) {
	echo := newEchoServer(t, nil)
	client, _ := runRelay(t)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	addr, err := socks5udp.EncodeAddr("localhost", echo.Port)
	if err != nil {
		t.Fatalf("EncodeAddr() error = %v", err)
	}
	if err := socks5udp.WriteFrame(client, addr, []byte("ping")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	gotAddr, _, err := socks5udp.ReadFrame(client, make([]byte, socks5udp.MaxPayload))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if gotAddr.String() != "localhost:"+strconv.Itoa(echo.Port) {
		t.Fatalf("reply address = %q, want the requested domain", gotAddr.String())
	}
}

// Two destinations share one stream, so the relay must keep a socket per
// destination and tag every reply with the destination it came from.
func TestUDPRelayMultiplexesDestinations(t *testing.T) {
	first := newEchoServer(t, func(b []byte) []byte { return append([]byte("a:"), b...) })
	second := newEchoServer(t, func(b []byte) []byte { return append([]byte("b:"), b...) })
	client, relay := runRelay(t)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	for _, echo := range []*net.UDPAddr{first, second} {
		if err := socks5udp.WriteFrame(client, addrOf(t, echo), []byte("x")); err != nil {
			t.Fatalf("WriteFrame() error = %v", err)
		}
	}

	seen := map[string]string{}
	scratch := make([]byte, socks5udp.MaxPayload)
	for range 2 {
		addr, payload, err := socks5udp.ReadFrame(client, scratch)
		if err != nil {
			t.Fatalf("ReadFrame() error = %v", err)
		}
		seen[addr.String()] = string(payload)
	}

	if got := seen[addrOf(t, first).String()]; got != "a:x" {
		t.Fatalf("first reply = %q, want %q", got, "a:x")
	}
	if got := seen[addrOf(t, second).String()]; got != "b:x" {
		t.Fatalf("second reply = %q, want %q", got, "b:x")
	}

	relay.mu.Lock()
	flows := len(relay.flows)
	relay.mu.Unlock()
	if flows != 2 {
		t.Fatalf("flows = %d, want 2", flows)
	}
}

// A destination that cannot be reached must drop just that datagram; the rest
// of the stream keeps working.
func TestUDPRelaySurvivesUnreachableDestination(t *testing.T) {
	echo := newEchoServer(t, nil)
	client, _ := runRelay(t)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	bad, err := socks5udp.EncodeAddr("no-such-host.invalid", 53)
	if err != nil {
		t.Fatalf("EncodeAddr() error = %v", err)
	}
	if err := socks5udp.WriteFrame(client, bad, []byte("dropped")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if err := socks5udp.WriteFrame(client, addrOf(t, echo), []byte("ping")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}

	_, payload, err := socks5udp.ReadFrame(client, make([]byte, socks5udp.MaxPayload))
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("payload = %q, want %q", payload, "ping")
	}
}

func TestUDPRelayCountsTraffic(t *testing.T) {
	echo := newEchoServer(t, nil)
	client, relay := runRelay(t)

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5udp.WriteFrame(client, addrOf(t, echo), []byte("12345")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, _, err := socks5udp.ReadFrame(client, make([]byte, socks5udp.MaxPayload)); err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}

	if got := relay.bytesOut.Load(); got != 5 {
		t.Fatalf("bytesOut = %d, want 5", got)
	}
	if got := relay.bytesIn.Load(); got != 5 {
		t.Fatalf("bytesIn = %d, want 5", got)
	}
}

// Closing the client end must release every socket the stream accumulated.
func TestUDPRelayShutdownReleasesFlows(t *testing.T) {
	echo := newEchoServer(t, nil)

	serverSide, clientSide := net.Pipe()
	relay := &udpRelay{
		stream: pipeStream{serverSide},
		dialer: &net.Dialer{Timeout: udpDialTimeout},
		flows:  make(map[string]*udpFlow),
	}

	done := make(chan struct{})
	go func() {
		_ = relay.run()
		relay.shutdown()
		close(done)
	}()

	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5udp.WriteFrame(clientSide, addrOf(t, echo), []byte("ping")); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if _, _, err := socks5udp.ReadFrame(clientSide, make([]byte, socks5udp.MaxPayload)); err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}

	_ = clientSide.Close()
	_ = serverSide.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not shut down")
	}

	relay.mu.Lock()
	flows := len(relay.flows)
	relay.mu.Unlock()
	if flows != 0 {
		t.Fatalf("flows after shutdown = %d, want 0", flows)
	}
}

func TestUDPRelayStopsOnMalformedFrame(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	relay := &udpRelay{
		stream: pipeStream{serverSide},
		dialer: &net.Dialer{Timeout: udpDialTimeout},
		flows:  make(map[string]*udpFlow),
	}

	errCh := make(chan error, 1)
	go func() {
		err := relay.run()
		relay.shutdown()
		errCh <- err
	}()

	_ = clientSide.SetDeadline(time.Now().Add(5 * time.Second))
	// HDRLEN of 4 cannot hold even an IPv4 address, so the relay rejects the
	// message on the header alone.
	if _, err := clientSide.Write([]byte{0x00, 0x00, 0x04}); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, socks5udp.ErrMalformedFrame) {
			t.Fatalf("run() error = %v, want %v", err, socks5udp.ErrMalformedFrame)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not reject the frame")
	}
	_ = clientSide.Close()
}
