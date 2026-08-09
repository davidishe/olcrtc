package e2e

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/socks5udp"
)

// startUDPEchoServer starts a datagram responder that mirrors what it receives.
func startUDPEchoServer(t *testing.T) *net.UDPAddr {
	t.Helper()

	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(buf[:n], peer); err != nil {
				return
			}
		}
	}()

	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() = %T, want *net.UDPAddr", pc.LocalAddr())
	}
	return addr
}

// openUDPRelayViaSOCKS performs the SOCKS5 handshake and asks for the
// UDP-in-TCP relay, the way hev-socks5-tunnel does.
func openUDPRelayViaSOCKS(t *testing.T, socksAddr string) net.Conn {
	t.Helper()

	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp4", socksAddr)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("write socks greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("read socks greeting: %v", err)
	}
	if !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("socks greeting = %v, want [5 0]", greeting)
	}

	// The request address is a placeholder; each datagram names its own
	// destination.
	request := []byte{5, socks5udp.CmdUDPInTCP, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write socks udp request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read socks reply: %v", err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("socks reply = %v, want success", reply)
	}
	return conn
}

func TestUDPRelayOverTunnel(t *testing.T) {
	echo := startUDPEchoServer(t)
	rt := startTunnel(t)
	defer rt.stop(t)

	relay := openUDPRelayViaSOCKS(t, rt.socksAddr)
	if err := relay.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	addr, err := socks5udp.EncodeAddr(echo.IP.String(), echo.Port)
	if err != nil {
		t.Fatalf("EncodeAddr() error = %v", err)
	}

	payload := []byte("olcrtc-udp-e2e")
	if err := socks5udp.WriteFrame(relay, addr, payload); err != nil {
		t.Fatalf("write udp frame: %v", err)
	}

	gotAddr, got, err := socks5udp.ReadFrame(relay, make([]byte, socks5udp.MaxPayload))
	if err != nil {
		t.Fatalf("read udp frame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo = %q, want %q", got, payload)
	}
	if gotAddr.String() != addr.String() {
		t.Fatalf("reply address = %q, want %q", gotAddr.String(), addr.String())
	}
}

// A single relay stream carries every destination, so datagrams must stay
// separated on the way back.
func TestUDPRelayOverTunnelMultiplexes(t *testing.T) {
	first := startUDPEchoServer(t)
	second := startUDPEchoServer(t)
	rt := startTunnel(t)
	defer rt.stop(t)

	relay := openUDPRelayViaSOCKS(t, rt.socksAddr)
	if err := relay.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	want := map[string]string{}
	for i, echo := range []*net.UDPAddr{first, second} {
		addr, err := socks5udp.EncodeAddr(echo.IP.String(), echo.Port)
		if err != nil {
			t.Fatalf("EncodeAddr() error = %v", err)
		}
		payload := string(rune('a' + i))
		want[addr.String()] = payload
		if err := socks5udp.WriteFrame(relay, addr, []byte(payload)); err != nil {
			t.Fatalf("write udp frame: %v", err)
		}
	}

	scratch := make([]byte, socks5udp.MaxPayload)
	got := map[string]string{}
	for range len(want) {
		addr, payload, err := socks5udp.ReadFrame(relay, scratch)
		if err != nil {
			t.Fatalf("read udp frame: %v", err)
		}
		got[addr.String()] = string(payload)
	}

	for addr, payload := range want {
		if got[addr] != payload {
			t.Fatalf("reply for %s = %q, want %q", addr, got[addr], payload)
		}
	}
}
