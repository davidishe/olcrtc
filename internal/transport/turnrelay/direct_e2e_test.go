package turnrelay_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/client"
	"github.com/openlibrecommunity/olcrtc/internal/server"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/transport/turnrelay"
)

func TestDirectKCPTunnelSOCKS(t *testing.T) {
	transport.Register("turnrelay", turnrelay.New)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(key)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	target := ln.Addr().String()

	udpLn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := udpLn.LocalAddr().String()
	_ = udpLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- server.Run(ctx, server.Config{
			Transport:  "turnrelay",
			Carrier:    "none",
			KeyHex:     keyHex,
			DNSServer:  "8.8.8.8:53",
			ListenAddr: listenAddr,
			TransportOptions: turnrelay.Options{
				ListenAddr: listenAddr,
			},
			AuthHook: func(deviceID string, _ map[string]any) (string, error) {
				return "sess-" + deviceID, nil
			},
		})
	}()

	// Give the server a moment to bind.
	time.Sleep(200 * time.Millisecond)

	socksLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksAddr := socksLn.Addr().String()
	_ = socksLn.Close()

	ready := make(chan struct{})
	go func() {
		errCh <- client.RunWithReady(ctx, client.Config{
			Transport: "turnrelay",
			Carrier:   "none",
			KeyHex:    keyHex,
			LocalAddr: socksAddr,
			DNSServer: "8.8.8.8:53",
			DeviceID:  "direct-e2e",
			Endpoint:  listenAddr,
			TransportOptions: turnrelay.Options{
				Endpoint: listenAddr,
				Direct:   true,
			},
		}, func() { close(ready) })
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("startup failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for client ready")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// SOCKS5 no-auth handshake + CONNECT
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("socks auth resp %v", resp)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("target not ipv4: %s", host)
	}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("socks connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("socks connect failed status=%d", reply[1])
	}

	cancel()
}
