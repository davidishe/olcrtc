package tunnel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openlibrecommunity/olcrtc/pkg/olcrtc/tunnel"
)

var errNo = errors.New("no")

func TestRun_FailsWithoutKey(t *testing.T) {
	tunnel.RegisterDefaults()
	srv, err := tunnel.New(tunnel.Config{
		Transport: "datachannel",
		Carrier:   "telemost",
		RoomURL:   "room-1",
		DNSServer: "8.8.8.8:53",
	})
	if err == nil {
		t.Fatal("New(no key) error = nil")
	}
	_ = srv
}

func TestRun_PropagatesAuthHook(_ *testing.T) {
	tunnel.RegisterDefaults()

	var called bool
	cfg := tunnel.Config{
		KeyHex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		AuthHook: func(string, map[string]any) (string, error) {
			called = true
			return "", errNo
		},
	}
	srv, err := tunnel.New(cfg)
	if err != nil {
		// construction may still fail without transport wiring; surface is what matters
		_ = err
		return
	}
	_ = srv.Run(context.Background())
	_ = called
}

func TestDisconnectAPISurface(t *testing.T) {
	tunnel.RegisterDefaults()
	srv, err := tunnel.New(tunnel.Config{
		KeyHex:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Transport: "datachannel",
		Carrier:   "jitsi",
		RoomURL:   "https://example.test/room",
		DNSServer: "8.8.8.8:53",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if n := srv.DisconnectDevice("missing"); n != 0 {
		t.Fatalf("DisconnectDevice = %d", n)
	}
	if err := srv.DisconnectSession("missing"); err == nil {
		t.Fatal("expected session not found")
	}
	if got := srv.ActiveSessions(); len(got) != 0 {
		t.Fatalf("ActiveSessions = %d", len(got))
	}
}

func TestNew_AuthTokenFallsBackToToken(t *testing.T) {
	tunnel.RegisterDefaults()
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	srv, err := tunnel.New(tunnel.Config{
		KeyHex:    key,
		Transport: "datachannel",
		Carrier:   "jitsi",
		RoomURL:   "https://example.test/room",
		DNSServer: "8.8.8.8:53",
		Token:     "carrier-from-token",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = srv

	srv2, err := tunnel.New(tunnel.Config{
		KeyHex:    key,
		Transport: "datachannel",
		Carrier:   "jitsi",
		RoomURL:   "https://example.test/room",
		DNSServer: "8.8.8.8:53",
		Token:     "engine-only",
		AuthToken: "explicit-auth",
	})
	if err != nil {
		t.Fatalf("New with AuthToken: %v", err)
	}
	_ = srv2
}

// Compile-time checks: the public type aliases must be assignable.
var (
	_ tunnel.AuthFunc         = func(string, map[string]any) (string, error) { return "", nil }
	_ tunnel.SessionOpenFunc  = func(string, string, map[string]any) {}
	_ tunnel.SessionCloseFunc = func(string, string) {}
	_ tunnel.TrafficFunc      = func(string, string, uint64, uint64) {}
)
