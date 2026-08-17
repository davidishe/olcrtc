package handshake_test

import (
	"net"
	"slices"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/handshake"
)

func runHandshake(t *testing.T, caps []string) ([]string, error) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	done := make(chan error, 1)
	go func() {
		_, _, err := handshake.ServerWithCaps(serverConn, func(string, map[string]any) (string, error) {
			return "session-1", nil
		}, caps)
		done <- err
	}()

	_, gotCaps, err := handshake.ClientWithCaps(clientConn, "device-1", nil)
	if serverErr := <-done; serverErr != nil {
		t.Fatalf("server handshake: %v", serverErr)
	}
	return gotCaps, err
}

func TestWelcomeCarriesServerCapabilities(t *testing.T) {
	t.Parallel()

	caps, err := runHandshake(t, []string{handshake.CapConnectPipeline})
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if !slices.Contains(caps, handshake.CapConnectPipeline) {
		t.Fatalf("caps = %v, want to contain %q", caps, handshake.CapConnectPipeline)
	}
}

// A server that advertises nothing — an agent built before capabilities
// existed — must leave the client on the conservative path rather than fail.
func TestWelcomeWithoutCapabilitiesIsAccepted(t *testing.T) {
	t.Parallel()

	caps, err := runHandshake(t, nil)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if len(caps) != 0 {
		t.Fatalf("caps = %v, want none", caps)
	}
}

// Client is the pre-capabilities entry point and must keep working unchanged.
func TestLegacyClientEntryPointStillReturnsSession(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	go func() {
		_, _, _ = handshake.ServerWithCaps(serverConn, func(string, map[string]any) (string, error) {
			return "session-1", nil
		}, []string{handshake.CapConnectPipeline})
	}()

	sid, err := handshake.Client(clientConn, "device-1", nil)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if sid != "session-1" {
		t.Fatalf("session = %q, want %q", sid, "session-1")
	}
}
