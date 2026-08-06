package server

import (
	"testing"
	"time"
)

func TestDisconnectDevice_Empty(t *testing.T) {
	s := &Server{
		peerSessions: make(map[string]*peerSession),
		peerStats:    make(map[string]peerStat),
	}
	if n := s.DisconnectDevice(""); n != 0 {
		t.Fatalf("empty device closed %d", n)
	}
	if n := s.DisconnectDevice("missing"); n != 0 {
		t.Fatalf("missing device closed %d", n)
	}
}

func TestDisconnectSession_NotFound(t *testing.T) {
	s := &Server{
		peerSessions: make(map[string]*peerSession),
		peerStats:    make(map[string]peerStat),
	}
	if err := s.DisconnectSession(""); err != ErrSessionNotFound {
		t.Fatalf("empty: %v", err)
	}
	if err := s.DisconnectSession("nope"); err != ErrSessionNotFound {
		t.Fatalf("missing: %v", err)
	}
}

func TestActiveSessions_Snapshot(t *testing.T) {
	s := &Server{
		peerSessions: make(map[string]*peerSession),
		peerStats: map[string]peerStat{
			"sid-1": {deviceID: "dev-a", openedAt: time.Now()},
			"sid-2": {deviceID: "dev-b", openedAt: time.Now()},
		},
	}
	got := s.ActiveSessions()
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
}
