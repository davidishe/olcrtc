package server

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// The agent must accept both framings so a client and an agent can be upgraded
// in either order: an old client sends bare JSON, a new one terminates the
// request with a newline and appends payload behind it.
func TestParseStreamRequestAcceptsBothFramings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		buf       string
		wantOK    bool
		wantAddr  string
		wantEarly string
	}{
		{
			name:     "legacy bare json",
			buf:      `{"cmd":"connect","addr":"example.com","port":443}`,
			wantOK:   true,
			wantAddr: "example.com",
		},
		{
			name:     "pipelined without payload yet",
			buf:      `{"cmd":"connect","addr":"example.com","port":443}` + "\n",
			wantOK:   true,
			wantAddr: "example.com",
		},
		{
			name:      "pipelined with early payload",
			buf:       `{"cmd":"connect","addr":"example.com","port":443}` + "\nGET / HTTP/1.1\r\n\r\n",
			wantOK:    true,
			wantAddr:  "example.com",
			wantEarly: "GET / HTTP/1.1\r\n\r\n",
		},
		{
			name:      "early payload may itself contain newlines",
			buf:       `{"cmd":"udp"}` + "\nline1\nline2\n",
			wantOK:    true,
			wantEarly: "line1\nline2\n",
		},
		{
			name:   "incomplete request keeps caller reading",
			buf:    `{"cmd":"connect","addr":"exa`,
			wantOK: false,
		},
		{
			name:   "unknown command is not a request",
			buf:    `{"cmd":"nope","addr":"example.com","port":443}`,
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, early, ok := parseStreamRequest([]byte(tt.buf))
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if tt.wantAddr != "" && req.Addr != tt.wantAddr {
				t.Errorf("addr = %q, want %q", req.Addr, tt.wantAddr)
			}
			if string(early) != tt.wantEarly {
				t.Errorf("early = %q, want %q", early, tt.wantEarly)
			}
		})
	}
}

// A payload that happens to start with a newline must not be mistaken for the
// pipelined framing when the request itself has not arrived yet.
func TestParseStreamRequestIgnoresNewlineBeforeValidRequest(t *testing.T) {
	t.Parallel()

	if _, _, ok := parseStreamRequest([]byte("\n{\"cmd\":\"connect\"")); ok {
		t.Fatal("partial request accepted")
	}
}

func TestDialGuardBlocksAfterRepeatedTimeouts(t *testing.T) {
	t.Parallel()

	now := time.Now()
	g := newDialGuard()
	g.now = func() time.Time { return now }

	const addr = "194.221.250.50:443"

	if g.blocked(addr) {
		t.Fatal("blocked before any failure")
	}
	if blocked := g.recordTimeout(addr); blocked {
		t.Fatal("blocked after a single timeout — one timeout can be a blip")
	}
	if g.blocked(addr) {
		t.Fatal("blocked below threshold")
	}
	if blocked := g.recordTimeout(addr); !blocked {
		t.Fatalf("not blocked after %d timeouts", dialGuardThreshold)
	}
	if !g.blocked(addr) {
		t.Fatal("address not in cooldown")
	}

	// A host that comes back must be reachable again once cooldown elapses.
	now = now.Add(dialGuardCooldown + time.Second)
	if g.blocked(addr) {
		t.Fatal("still blocked after cooldown expired")
	}
}

func TestDialGuardForgetsAddressThatAnswers(t *testing.T) {
	t.Parallel()

	g := newDialGuard()
	const addr = "example.com:443"

	g.recordTimeout(addr)
	g.recordSuccess(addr)

	// The counter is cleared, so the next timeout starts from scratch rather
	// than immediately tipping a working host into cooldown.
	if blocked := g.recordTimeout(addr); blocked {
		t.Fatal("a single timeout after a success put the address in cooldown")
	}
}

func TestDialGuardIsBoundedInSize(t *testing.T) {
	t.Parallel()

	g := newDialGuard()
	for i := range dialGuardCapacity * 2 {
		g.recordTimeout(net.JoinHostPort("10.0.0.1", strconv.Itoa(1024+i)))
	}
	if len(g.entries) > dialGuardCapacity {
		t.Fatalf("entries = %d, want at most %d", len(g.entries), dialGuardCapacity)
	}
}
