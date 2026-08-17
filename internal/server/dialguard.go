package server

import (
	"errors"
	"net"
	"sync"
	"time"
)

// A background service on the phone that retries an unreachable address every
// few seconds costs a full dial timeout each time. Those dials sit in the KCP
// window and hold a smux stream for ten seconds while doing nothing, which is
// pure loss for every other connection sharing the tunnel.
//
// dialGuard remembers addresses that just timed out and refuses them
// immediately for a short while, so the retry storm costs one round trip
// instead of ten seconds. It deliberately reacts only to timeouts: a refused
// connection or a DNS failure already fails fast and may be a legitimate
// transient, while a timeout means nobody answered at all.
const (
	// dialGuardThreshold is how many consecutive timeouts an address needs
	// before it is blocked. One timeout can be a blip; two in a row on the
	// same address is a pattern.
	dialGuardThreshold = 2
	// dialGuardCooldown is how long the block lasts. Short enough that a host
	// coming back is picked up quickly, long enough to swallow a retry storm.
	dialGuardCooldown = 60 * time.Second
	// dialGuardCapacity bounds the map so a client dialling many distinct dead
	// addresses cannot grow it without limit.
	dialGuardCapacity = 512
)

// errDialSuppressed is returned instead of dialling an address that is in
// cooldown. It is reported to the client the same way a failed dial is — the
// stream simply closes — so no protocol change is involved.
var errDialSuppressed = errors.New("dial suppressed: address timed out repeatedly")

type dialGuardEntry struct {
	failures int
	blockAt  time.Time
}

type dialGuard struct {
	mu      sync.Mutex
	entries map[string]dialGuardEntry
	now     func() time.Time // injectable for tests
}

func newDialGuard() *dialGuard {
	return &dialGuard{
		entries: make(map[string]dialGuardEntry),
		now:     time.Now,
	}
}

// blocked reports whether addr is currently in cooldown.
func (g *dialGuard) blocked(addr string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.entries[addr]
	if !ok || e.blockAt.IsZero() {
		return false
	}
	if g.now().Sub(e.blockAt) >= dialGuardCooldown {
		// Cooldown expired: let one dial through to probe whether the host is
		// back. Clearing the counter too means a host that is still dead pays
		// the threshold again before being blocked, which is the price of not
		// blacklisting anything permanently.
		delete(g.entries, addr)
		return false
	}
	return true
}

// recordTimeout counts a dial timeout and reports whether this pushed the
// address into cooldown.
func (g *dialGuard) recordTimeout(addr string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.entries) >= dialGuardCapacity {
		g.evictExpiredLocked()
	}
	e, existed := g.entries[addr]
	if !existed && len(g.entries) >= dialGuardCapacity {
		// Still full after eviction: drop the sample rather than grow the map.
		// Missing a block is cheaper than unbounded memory on the agent.
		return false
	}
	e.failures++
	justBlocked := false
	if e.failures >= dialGuardThreshold && e.blockAt.IsZero() {
		e.blockAt = g.now()
		justBlocked = true
	}
	g.entries[addr] = e
	return justBlocked
}

// recordSuccess forgets an address that answered.
func (g *dialGuard) recordSuccess(addr string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.entries, addr)
	g.mu.Unlock()
}

// evictExpiredLocked drops entries whose cooldown has elapsed. Callers hold mu.
func (g *dialGuard) evictExpiredLocked() {
	now := g.now()
	for addr, e := range g.entries {
		if e.blockAt.IsZero() || now.Sub(e.blockAt) >= dialGuardCooldown {
			delete(g.entries, addr)
		}
	}
}

// isTimeout reports whether err is a network timeout, including the timeouts
// net.Dialer wraps in *net.OpError.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
