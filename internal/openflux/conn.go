// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: document frame parsing, dedup, and per-packet accounting.
// The session lifecycle (dial, read, seamless rotation) lives in session.go.

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cursorPrefix  = `42["message",{"type":"cursor","cursor":"18;`
	cursorSuffix  = `"}]`
	kaMarker      = "---KA---"
	slowWrite     = 500 * time.Millisecond
	echoRingSize  = 4096
	recvRingSize  = 4096
	frameLogLimit = 400
	shapeLogLimit = 6
	lateLag       = time.Second
	lateLogEvery  = 10 * time.Second
)

//nolint:gochecknoglobals // compiled once
var (
	blobRe   = regexp.MustCompile(`[A-Za-z0-9+/=_.\-]{32,}`)
	typeRe   = regexp.MustCompile(`"type":"([A-Za-z]+)"`)
	userRe   = regexp.MustCompile(`"user":"([^"]{1,64})"`)
	timeRe   = regexp.MustCompile(`"time":(\d{13})`)
	userIDRe = regexp.MustCompile(`"id":"([^"]{1,64})"`)
)

// hashRing is a fixed-size set of recent hashes for echo/duplicate suppression.
type hashRing struct {
	mu   sync.Mutex
	set  map[uint64]struct{}
	ring []uint64
	pos  int
}

func newHashRing(n int) *hashRing {
	return &hashRing{set: make(map[uint64]struct{}, n), ring: make([]uint64, n)}
}

func (r *hashRing) add(h uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.insert(h)
}

func (r *hashRing) insert(h uint64) {
	if old := r.ring[r.pos]; old != 0 {
		delete(r.set, old)
	}
	r.ring[r.pos] = h
	r.set[h] = struct{}{}
	r.pos = (r.pos + 1) % len(r.ring)
}

func (r *hashRing) has(h uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.set[h]
	return ok
}

// addIfNew records h and reports whether it was unseen.
func (r *hashRing) addIfNew(h uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.set[h]; ok {
		return false
	}
	r.insert(h)
	return true
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

type docConn struct {
	docURL   string
	st       *stats
	deliver  func([]byte)
	sendQ    chan []byte
	baseUser string

	txData       atomic.Int64
	lastTxData   atomic.Int64
	lastRxData   atomic.Int64
	stallSince   atomic.Int64
	lateLogAt    atomic.Int64
	participants atomic.Int64

	echo *hashRing // our own outgoing payloads, so their broadcast is ignored
	recv *hashRing // incoming data payloads, deduped across overlapping sessions

	shapesMu   sync.Mutex
	shapesSeen map[string]int

	probe probeState

	// Supervisor state (see session.go). Guarded by mu; active is read from
	// the writer/keepalive/probe goroutines, the rest only from the manager.
	mu       sync.Mutex
	active   *session
	sessions map[int]*session
	nextID   int
	rotating bool
	attempt  int

	runCtx context.Context //nolint:containedctx // set once by loop, read by session goroutines
	events chan sessionEvent
}

func (c *docConn) participantsSwap(n int64) int64 { return c.participants.Swap(n) }

func newDocConn(docURL string, st *stats, deliver func([]byte)) *docConn {
	return &docConn{
		docURL:     docURL,
		st:         st,
		deliver:    deliver,
		sendQ:      make(chan []byte, queueSize),
		baseUser:   fmt.Sprintf("%010d", rand.IntN(1_000_000_000)), //nolint:gosec // not a secret
		echo:       newHashRing(echoRingSize),
		recv:       newHashRing(recvRingSize),
		shapesSeen: map[string]int{},
		sessions:   map[int]*session{},
		events:     make(chan sessionEvent, 32),
	}
}

func (c *docConn) queueLen() int { return len(c.sendQ) }

// isUp reports whether a promoted session is ready to carry traffic.
func (c *docConn) isUp() bool {
	s := c.currentActive()
	return s != nil && s.ready.Load()
}

func (c *docConn) currentActive() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

func (c *docConn) stateText() string {
	s := c.currentActive()
	if s == nil || !s.ready.Load() {
		return "down"
	}
	c.mu.Lock()
	live := len(c.sessions)
	c.mu.Unlock()
	return fmt.Sprintf("up%ds/n%d", int(time.Since(s.startedAt).Seconds()), live)
}

// send queues one packet payload (already compressed).
func (c *docConn) send(payload []byte) {
	if !c.isUp() {
		c.st.notConnDrops.Add(1)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(payload)
	select {
	case c.sendQ <- []byte(b64):
		c.st.sendQHigh.observe(int64(len(c.sendQ)))
	default:
		c.st.sendQDrops.Add(1)
	}
}

func (c *docConn) handleFrame(s *session, frame string) {
	c.st.rxFrames.Add(1)
	c.st.rxBytes.Add(int64(len(frame)))
	switch frame {
	case "2":
		_ = s.writeText("3")
		return
	case "3":
		return
	}

	cursors := extractCursors(frame)
	if len(cursors) == 0 {
		if strings.Contains(frame, "saveChanges") {
			c.st.rxSC.Add(1)
			c.logShape("savechanges", frame)
			return
		}
		c.st.rxOther.Add(1)
		c.logShape(frameKind(frame), frame)
		c.handleControl(s, frame)
		return
	}
	c.markReady(s, "first cursor")
	c.st.rxCursors.Add(int64(len(cursors)))
	c.observeLag(frame)
	if len(cursors) > 1 {
		c.st.rxMulti.Add(1)
		c.logShape("multicursor", frame)
	} else {
		c.logShape("cursor", frame)
	}
	for _, m := range userRe.FindAllStringSubmatch(frame, -1) {
		c.st.notePeer(m[1])
	}
	for _, payload := range cursors {
		c.handleCursor(s, payload)
	}
}

// extractCursors returns every cursor payload after the "NN;" prefix.
// Upstream OpenFlux takes only the first match per frame.
func extractCursors(frame string) []string {
	const key = `"cursor":"`
	var out []string
	rest := frame
	for {
		i := strings.Index(rest, key)
		if i < 0 {
			return out
		}
		rest = rest[i+len(key):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return out
		}
		val := rest[:end]
		rest = rest[end:]
		if semi := strings.IndexByte(val, ';'); semi >= 0 {
			out = append(out, val[semi+1:])
		}
	}
}

// handleControl reacts to auth and participant updates. Data is only sent
// after auth: Yandex sometimes closes the socket right after the handshake,
// and packets queued before that are lost silently.
func (c *docConn) handleControl(s *session, frame string) {
	if strings.Contains(frame, `"type":"auth"`) {
		if strings.Contains(frame, `"result":1`) {
			s.authOK.Store(true)
			c.markReady(s, "auth")
		} else {
			logf("openflux: session #%d auth not accepted len=%d", s.id, len(frame))
		}
	}
	if strings.Contains(frame, `"type":"waitAuth"`) {
		holder := ""
		if m := userIDRe.FindStringSubmatch(frame); len(m) > 1 {
			holder = m[1]
		}
		logf("openflux: session #%d waitAuth, document locked by %s", s.id, holder)
	}
	if strings.Contains(frame, `"participants":[`) {
		s.lastCtrl.Store(strPtr("participants"))
		n := int64(strings.Count(frame, `"connectionId":`))
		if old := c.participantsSwap(n); old != n {
			logf("openflux: document participants=%d (was %d)", n, old)
		}
	}
}

func strPtr(s string) *string { return &s }

func frameKind(frame string) string {
	if m := typeRe.FindStringSubmatch(frame); len(m) > 1 {
		return "type:" + m[1]
	}
	if len(frame) > 2 {
		return "eio:" + frame[:2]
	}
	return "eio:" + frame
}

// logShape logs the first few frames of each kind with blobs elided, so the
// Yandex message format can be read from the journal.
func (c *docConn) logShape(kind, frame string) {
	c.shapesMu.Lock()
	n := c.shapesSeen[kind]
	c.shapesSeen[kind] = n + 1
	c.shapesMu.Unlock()
	if n >= shapeLogLimit {
		return
	}
	clean := blobRe.ReplaceAllStringFunc(frame, func(s string) string {
		return fmt.Sprintf("<%dB>", len(s))
	})
	if len(clean) > frameLogLimit {
		clean = clean[:frameLogLimit] + "..."
	}
	logf("openflux: frame %s #%d len=%d %s", kind, n+1, len(frame), clean)
}

func (c *docConn) handleCursor(s *session, payload string) {
	if strings.Contains(payload, kaMarker) {
		if c.handleProbe(s, payload) {
			c.st.rxProbe.Add(1)
			return
		}
		c.st.rxKA.Add(1)
		return
	}
	if c.echo.has(hash64(payload)) {
		c.st.rxEcho.Add(1)
		return
	}
	// The exit node's reply is broadcast to every participant, so both of our
	// overlapping sessions see it. Deliver each payload to the device once.
	if !c.recv.addIfNew(hash64(payload)) {
		c.st.rxDup.Add(1)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		c.st.rxDecodeErr.Add(1)
		return
	}
	pkt, err := decompress(raw)
	if err != nil {
		c.st.rxDecompErr.Add(1)
		return
	}
	c.st.rxData.Add(1)
	now := time.Now().UnixNano()
	c.lastRxData.Store(now)
	if since := c.stallSince.Swap(0); since != 0 {
		logf("openflux: stall over after %dms", (now-since)/int64(time.Millisecond))
	}
	c.deliver(pkt)
}

// observeLag compares Yandex server stamps with local receive time. Large
// values mean the document server held the broadcast back.
func (c *docConn) observeLag(frame string) {
	now := time.Now().UnixMilli()
	var worst int64
	for _, m := range timeRe.FindAllStringSubmatch(frame, -1) {
		ts, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			continue
		}
		lag := max(now-ts, 0)
		c.st.lagCount.Add(1)
		c.st.lagTotal.Add(lag)
		c.st.lagMax.observe(lag)
		worst = max(worst, lag)
	}
	if worst < lateLag.Milliseconds() {
		return
	}
	c.st.lagLate.Add(1)
	if last := c.lateLogAt.Load(); now-last > lateLogEvery.Milliseconds() && c.lateLogAt.CompareAndSwap(last, now) {
		logf("openflux: yandex delivery lag %dms frame=%dB", worst, len(frame))
	}
}

// checkStall logs once when data keeps leaving but nothing comes back.
func (c *docConn) checkStall(now time.Time) {
	s := c.currentActive()
	if s == nil || !s.ready.Load() || c.stallSince.Load() != 0 {
		return
	}
	tx := c.lastTxData.Load()
	rx := c.lastRxData.Load()
	if tx == 0 || now.UnixNano()-tx > int64(stallTimeout) {
		return
	}
	if silent := now.UnixNano() - max(rx, s.startedAt.UnixNano()); silent > int64(stallTimeout) {
		c.stallSince.Store(now.UnixNano() - silent)
		logf("openflux: stall rx silent %dms while tx active, sendq=%d", silent/int64(time.Millisecond),
			len(c.sendQ))
	}
}
