// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: session lifecycle and seamless rotation.
//
// Yandex closes each editor websocket after roughly a minute (observed
// 13.09.2026: sessions lived ~64-70 s, then close 1005). A single-session
// client froze for 2-6 s on every close. The supervisor keeps the active
// session young by opening a successor before the current one is due to die
// and promoting it once it is ready, so writes never land on a dead socket.
// Both sessions receive during the overlap; incoming data is deduped in
// handleCursor.

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

const (
	// Open a successor well before Yandex's ~66 s close, and keep the active
	// session younger than that ceiling at all times.
	rotateAfter  = 45 * time.Second
	rotateCheck  = 2 * time.Second
	overlapGrace = 6 * time.Second
)

type evKind int

const (
	evReady evKind = iota
	evEnded
	evSpawn
)

type sessionEvent struct {
	kind  evKind
	s     *session
	lived time.Duration
}

// earlyClose is how long a session must survive before a failure counts as a
// real outage. Yandex often closes a fresh socket within a fraction of a
// second; backing off there only delays a connect that usually works at once.
const earlyClose = 3 * time.Second

// session is one websocket participant in the document.
type session struct {
	c         *docConn
	id        int
	userID    string
	startedAt time.Time

	ready    atomic.Bool
	authOK   atomic.Bool
	lastCtrl atomic.Pointer[string]

	mu sync.Mutex
	ws *websocket.Conn
	// Data, keepalives, probes and pongs all write here; gorilla allows one
	// writer at a time and panics otherwise.
	writeMu sync.Mutex
}

func (s *session) setWS(ws *websocket.Conn) {
	s.mu.Lock()
	s.ws = ws
	s.mu.Unlock()
}

func (s *session) close() {
	s.mu.Lock()
	ws := s.ws
	s.mu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

func (s *session) writeText(msg string) error {
	s.mu.Lock()
	ws := s.ws
	s.mu.Unlock()
	if ws == nil {
		return websocket.ErrCloseSent
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	started := time.Now()
	err := ws.WriteMessage(websocket.TextMessage, []byte(msg))
	took := time.Since(started)
	s.c.st.txMaxMs.observe(took.Milliseconds())
	if took > slowWrite {
		s.c.st.txSlow.Add(1)
	}
	if err != nil {
		s.c.st.txErr.Add(1)
		return fmt.Errorf("ws write: %w", err)
	}
	s.c.st.txBytes.Add(int64(len(msg)))
	return nil
}

// loop is the session supervisor. It runs until ctx is cancelled.
func (c *docConn) loop(ctx context.Context) {
	c.runCtx = ctx
	c.spawn()
	ticker := time.NewTicker(rotateCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.closeAll()
			return
		case ev := <-c.events:
			c.onEvent(ev)
		case <-ticker.C:
			c.maybeRotate()
		}
	}
}

func (c *docConn) close() { c.closeAll() }

func (c *docConn) closeAll() {
	c.mu.Lock()
	sessions := make([]*session, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.active = nil
	c.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
}

func (c *docConn) newUserID(id int) string {
	return fmt.Sprintf("%s%03d", c.baseUser, id%1000)
}

// spawn starts a new session. Manager goroutine only.
func (c *docConn) spawn() {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	s := &session{c: c, id: id, userID: c.newUserID(id), startedAt: time.Now()}
	c.sessions[id] = s
	c.mu.Unlock()
	go c.runSession(s)
}

func (c *docConn) spawnAfter(d time.Duration) {
	go func() {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			c.postEvent(sessionEvent{kind: evSpawn})
		case <-c.runCtx.Done():
		}
	}()
}

func (c *docConn) scheduleClose(s *session, d time.Duration) {
	go func() {
		select {
		case <-time.After(d):
		case <-c.runCtx.Done():
		}
		s.close()
	}()
}

func (c *docConn) postEvent(ev sessionEvent) {
	select {
	case c.events <- ev:
	case <-c.runCtx.Done():
	}
}

func (c *docConn) markReady(s *session, reason string) {
	if s.ready.CompareAndSwap(false, true) {
		logf("openflux: session #%d ready via %s after %dms", s.id, reason,
			time.Since(s.startedAt).Milliseconds())
		c.postEvent(sessionEvent{kind: evReady, s: s})
	}
}

func (c *docConn) onEvent(ev sessionEvent) {
	switch ev.kind {
	case evReady:
		c.onReady(ev.s)
	case evEnded:
		c.onEnded(ev.s, ev.lived)
	case evSpawn:
		c.spawn()
	}
}

// onReady promotes the newest ready session to active.
func (c *docConn) onReady(s *session) {
	c.mu.Lock()
	if _, live := c.sessions[s.id]; !live {
		c.mu.Unlock()
		return
	}
	old := c.active
	promote := old == nil || s.id > old.id
	if promote {
		c.active = s
		c.rotating = false
		c.attempt = 0
	}
	c.mu.Unlock()

	if !promote {
		return
	}
	if old == nil {
		logf("openflux: session #%d active", s.id)
		return
	}
	logf("openflux: promoted session #%d (was #%d)", s.id, old.id)
	c.scheduleClose(old, overlapGrace)
}

// onEnded removes a session and repairs the active path if it was lost.
func (c *docConn) onEnded(s *session, lived time.Duration) {
	c.mu.Lock()
	delete(c.sessions, s.id)
	wasActive := c.active == s
	if wasActive {
		c.active = c.newestReadyLocked()
	}
	if c.rotating && !s.ready.Load() {
		// a successor died before becoming ready; let rotation try again
		c.rotating = false
	}
	active := c.active
	dialing := c.hasDialingLocked()
	c.mu.Unlock()

	if active != nil {
		if wasActive {
			logf("openflux: active fell back to session #%d", active.id)
		}
		return
	}
	// No usable path left. This also covers the first session dying before it
	// ever became active: Yandex sometimes closes right after the handshake,
	// and nothing else would restart the tunnel.
	if dialing {
		return // a younger session is still connecting; wait for it
	}
	c.mu.Lock()
	c.attempt++
	attempt := c.attempt
	c.mu.Unlock()
	d := backoff(attempt)
	if !s.ready.Load() && lived < earlyClose && attempt <= 3 {
		// Yandex dropped the socket right after the handshake; a redial
		// normally succeeds, and the dial itself already costs ~2 s.
		d = 200 * time.Millisecond
	}
	logf("openflux: no live session, redialing in %dms", d.Milliseconds())
	c.spawnAfter(d)
}

func (c *docConn) newestReadyLocked() *session {
	var best *session
	for _, s := range c.sessions {
		if s.ready.Load() && (best == nil || s.id > best.id) {
			best = s
		}
	}
	return best
}

func (c *docConn) hasDialingLocked() bool {
	for _, s := range c.sessions {
		if !s.ready.Load() {
			return true
		}
	}
	return false
}

// maybeRotate opens a successor once the active session nears Yandex's cutoff.
func (c *docConn) maybeRotate() {
	c.mu.Lock()
	a := c.active
	rotating := c.rotating
	c.mu.Unlock()
	if a == nil || !a.ready.Load() || rotating {
		return
	}
	if time.Since(a.startedAt) < rotateAfter {
		return
	}
	c.mu.Lock()
	c.rotating = true
	c.mu.Unlock()
	logf("openflux: rotating: active #%d age=%.0fs", a.id, time.Since(a.startedAt).Seconds())
	c.spawn()
}

func (c *docConn) runSession(s *session) {
	lived, err := s.dialAndRead(c.runCtx)
	ctrl := "-"
	if p := s.lastCtrl.Load(); p != nil {
		ctrl = *p
	}
	logf("openflux: session #%d ended after %dms ready=%v authOK=%v lastctrl=%s: %v",
		s.id, lived.Milliseconds(), s.ready.Load(), s.authOK.Load(), ctrl, err)
	c.postEvent(sessionEvent{kind: evEnded, s: s, lived: lived})
}

func (s *session) dialAndRead(ctx context.Context) (time.Duration, error) {
	c := s.c
	info, err := fetchDocInfo(ctx, c.docURL, s.userID)
	if err != nil {
		return 0, err
	}
	dialer := protect.NewWebSocketDialer(15 * time.Second)
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Origin", info.origin)
	headers.Set("Cookie", info.cookie)
	dialStart := time.Now()
	ws, resp, err := dialer.DialContext(ctx, info.wsURL, headers)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return 0, fmt.Errorf("ws dial http=%d: %w", status, err)
	}
	logf("openflux: session #%d ws connected host=%s dial=%dms user=%s", s.id, shortHost(info.host),
		time.Since(dialStart).Milliseconds(), s.userID)
	s.setWS(ws)

	msgs, err := authMessages(info, s.userID)
	if err != nil {
		return 0, err
	}
	for _, m := range msgs {
		if err := s.writeText(m); err != nil {
			return 0, err
		}
	}
	connAt := time.Now()
	c.st.connects.Add(1)
	defer c.st.disconnects.Add(1)
	for {
		_, data, readErr := ws.ReadMessage()
		if readErr != nil {
			return time.Since(connAt), fmt.Errorf("ws read: %w", readErr)
		}
		c.handleFrame(s, string(data))
	}
}

func (c *docConn) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case first := <-c.sendQ:
			s := c.currentActive()
			if s == nil || !s.ready.Load() {
				c.st.notConnDrops.Add(1)
				continue
			}
			units := c.drainQueue(first)
			payload := units[0]
			if len(units) > 1 {
				payload = encodeBatch(units)
				c.st.txBatch.Add(1)
			}
			b64 := base64.StdEncoding.EncodeToString(payload)
			c.echo.add(hash64(b64))
			if err := s.writeText(cursorPrefix + b64 + cursorSuffix); err != nil {
				continue
			}
			c.st.txMsgs.Add(1)
			c.txData.Add(int64(len(units)))
			c.lastTxData.Store(time.Now().UnixNano())
		}
	}
}

func (c *docConn) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(keepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s := c.currentActive()
			if s == nil || !s.ready.Load() {
				continue
			}
			if err := s.writeText(cursorPrefix + kaMarker + cursorSuffix); err != nil {
				logf("openflux: keepalive failed on #%d: %v", s.id, err)
				s.close()
			}
		}
	}
}

// drainQueue takes everything already queued, up to the batch limits. It never
// waits: a quiet tunnel still sends each packet immediately.
func (c *docConn) drainQueue(first []byte) [][]byte {
	units := [][]byte{first}
	total := len(first) + 2
	for len(units) < maxBatchUnits && total < maxBatchBytes {
		select {
		case next := <-c.sendQ:
			units = append(units, next)
			total += len(next) + 2
		default:
			return units
		}
	}
	return units
}

func backoff(n int) time.Duration {
	shift := min(max(n-1, 0), 5)
	d := min(500*time.Millisecond*time.Duration(1<<shift), 15*time.Second)
	return d + time.Duration(rand.Int64N(int64(d/2)+1)) //nolint:gosec // jitter only
}

func shortHost(h string) string {
	if i := strings.Index(h, "."); i > 12 {
		return h[:12] + "..." + h[i:]
	}
	return h
}
