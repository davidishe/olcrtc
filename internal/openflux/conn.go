// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: document websocket session, reconnect, frame parsing.

import (
	"context"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

const (
	cursorPrefix  = `42["message",{"type":"cursor","cursor":"18;`
	cursorSuffix  = `"}]`
	kaMarker      = "---KA---"
	slowWrite     = 500 * time.Millisecond
	echoRingSize  = 4096
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

type docConn struct {
	docURL  string
	st      *stats
	deliver func([]byte)
	sendQ   chan []byte

	userID string

	mu      sync.Mutex
	ws      *websocket.Conn
	writeMu sync.Mutex

	connected    atomic.Bool
	txData       atomic.Int64
	lastTxData   atomic.Int64
	lastRxData   atomic.Int64
	stallSince   atomic.Int64
	sessionFrom  atomic.Int64
	lateLogAt    atomic.Int64
	participants atomic.Int64

	echoMu   sync.Mutex
	echoSet  map[uint64]struct{}
	echoRing []uint64
	echoPos  int

	shapesMu   sync.Mutex
	shapesSeen map[string]int

	probe probeState
}

func newDocConn(docURL string, st *stats, deliver func([]byte)) *docConn {
	return &docConn{
		docURL:     docURL,
		st:         st,
		deliver:    deliver,
		sendQ:      make(chan []byte, queueSize),
		userID:     fmt.Sprintf("%010d%03d", rand.IntN(1_000_000_000), rand.IntN(1000)), //nolint:gosec // not a secret
		echoSet:    make(map[uint64]struct{}, echoRingSize),
		echoRing:   make([]uint64, echoRingSize),
		shapesSeen: map[string]int{},
	}
}

func (c *docConn) queueLen() int { return len(c.sendQ) }

func (c *docConn) stateText() string {
	if !c.connected.Load() {
		return "down"
	}
	return fmt.Sprintf("up%ds", (time.Now().UnixNano()-c.sessionFrom.Load())/int64(time.Second))
}

func (c *docConn) close() {
	c.mu.Lock()
	ws := c.ws
	c.mu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

// send queues one packet payload (already compressed).
func (c *docConn) send(payload []byte) {
	if !c.connected.Load() {
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

func (c *docConn) writeText(msg string) error {
	c.mu.Lock()
	ws := c.ws
	c.mu.Unlock()
	if ws == nil {
		return websocket.ErrCloseSent
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	started := time.Now()
	err := ws.WriteMessage(websocket.TextMessage, []byte(msg))
	took := time.Since(started)
	c.st.txMaxMs.observe(took.Milliseconds())
	if took > slowWrite {
		c.st.txSlow.Add(1)
	}
	if err != nil {
		c.st.txErr.Add(1)
		return fmt.Errorf("ws write: %w", err)
	}
	c.st.txBytes.Add(int64(len(msg)))
	return nil
}

func (c *docConn) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case b64 := <-c.sendQ:
			if !c.connected.Load() {
				c.st.notConnDrops.Add(1)
				continue
			}
			c.rememberSent(string(b64))
			if err := c.writeText(cursorPrefix + string(b64) + cursorSuffix); err != nil {
				continue
			}
			c.st.txMsgs.Add(1)
			c.txData.Add(1)
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
			if !c.connected.Load() {
				continue
			}
			if err := c.writeText(cursorPrefix + kaMarker + cursorSuffix); err != nil {
				logf("openflux: keepalive failed: %v", err)
				c.close()
			}
		}
	}
}

// loop keeps one session alive until ctx is cancelled.
func (c *docConn) loop(ctx context.Context) {
	attempt := 0
	for ctx.Err() == nil {
		lived, err := c.session(ctx)
		c.connected.Store(false)
		c.mu.Lock()
		c.ws = nil
		c.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
		if lived > 15*time.Second {
			attempt = 0
		}
		attempt++
		wait := backoff(attempt)
		logf("openflux: session ended after %dms: %v; retry #%d in %dms", lived.Milliseconds(), err, attempt,
			wait.Milliseconds())
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func backoff(n int) time.Duration {
	shift := min(max(n-1, 0), 5)
	d := min(500*time.Millisecond*time.Duration(1<<shift), 15*time.Second)
	return d + time.Duration(rand.Int64N(int64(d/2)+1)) //nolint:gosec // jitter only
}

func (c *docConn) session(ctx context.Context) (time.Duration, error) {
	started := time.Now()
	info, err := fetchDocInfo(ctx, c.docURL, c.userID)
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
	logf("openflux: ws connected host=%s dial=%dms total=%dms user=%s", shortHost(info.host),
		time.Since(dialStart).Milliseconds(), time.Since(started).Milliseconds(), c.userID)

	c.mu.Lock()
	c.ws = ws
	c.mu.Unlock()
	msgs, err := authMessages(info, c.userID)
	if err != nil {
		return 0, err
	}
	for _, m := range msgs {
		if err := c.writeText(m); err != nil {
			return 0, err
		}
	}
	c.sessionFrom.Store(time.Now().UnixNano())
	c.st.connects.Add(1)
	defer c.st.disconnects.Add(1)

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return time.Since(started), fmt.Errorf("ws read: %w", err)
		}
		c.handleFrame(string(data))
	}
}

func shortHost(h string) string {
	if i := strings.Index(h, "."); i > 12 {
		return h[:12] + "..." + h[i:]
	}
	return h
}

func (c *docConn) handleFrame(frame string) {
	c.st.rxFrames.Add(1)
	c.st.rxBytes.Add(int64(len(frame)))
	switch frame {
	case "2":
		_ = c.writeText("3")
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
		c.handleControl(frame)
		return
	}
	c.markReady("first cursor")
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
		c.handleCursor(payload)
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
func (c *docConn) handleControl(frame string) {
	if strings.Contains(frame, `"type":"auth"`) {
		if strings.Contains(frame, `"result":1`) {
			c.markReady("auth")
		} else {
			logf("openflux: auth not accepted len=%d", len(frame))
		}
	}
	if strings.Contains(frame, `"type":"waitAuth"`) {
		holder := ""
		if m := userIDRe.FindStringSubmatch(frame); len(m) > 1 {
			holder = m[1]
		}
		logf("openflux: waitAuth, document locked by %s", holder)
	}
	if strings.Contains(frame, `"participants":[`) {
		n := int64(strings.Count(frame, `"connectionId":`))
		if old := c.participants.Swap(n); old != n {
			logf("openflux: document participants=%d (was %d)", n, old)
		}
	}
}

func (c *docConn) markReady(reason string) {
	if c.connected.CompareAndSwap(false, true) {
		logf("openflux: session ready via %s after %dms", reason,
			(time.Now().UnixNano()-c.sessionFrom.Load())/int64(time.Millisecond))
	}
}

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

func (c *docConn) handleCursor(payload string) {
	if strings.Contains(payload, kaMarker) {
		if c.handleProbe(payload) {
			c.st.rxProbe.Add(1)
			return
		}
		c.st.rxKA.Add(1)
		return
	}
	if c.isEcho(payload) {
		c.st.rxEcho.Add(1)
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

func hash64(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

func (c *docConn) rememberSent(b64 string) {
	h := hash64(b64)
	c.echoMu.Lock()
	defer c.echoMu.Unlock()
	if old := c.echoRing[c.echoPos]; old != 0 {
		delete(c.echoSet, old)
	}
	c.echoRing[c.echoPos] = h
	c.echoSet[h] = struct{}{}
	c.echoPos = (c.echoPos + 1) % echoRingSize
}

func (c *docConn) isEcho(b64 string) bool {
	h := hash64(b64)
	c.echoMu.Lock()
	defer c.echoMu.Unlock()
	_, ok := c.echoSet[h]
	return ok
}

// checkStall logs once when data keeps leaving but nothing comes back.
func (c *docConn) checkStall(now time.Time) {
	if !c.connected.Load() || c.stallSince.Load() != 0 {
		return
	}
	tx := c.lastTxData.Load()
	rx := c.lastRxData.Load()
	if tx == 0 || now.UnixNano()-tx > int64(stallTimeout) {
		return
	}
	if silent := now.UnixNano() - max(rx, c.sessionFrom.Load()); silent > int64(stallTimeout) {
		c.stallSince.Store(now.UnixNano() - silent)
		logf("openflux: stall rx silent %dms while tx active, sendq=%d", silent/int64(time.Millisecond),
			len(c.sendQ))
	}
}
