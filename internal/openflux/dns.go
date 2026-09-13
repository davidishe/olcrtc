// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: device DNS answered locally over pooled DNS-over-TLS.
//
// The first version opened a TLS connection per query. On a phone that meant
// ~300 ms per lookup and, under load, resolvers started refusing: on
// 13.09.2026 a single query spent 12.6 s and failed on all three servers
// (Yandex EOF, Google and Cloudflare timeouts). Now one connection per server
// is kept open and queries are pipelined over it by DNS id, answers are
// cached, and the server that last worked is tried first.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

const (
	dnsInFlight   = 32
	dnsTimeout    = 5 * time.Second
	dnsDialTime   = 6 * time.Second
	dnsLogEvery   = 30 * time.Second
	dnsMaxAnswer  = 4096
	dnsMinMessage = 12
	dnsCacheTTL   = 60 * time.Second
	dnsMissTTL    = 5 * time.Second
	dnsCacheMax   = 2048
)

var (
	errDNSClosed  = errors.New("dot connection closed")
	errDNSTimeout = errors.New("dot query timed out")
	errNoServers  = errors.New("no usable resolver")
)

type dotServer struct{ addr, sni string }

// Yandex first: it is reachable where foreign resolvers are filtered.
//
//nolint:gochecknoglobals // fixed resolver list
var dotServers = []dotServer{
	{"77.88.8.8:853", "common.dot.dns.yandex.net"},
	{"77.88.8.1:853", "common.dot.dns.yandex.net"},
	{"8.8.8.8:853", "dns.google"},
	{"1.1.1.1:853", "cloudflare-dns.com"},
}

// DoTBypassAddrs lists resolver addresses that must stay off the tunnel.
func DoTBypassAddrs() []string {
	out := make([]string, 0, len(dotServers))
	for _, s := range dotServers {
		host, _, err := net.SplitHostPort(s.addr)
		if err != nil {
			continue
		}
		out = append(out, host)
	}
	return out
}

// dotConn is one long-lived DNS-over-TLS connection with pipelined queries.
type dotConn struct {
	srv  dotServer
	conn net.Conn

	writeMu sync.Mutex

	mu      sync.Mutex
	pending map[uint16]chan []byte
	nextID  uint16
	closed  bool
}

func dialDoT(ctx context.Context, srv dotServer) (*dotConn, error) {
	d := tls.Dialer{
		NetDialer: protect.NewDialer(),
		Config:    &tls.Config{ServerName: srv.sni, MinVersion: tls.VersionTLS12},
	}
	dialCtx, cancel := context.WithTimeout(ctx, dnsDialTime)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", srv.addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	c := &dotConn{srv: srv, conn: conn, pending: map[uint16]chan []byte{}}
	go c.readLoop()
	return c, nil
}

func (c *dotConn) readLoop() {
	defer c.shutdown()
	for {
		var lenBuf [2]byte
		if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lenBuf[:]))
		if n < dnsMinMessage || n > dnsMaxAnswer {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c.conn, msg); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(msg[:2])
		c.mu.Lock()
		ch := c.pending[id]
		delete(c.pending, id)
		c.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

func (c *dotConn) shutdown() {
	c.mu.Lock()
	c.closed = true
	waiters := c.pending
	c.pending = map[uint16]chan []byte{}
	c.mu.Unlock()
	_ = c.conn.Close()
	for _, ch := range waiters {
		close(ch)
	}
}

// query sends one DNS message and waits for the matching answer. The caller's
// id is replaced by a connection-unique one and restored by the caller.
func (c *dotConn) query(msg []byte) ([]byte, error) {
	ch := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errDNSClosed
	}
	c.nextID++
	id := c.nextID
	for c.pending[id] != nil {
		c.nextID++
		id = c.nextID
	}
	c.pending[id] = ch
	c.mu.Unlock()

	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg))) //nolint:gosec // dns message < 65536
	copy(out[2:], msg)
	binary.BigEndian.PutUint16(out[2:], id)

	c.writeMu.Lock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(dnsTimeout))
	_, err := c.conn.Write(out)
	c.writeMu.Unlock()
	if err != nil {
		c.dropPending(id)
		return nil, fmt.Errorf("write: %w", err)
	}

	timer := time.NewTimer(dnsTimeout)
	defer timer.Stop()
	select {
	case answer, ok := <-ch:
		if !ok {
			return nil, errDNSClosed
		}
		return answer, nil
	case <-timer.C:
		c.dropPending(id)
		return nil, errDNSTimeout
	}
}

func (c *dotConn) dropPending(id uint16) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

type cacheEntry struct {
	answer  []byte
	expires time.Time
}

type dnsResolver struct {
	st  *stats
	sem chan struct{}

	mu      sync.Mutex
	conns   map[string]*dotConn
	best    int // index of the server that answered last
	lastLog time.Time
	failN   int

	cacheMu sync.Mutex
	cache   map[string]cacheEntry
}

func newDNSResolver(st *stats) *dnsResolver {
	return &dnsResolver{
		st:    st,
		sem:   make(chan struct{}, dnsInFlight),
		conns: map[string]*dotConn{},
		cache: map[string]cacheEntry{},
	}
}

func (r *dnsResolver) handle(req []byte, reply func([]byte)) {
	select {
	case r.sem <- struct{}{}:
	default:
		r.st.dnsDrop.Add(1)
		return
	}
	go func() {
		defer func() { <-r.sem }()
		r.resolve(req, reply)
	}()
}

func (r *dnsResolver) resolve(req []byte, reply func([]byte)) {
	ihl := int(req[0]&0x0f) * 4
	if len(req) < ihl+8+dnsMinMessage {
		return
	}
	query := req[ihl+8:]
	r.st.dnsQ.Add(1)
	started := time.Now()

	if answer, ok := r.fromCache(query); ok {
		r.st.dnsCacheHit.Add(1)
		reply(dnsResponse(req, ihl, answer))
		return
	}

	answer, err := r.exchange(query)
	ms := time.Since(started).Milliseconds()
	if err != nil {
		r.st.dnsFail.Add(1)
		r.logFailure(err, ms)
		return
	}
	r.st.dnsOK.Add(1)
	r.st.dnsMsTotal.Add(ms)
	r.st.dnsMsMax.observe(ms)
	r.store(query, answer)
	reply(dnsResponse(req, ihl, answer))
}

// exchange tries the last known good server first, then the rest.
func (r *dnsResolver) exchange(query []byte) ([]byte, error) {
	r.mu.Lock()
	start := r.best
	r.mu.Unlock()

	var errs []error
	for i := range dotServers {
		idx := (start + i) % len(dotServers)
		srv := dotServers[idx]
		answer, err := r.askServer(srv, query)
		if err == nil {
			r.mu.Lock()
			if r.best != idx {
				r.best = idx
				logf("openflux: dns now using %s", srv.addr)
			}
			r.mu.Unlock()
			// restore the device's transaction id
			out := make([]byte, len(answer))
			copy(out, answer)
			copy(out[:2], query[:2])
			return out, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", srv.addr, err))
	}
	if len(errs) == 0 {
		return nil, errNoServers
	}
	return nil, errors.Join(errs...)
}

// askServer reuses the open connection and redials once if it went away.
func (r *dnsResolver) askServer(srv dotServer, query []byte) ([]byte, error) {
	for attempt := range 2 {
		conn, err := r.connFor(srv)
		if err != nil {
			return nil, err
		}
		answer, err := conn.query(query)
		if err == nil {
			return answer, nil
		}
		r.dropConn(srv, conn)
		if attempt == 1 || errors.Is(err, errDNSTimeout) {
			return nil, err
		}
	}
	return nil, errDNSClosed
}

func (r *dnsResolver) connFor(srv dotServer) (*dotConn, error) {
	r.mu.Lock()
	conn := r.conns[srv.addr]
	r.mu.Unlock()
	if conn != nil {
		conn.mu.Lock()
		alive := !conn.closed
		conn.mu.Unlock()
		if alive {
			return conn, nil
		}
		r.dropConn(srv, conn)
	}

	fresh, err := dialDoT(context.Background(), srv)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if existing := r.conns[srv.addr]; existing != nil {
		r.mu.Unlock()
		fresh.shutdown()
		return existing, nil
	}
	r.conns[srv.addr] = fresh
	r.mu.Unlock()
	return fresh, nil
}

func (r *dnsResolver) dropConn(srv dotServer, conn *dotConn) {
	r.mu.Lock()
	if r.conns[srv.addr] == conn {
		delete(r.conns, srv.addr)
	}
	r.mu.Unlock()
	conn.shutdown()
}

func (r *dnsResolver) closeAll() {
	r.mu.Lock()
	conns := make([]*dotConn, 0, len(r.conns))
	for _, c := range r.conns {
		conns = append(conns, c)
	}
	r.conns = map[string]*dotConn{}
	r.mu.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
}

// cacheKey is the question section, which excludes the transaction id.
func cacheKey(query []byte) (string, bool) {
	if len(query) < dnsMinMessage {
		return "", false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 { // exactly one question
		return "", false
	}
	i := dnsMinMessage
	for i < len(query) {
		l := int(query[i])
		if l == 0 {
			i++
			break
		}
		if l >= 0xc0 { // compression pointer: not expected in a question
			return "", false
		}
		i += l + 1
	}
	if i+4 > len(query) {
		return "", false
	}
	return strings.ToLower(string(query[dnsMinMessage : i+4])), true
}

func (r *dnsResolver) fromCache(query []byte) ([]byte, bool) {
	key, ok := cacheKey(query)
	if !ok {
		return nil, false
	}
	r.cacheMu.Lock()
	entry, hit := r.cache[key]
	r.cacheMu.Unlock()
	if !hit || time.Now().After(entry.expires) {
		return nil, false
	}
	out := make([]byte, len(entry.answer))
	copy(out, entry.answer)
	copy(out[:2], query[:2])
	return out, true
}

// store caches an answer for a fixed window. Record TTLs are not parsed: the
// window is short enough that a stale entry costs one minute at most.
func (r *dnsResolver) store(query, answer []byte) {
	key, ok := cacheKey(query)
	if !ok {
		return
	}
	ttl := dnsCacheTTL
	if len(answer) >= dnsMinMessage && binary.BigEndian.Uint16(answer[6:8]) == 0 {
		ttl = dnsMissTTL // no answer records
	}
	stored := make([]byte, len(answer))
	copy(stored, answer)
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()
	if len(r.cache) >= dnsCacheMax {
		now := time.Now()
		for k, v := range r.cache {
			if now.After(v.expires) {
				delete(r.cache, k)
			}
		}
		if len(r.cache) >= dnsCacheMax {
			r.cache = map[string]cacheEntry{}
		}
	}
	r.cache[key] = cacheEntry{answer: stored, expires: time.Now().Add(ttl)}
}

func (r *dnsResolver) logFailure(err error, ms int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failN++
	if time.Since(r.lastLog) < dnsLogEvery {
		return
	}
	logf("openflux: dns failed after %dms (%d events since last line): %v", ms, r.failN, err)
	r.lastLog = time.Now()
	r.failN = 0
}

func dnsResponse(req []byte, ihl int, answer []byte) []byte {
	udpLen := 8 + len(answer)
	resp := make([]byte, 20+udpLen)
	resp[0] = 0x45
	binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp))) //nolint:gosec // bounded by dnsMaxAnswer
	resp[8] = 64
	resp[9] = protoUDP
	copy(resp[12:16], req[16:20])
	copy(resp[16:20], req[12:16])
	binary.BigEndian.PutUint16(resp[10:12], ipChecksum(resp[:20]))
	udp := resp[20:]
	copy(udp[0:2], req[ihl+2:ihl+4])
	copy(udp[2:4], req[ihl:ihl+2])
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen)) //nolint:gosec // bounded by dnsMaxAnswer
	copy(udp[8:], answer)
	return resp
}
