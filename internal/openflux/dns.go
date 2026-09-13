// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: device DNS answered locally over DNS-over-TLS.

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

const (
	dnsInFlight   = 16
	dnsTimeout    = 6 * time.Second
	dnsLogEvery   = 30 * time.Second
	dnsMaxAnswer  = 4096
	dnsMinMessage = 12
)

var errDNSShort = errors.New("dns answer too short")

type dotServer struct{ addr, sni string }

// Yandex first: it is reachable where foreign resolvers are filtered.
//
//nolint:gochecknoglobals // fixed resolver list
var dotServers = []dotServer{
	{"77.88.8.8:853", "common.dot.dns.yandex.net"},
	{"8.8.8.8:853", "dns.google"},
	{"1.1.1.1:853", "cloudflare-dns.com"},
}

// DoTBypassAddrs lists resolver addresses that must stay off the tunnel.
func DoTBypassAddrs() []string {
	out := make([]string, 0, len(dotServers))
	for _, s := range dotServers {
		out = append(out, s.addr[:len(s.addr)-4])
	}
	return out
}

type dnsResolver struct {
	st      *stats
	sem     chan struct{}
	mu      sync.Mutex
	lastLog time.Time
	failN   int
}

func newDNSResolver(st *stats) *dnsResolver {
	return &dnsResolver{st: st, sem: make(chan struct{}, dnsInFlight)}
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
	r.st.dnsQ.Add(1)
	started := time.Now()
	answer, server, err := queryDoT(req[ihl+8:])
	ms := time.Since(started).Milliseconds()
	if err != nil {
		r.st.dnsFail.Add(1)
		r.logFailure(err, ms)
		return
	}
	r.st.dnsOK.Add(1)
	r.st.dnsMsTotal.Add(ms)
	r.st.dnsMsMax.observe(ms)
	if server != dotServers[0].addr {
		r.logFailure(fmt.Errorf("answered by fallback %s", server), ms)
	}
	reply(dnsResponse(req, ihl, answer))
}

func (r *dnsResolver) logFailure(err error, ms int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failN++
	if time.Since(r.lastLog) < dnsLogEvery {
		return
	}
	logf("openflux: dns %v after %dms (%d events since last line)", err, ms, r.failN)
	r.lastLog = time.Now()
	r.failN = 0
}

func queryDoT(query []byte) ([]byte, string, error) {
	var errs []error
	for _, s := range dotServers {
		ans, err := dotOnce(s, query)
		if err == nil {
			return ans, s.addr, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.addr, err))
	}
	return nil, "", errors.Join(errs...)
}

func dotOnce(s dotServer, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	d := tls.Dialer{NetDialer: protect.NewDialer(), Config: &tls.Config{ServerName: s.sni, MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(dnsTimeout))

	msg := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(msg, uint16(len(query))) //nolint:gosec // udp dns < 65536
	copy(msg[2:], query)
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read len: %w", err)
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < dnsMinMessage || n > dnsMaxAnswer {
		return nil, errDNSShort
	}
	ans := make([]byte, n)
	if _, err := io.ReadFull(conn, ans); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return ans, nil
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
