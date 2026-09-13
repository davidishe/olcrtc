// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: counters and the periodic stats line.

import (
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const idleStatsEvery = 30 * time.Second

func logf(format string, v ...any) {
	log.Printf(format, v...)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid"
	}
	path := u.Path
	if len(path) > 8 {
		path = path[:8] + "..."
	}
	return u.Host + path
}

// maxGauge keeps the maximum value seen since the last reset.
type maxGauge struct{ v atomic.Int64 }

func (g *maxGauge) observe(x int64) {
	for {
		cur := g.v.Load()
		if x <= cur || g.v.CompareAndSwap(cur, x) {
			return
		}
	}
}

func (g *maxGauge) take() int64 { return g.v.Swap(0) }

type stats struct {
	// device -> tunnel
	devInPkts, devInBytes, tcpUp, udpDNS, udpOther, nonIPv4 atomic.Int64
	synUp, rstUp, finUp, dataUp, retransUp, zeroWinUp       atomic.Int64
	sendQDrops, notConnDrops                                atomic.Int64
	sendQHigh                                               maxGauge

	// tunnel -> device
	devOutPkts, synAckDn, rstDn, finDn, dataDn, retransDn, zeroWinDn atomic.Int64
	outQDrops                                                        atomic.Int64
	outQHigh                                                         maxGauge

	// websocket write side
	txMsgs, txBytes, txErr, txSlow atomic.Int64
	txMaxMs                        maxGauge

	// websocket read side
	rxFrames, rxBytes, rxCursors, rxMulti, rxData, rxEcho  atomic.Int64
	rxKA, rxProbe, rxOther, rxDecodeErr, rxDecompErr, rxSC atomic.Int64

	// Yandex delivery lag: receive time minus the server "time" stamp
	lagCount, lagTotal, lagLate atomic.Int64
	lagMax                      maxGauge

	// connection
	connects, disconnects atomic.Int64

	// dns
	dnsQ, dnsOK, dnsFail, dnsDrop, dnsMsTotal atomic.Int64
	dnsMsMax                                  maxGauge

	// probes
	probeSent, probeRecv, probeRttTotal atomic.Int64
	probeRttMax                         maxGauge

	mu       sync.Mutex
	peers    map[string]struct{}
	known    map[string]struct{}
	prev     map[string]int64
	lastLine time.Time
	probeTxt string
}

func newStats() *stats {
	return &stats{peers: map[string]struct{}{}, known: map[string]struct{}{}, prev: map[string]int64{}}
}

func (s *stats) notePeer(id string) {
	s.mu.Lock()
	_, seen := s.known[id]
	s.known[id] = struct{}{}
	s.peers[id] = struct{}{}
	s.mu.Unlock()
	if !seen {
		logf("openflux: peer seen user=%s", id)
	}
}

func (s *stats) setProbeText(txt string) {
	s.mu.Lock()
	s.probeTxt = txt
	s.mu.Unlock()
}

// named lists counters in log order; group names become line sections.
func (s *stats) named() []struct {
	group, name string
	c           *atomic.Int64
} {
	type item = struct {
		group, name string
		c           *atomic.Int64
	}
	return []item{
		{"up", "pkts", &s.devInPkts}, {"up", "bytes", &s.devInBytes}, {"up", "tcp", &s.tcpUp},
		{"up", "data", &s.dataUp}, {"up", "retr", &s.retransUp}, {"up", "syn", &s.synUp},
		{"up", "rst", &s.rstUp}, {"up", "fin", &s.finUp}, {"up", "zwin", &s.zeroWinUp},
		{"up", "dns", &s.udpDNS}, {"up", "udp", &s.udpOther}, {"up", "v6", &s.nonIPv4},
		{"up", "qdrop", &s.sendQDrops}, {"up", "offline", &s.notConnDrops},
		{"dn", "pkts", &s.devOutPkts}, {"dn", "data", &s.dataDn}, {"dn", "retr", &s.retransDn},
		{"dn", "synack", &s.synAckDn}, {"dn", "rst", &s.rstDn}, {"dn", "fin", &s.finDn},
		{"dn", "zwin", &s.zeroWinDn}, {"dn", "qdrop", &s.outQDrops},
		{"tx", "msgs", &s.txMsgs}, {"tx", "bytes", &s.txBytes}, {"tx", "err", &s.txErr},
		{"tx", "slow", &s.txSlow},
		{"rx", "frames", &s.rxFrames}, {"rx", "bytes", &s.rxBytes}, {"rx", "cursors", &s.rxCursors},
		{"rx", "multi", &s.rxMulti}, {"rx", "data", &s.rxData}, {"rx", "echo", &s.rxEcho},
		{"rx", "ka", &s.rxKA}, {"rx", "probe", &s.rxProbe}, {"rx", "other", &s.rxOther},
		{"rx", "b64err", &s.rxDecodeErr}, {"rx", "lz4err", &s.rxDecompErr}, {"rx", "savechg", &s.rxSC},
		{"rx", "late", &s.lagLate},
		{"ws", "connects", &s.connects}, {"ws", "drops", &s.disconnects},
		{"dns", "q", &s.dnsQ}, {"dns", "ok", &s.dnsOK}, {"dns", "fail", &s.dnsFail},
		{"dns", "busy", &s.dnsDrop},
		{"probe", "sent", &s.probeSent}, {"probe", "replies", &s.probeRecv},
	}
}

// snapshot renders deltas since the previous call. ok is false when nothing
// moved and the idle heartbeat is not due yet.
func (s *stats) snapshot(c *docConn, outQLen, flows int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	groups := map[string][]string{}
	order := []string{}
	moved := false
	for _, it := range s.named() {
		key := it.group + "." + it.name
		cur := it.c.Load()
		d := cur - s.prev[key]
		s.prev[key] = cur
		if d == 0 {
			continue
		}
		moved = true
		if _, ok := groups[it.group]; !ok {
			order = append(order, it.group)
		}
		groups[it.group] = append(groups[it.group], fmt.Sprintf("%s=%d", it.name, d))
	}
	if !moved && now.Sub(s.lastLine) < idleStatsEvery {
		return "", false
	}
	s.lastLine = now

	var b strings.Builder
	fmt.Fprintf(&b, "openflux: stats ws=%s", c.stateText())
	for _, g := range order {
		fmt.Fprintf(&b, " | %s %s", g, strings.Join(groups[g], " "))
	}
	fmt.Fprintf(&b, " | q send=%d/%d out=%d/%d flows=%d", c.queueLen(), s.sendQHigh.take(),
		outQLen, s.outQHigh.take(), flows)
	if n := s.lagCount.Swap(0); n > 0 {
		fmt.Fprintf(&b, " lag avg=%dms max=%dms", s.lagTotal.Swap(0)/n, s.lagMax.take())
	}
	if ms := s.txMaxMs.take(); ms > 0 {
		fmt.Fprintf(&b, " txmax=%dms", ms)
	}
	if q := s.dnsQ.Load(); q > 0 {
		fmt.Fprintf(&b, " dnsavg=%dms dnsmax=%dms", s.dnsMsTotal.Load()/max(s.dnsOK.Load(), 1), s.dnsMsMax.take())
	}
	switch {
	case s.probeTxt != "":
		fmt.Fprintf(&b, " | %s", s.probeTxt)
	case s.probeSent.Load() > 0:
		b.WriteString(" | probe no replies (exit node without diagnostics?)")
	}
	if len(s.peers) > 0 {
		ids := make([]string, 0, len(s.peers))
		for id := range s.peers {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		fmt.Fprintf(&b, " | peers=%s", strings.Join(ids, ","))
		s.peers = map[string]struct{}{}
	}
	return b.String(), true
}

// totals renders lifetime counters for the stop line.
func (s *stats) totals() string {
	return fmt.Sprintf("up=%d/%dB retr=%d dn=%d retr=%d tx=%d rx=%d echo=%d multi=%d drops=%d/%d ws=%d/%d",
		s.devInPkts.Load(), s.devInBytes.Load(), s.retransUp.Load(), s.dataDn.Load(), s.retransDn.Load(),
		s.txMsgs.Load(), s.rxData.Load(), s.rxEcho.Load(), s.rxMulti.Load(),
		s.sendQDrops.Load(), s.outQDrops.Load(), s.connects.Load(), s.disconnects.Load())
}
