// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: in-band probes measuring the document channel.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Probes ride inside keepalive cursors ("---KA---P1:..."), so upstream
// OpenFlux peers ignore them. A diagnostic exit node answers:
//
//	P1:<side>:<seq>:<unixms>:<dataSent>:<dataRecv>  probe from side c or s
//	R1:<side>:<seq>:<echoms>:<dataSent>:<dataRecv>  reply with replier counters
//
// Counters are data cursors only. Comparing one side's sent delta with the
// other side's received delta between two probes gives loss per direction.
const probeFields = 6

type probeSample struct {
	at       time.Time
	dataSent int64
}

type probeState struct {
	mu        sync.Mutex
	seq       int64
	pending   map[int64]probeSample
	lastReply *probeReply
	lastPeer  *probeReply
	lastRecv  int64
	upText    string
	dnText    string
	rttText   string
	replies   int64
}

type probeReply struct {
	seq            int64
	ms             int64
	sent, recv     int64
	localSent      int64
	localRecvAtArr int64
}

func parseProbe(payload string) (kind, side string, r probeReply, ok bool) {
	parts := strings.Split(payload[strings.Index(payload, kaMarker)+len(kaMarker):], ":")
	if len(parts) != probeFields || (parts[0] != "P1" && parts[0] != "R1") {
		return "", "", r, false
	}
	nums := make([]int64, 4)
	for i := range nums {
		v, err := strconv.ParseInt(parts[i+2], 10, 64)
		if err != nil {
			return "", "", r, false
		}
		nums[i] = v
	}
	return parts[0], parts[1], probeReply{seq: nums[0], ms: nums[1], sent: nums[2], recv: nums[3]}, true
}

func (c *docConn) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(probePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s := c.currentActive(); s != nil && s.ready.Load() {
				c.sendProbe(s)
			}
		}
	}
}

func (c *docConn) sendProbe(s *session) {
	p := &c.probe
	now := time.Now()
	sent := c.txData.Load()
	p.mu.Lock()
	p.seq++
	seq := p.seq
	if p.pending == nil {
		p.pending = map[int64]probeSample{}
	}
	p.pending[seq] = probeSample{at: now, dataSent: sent}
	for k, v := range p.pending {
		if now.Sub(v.at) > time.Minute {
			delete(p.pending, k)
		}
	}
	p.mu.Unlock()
	msg := fmt.Sprintf("%sP1:c:%d:%d:%d:%d", kaMarker, seq, now.UnixMilli(), sent, c.st.rxData.Load())
	if s.writeText(cursorPrefix+msg+cursorSuffix) == nil {
		c.st.probeSent.Add(1)
	}
}

// handleProbe reports whether payload was a probe. Replies go out on the same
// session the probe arrived on.
func (c *docConn) handleProbe(s *session, payload string) bool {
	kind, side, r, ok := parseProbe(payload)
	if !ok {
		return false
	}
	if side == "c" {
		// our own probe or reply echoed back by the document
		c.st.rxEcho.Add(1)
		return true
	}
	now := time.Now()
	if kind == "P1" {
		reply := fmt.Sprintf("%sR1:c:%d:%d:%d:%d", kaMarker, r.seq, r.ms, c.txData.Load(), c.st.rxData.Load())
		_ = s.writeText(cursorPrefix + reply + cursorSuffix)
		c.onPeerProbe(r)
		return true
	}
	c.onReply(r, now)
	return true
}

// onReply measures rtt and upstream loss from a reply to our probe.
func (c *docConn) onReply(r probeReply, now time.Time) {
	p := &c.probe
	p.mu.Lock()
	defer p.mu.Unlock()
	sample, ok := p.pending[r.seq]
	if !ok {
		return
	}
	delete(p.pending, r.seq)
	p.replies++
	rtt := now.Sub(sample.at).Milliseconds()
	c.st.probeRecv.Add(1)
	c.st.probeRttTotal.Add(rtt)
	c.st.probeRttMax.observe(rtt)
	r.localSent = sample.dataSent
	if prev := p.lastReply; prev != nil {
		p.upText = lossText("up", r.localSent-prev.localSent, r.recv-prev.recv)
	}
	p.lastReply = &r
	p.rttText = fmt.Sprintf("rtt=%dms avg=%dms max=%dms", rtt,
		c.st.probeRttTotal.Load()/max(c.st.probeRecv.Load(), 1), c.st.probeRttMax.v.Load())
	c.st.setProbeText(p.summary())
}

// onPeerProbe measures downstream loss from the exit node's own probe.
func (c *docConn) onPeerProbe(r probeReply) {
	p := &c.probe
	p.mu.Lock()
	defer p.mu.Unlock()
	r.localRecvAtArr = c.st.rxData.Load()
	if prev := p.lastPeer; prev != nil {
		p.dnText = lossText("dn", r.sent-prev.sent, r.localRecvAtArr-prev.localRecvAtArr)
	}
	p.lastPeer = &r
	c.st.setProbeText(p.summary())
}

func (p *probeState) summary() string {
	parts := []string{"probe"}
	for _, s := range []string{p.rttText, p.upText, p.dnText} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// lossText compares what one side sent with what the other side received
// between two probes. Either counter resets when a peer restarts, so a window
// with non-positive or impossible values is reported as unknown instead of a
// nonsense percentage.
func lossText(dir string, sent, got int64) string {
	if sent <= 0 || got < 0 || got > sent {
		return fmt.Sprintf("%s_loss=? (%d/%d)", dir, got, sent)
	}
	loss := float64(sent-got) * 100 / float64(sent)
	return fmt.Sprintf("%s_loss=%.1f%%(%d/%d)", dir, loss, got, sent)
}
