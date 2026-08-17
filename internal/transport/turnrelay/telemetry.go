package turnrelay

import (
	"fmt"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/xtaci/kcp-go/v5"
)

// telemetryInterval is how often the KCP counters are sampled. Ten seconds is
// short enough to localise a stall inside a browsing session and long enough
// that the line itself costs nothing on the wire.
const telemetryInterval = 10 * time.Second

// snmpSample is the subset of [kcp.Snmp] that answers the questions we
// actually have: how much is lost, how much is retransmitted, whether FEC
// earns its redundancy, and what the real RTT is.
//
// The counters come from kcp.DefaultSnmp, which is process-global: on an agent
// serving several peers the numbers are the sum over all of them. That is fine
// for the client (one session) and for spotting agent-wide loss, but do not
// read a per-peer loss rate out of it.
type snmpSample struct {
	outSegs   uint64
	inSegs    uint64
	outBytes  uint64
	inBytes   uint64
	sent      uint64
	received  uint64
	retrans   uint64
	fastRe    uint64
	earlyRe   uint64
	lost      uint64
	repeat    uint64
	fecRecov  uint64
	fecErrs   uint64
	fecParity uint64
	inErrs    uint64
	kcpInErrs uint64
}

func takeSnmpSample() snmpSample {
	s := kcp.DefaultSnmp.Copy()
	return snmpSample{
		outSegs:   s.OutSegs,
		inSegs:    s.InSegs,
		outBytes:  s.OutBytes,
		inBytes:   s.InBytes,
		sent:      s.BytesSent,
		received:  s.BytesReceived,
		retrans:   s.RetransSegs,
		fastRe:    s.FastRetransSegs,
		earlyRe:   s.EarlyRetransSegs,
		lost:      s.LostSegs,
		repeat:    s.RepeatSegs,
		fecRecov:  s.FECRecovered,
		fecErrs:   s.FECErrs,
		fecParity: s.FECParityShards,
		inErrs:    s.InErrs,
		kcpInErrs: s.KCPInErrors,
	}
}

// sub returns the counters accumulated between two samples. KCP counters only
// grow, but guard anyway so a Reset elsewhere cannot produce absurd deltas.
func (s snmpSample) sub(prev snmpSample) snmpSample {
	d := func(now, was uint64) uint64 {
		if now < was {
			return 0
		}
		return now - was
	}
	return snmpSample{
		outSegs:   d(s.outSegs, prev.outSegs),
		inSegs:    d(s.inSegs, prev.inSegs),
		outBytes:  d(s.outBytes, prev.outBytes),
		inBytes:   d(s.inBytes, prev.inBytes),
		sent:      d(s.sent, prev.sent),
		received:  d(s.received, prev.received),
		retrans:   d(s.retrans, prev.retrans),
		fastRe:    d(s.fastRe, prev.fastRe),
		earlyRe:   d(s.earlyRe, prev.earlyRe),
		lost:      d(s.lost, prev.lost),
		repeat:    d(s.repeat, prev.repeat),
		fecRecov:  d(s.fecRecov, prev.fecRecov),
		fecErrs:   d(s.fecErrs, prev.fecErrs),
		fecParity: d(s.fecParity, prev.fecParity),
		inErrs:    d(s.inErrs, prev.inErrs),
		kcpInErrs: d(s.kcpInErrs, prev.kcpInErrs),
	}
}

func (s snmpSample) idle() bool {
	return s.outSegs == 0 && s.inSegs == 0
}

// startTelemetry samples the KCP counters until the transport closes. It is
// launched from Connect for both roles so client and agent lines can be
// compared side by side for the same session.
func (t *Transport) startTelemetry() {
	t.wg.Add(1)
	go t.telemetryLoop()
}

func (t *Transport) telemetryLoop() {
	defer t.wg.Done()

	role := "client"
	if t.isServer() {
		role = "agent"
	}
	prev := takeSnmpSample()

	ticker := time.NewTicker(telemetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-t.closed:
			return
		case <-ticker.C:
			now := takeSnmpSample()
			delta := now.sub(prev)
			prev = now
			logger.Infof("turnrelay: kcp %s %s", role, formatSnmpDelta(delta, t.sampleRTT()))
		}
	}
}

// sampleRTT reports the smoothed RTT and retransmission timeout of one live
// session, or an empty string when none is available. On the agent this is
// whichever peer the map yields — enough to see the order of magnitude.
func (t *Transport) sampleRTT() string {
	t.mu.RLock()
	sess := t.client
	if sess == nil {
		for _, p := range t.peers {
			if p != nil && p.sess != nil {
				sess = p.sess
				break
			}
		}
	}
	t.mu.RUnlock()
	if sess == nil {
		return ""
	}
	return fmt.Sprintf(" srtt=%dms rto=%dms", sess.GetSRTT(), sess.GetRTO())
}

// formatSnmpDelta renders one sampling window as a single line. Percentages are
// relative to segments sent in the same window, so a window with no traffic
// prints plain zeroes instead of a misleading ratio.
func formatSnmpDelta(d snmpSample, rtt string) string {
	var b strings.Builder

	if d.idle() {
		b.WriteString(fmt.Sprintf("idle %s: no segments in or out", telemetryInterval))
		b.WriteString(rtt)
		return b.String()
	}

	b.WriteString(fmt.Sprintf("out=%dseg/%s in=%dseg/%s",
		d.outSegs, humanBytes(d.outBytes), d.inSegs, humanBytes(d.inBytes)))
	b.WriteString(fmt.Sprintf(" retrans=%d(%s) fast=%d early=%d lost=%d(%s) dup=%d",
		d.retrans, percentOf(d.retrans, d.outSegs),
		d.fastRe, d.earlyRe,
		d.lost, percentOf(d.lost, d.outSegs),
		d.repeat))
	b.WriteString(fmt.Sprintf(" fec=recovered:%d/errs:%d/parity:%d", d.fecRecov, d.fecErrs, d.fecParity))
	// Wire bytes over payload bytes: everything FEC parity, retransmits and
	// KCP headers add on top of what the tunnel actually carried.
	b.WriteString(fmt.Sprintf(" overhead=up:%s down:%s",
		ratioOf(d.outBytes, d.sent), ratioOf(d.inBytes, d.received)))
	if d.inErrs != 0 || d.kcpInErrs != 0 {
		b.WriteString(fmt.Sprintf(" errs=udp:%d kcp:%d", d.inErrs, d.kcpInErrs))
	}
	b.WriteString(rtt)
	return b.String()
}

func percentOf(part, total uint64) string {
	if total == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", float64(part)*100/float64(total))
}

func ratioOf(wire, payload uint64) string {
	if payload == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2fx", float64(wire)/float64(payload))
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}
