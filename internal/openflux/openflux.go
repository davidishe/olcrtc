// SPDX-License-Identifier: WTFPL

// Package openflux is an L3 client for the OpenFlux Yandex Docs transport.
//
// Device IPv4 packets travel as base64 cursor messages of a shared Yandex
// Docs document to an OpenFlux exit node. The wire format is compatible with
// upstream OpenFlux (github.com/p1neappleXpress/OpenFlux). This package adds
// the instrumentation that upstream lacks: queue drops, per-frame cursor
// counts, echo detection, TCP retransmission estimates in both directions and
// in-band probes that measure loss and latency of the document channel.
package openflux

// ai-generated: whole package (openflux client and diagnostics).

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"
	"time"
)

// TunnelAddress is the device address the exit node routes replies to.
// Upstream exit nodes hardcode it, so it is not configurable.
const TunnelAddress = "10.10.10.2"

const (
	queueSize    = 1024
	statsPeriod  = 5 * time.Second
	probePeriod  = 2 * time.Second
	keepAlive    = 10 * time.Second
	stallTimeout = 5 * time.Second

	// iOS kills a Packet Tunnel extension at roughly 50 MB. Without a soft limit
	// the Go heap grew with traffic and jetsam killed the tunnel mid-video
	// (13.09.2026: 9 MB -> 38 MB in 10 s, then silence).
	memoryLimit = 30 << 20
	gcPercent   = 20
)

var (
	// ErrAlreadyRunning is returned by Start when a tunnel is active.
	ErrAlreadyRunning = errors.New("openflux: already running")
	// ErrDocURLRequired is returned by Start without a document URL.
	ErrDocURLRequired = errors.New("openflux: document url is required")
)

// Tunnel is one running OpenFlux client.
type Tunnel struct {
	docURL string
	st     *stats
	conn   *docConn
	outQ   chan []byte
	flows  *flowTable
	dns    *dnsResolver
	ctx    context.Context //nolint:containedctx // ReadPacket must unblock on Stop
	cancel context.CancelFunc
	done   sync.WaitGroup
}

// Start connects to the document and begins forwarding.
func Start(docURL string) (*Tunnel, error) {
	if docURL == "" {
		return nil, ErrDocURLRequired
	}
	debug.SetMemoryLimit(memoryLimit)
	debug.SetGCPercent(gcPercent)
	ctx, cancel := context.WithCancel(context.Background())
	st := newStats()
	t := &Tunnel{
		docURL: docURL,
		st:     st,
		outQ:   make(chan []byte, queueSize),
		flows:  newFlowTable(),
		ctx:    ctx,
		cancel: cancel,
	}
	t.dns = newDNSResolver(st)
	t.conn = newDocConn(docURL, st, t.deliver)

	t.run(ctx, t.conn.loop)
	t.run(ctx, t.conn.writer)
	t.run(ctx, t.conn.keepAliveLoop)
	t.run(ctx, t.conn.probeLoop)
	t.run(ctx, t.statsLoop)
	logf("openflux: start doc=%s addr=%s queue=%d", redactURL(docURL), TunnelAddress, queueSize)
	return t, nil
}

func (t *Tunnel) run(ctx context.Context, fn func(context.Context)) {
	t.done.Add(1)
	go func() {
		defer t.done.Done()
		fn(ctx)
	}()
}

// Stop tears the tunnel down and waits for its goroutines.
func (t *Tunnel) Stop() {
	t.cancel()
	t.conn.close()
	t.done.Wait()
	logf("openflux: stopped %s", t.st.totals())
}

// Connected reports whether the document websocket is up.
func (t *Tunnel) Connected() bool {
	return t.conn.connected.Load()
}

// WritePacket accepts one IPv4 packet from the device.
func (t *Tunnel) WritePacket(pkt []byte) {
	t.handleDevicePacket(pkt)
}

// ReadPacket returns the next packet for the device or nil on timeout/stop.
func (t *Tunnel) ReadPacket(timeout time.Duration) []byte {
	if timeout <= 0 {
		select {
		case p := <-t.outQ:
			t.st.devOutPkts.Add(1)
			return p
		default:
			return nil
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case p := <-t.outQ:
		t.st.devOutPkts.Add(1)
		return p
	case <-timer.C:
		return nil
	case <-t.ctx.Done():
		return nil
	}
}

// enqueueDevice queues a packet for the device, counting drops.
func (t *Tunnel) enqueueDevice(p []byte) {
	select {
	case t.outQ <- p:
		t.st.outQHigh.observe(int64(len(t.outQ)))
	default:
		t.st.outQDrops.Add(1)
	}
}

// deliver is called by the document connection for every data payload.
func (t *Tunnel) deliver(pkt []byte) {
	t.flows.observeDown(pkt, t.st)
	t.enqueueDevice(pkt)
}

func (t *Tunnel) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(statsPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.flows.expire(time.Now())
			t.conn.checkStall(time.Now())
			if line, ok := t.st.snapshot(t.conn, len(t.outQ), t.flows.size()); ok {
				logf("%s", line)
			}
		}
	}
}
