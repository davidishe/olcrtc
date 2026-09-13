// SPDX-License-Identifier: WTFPL

package mobile

// ai-generated: gomobile surface for the OpenFlux L3 tunnel.

import (
	"strings"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/openflux"
)

var (
	ofMu     sync.Mutex       //nolint:gochecknoglobals // one tunnel per extension process
	ofTunnel *openflux.Tunnel //nolint:gochecknoglobals // one tunnel per extension process
)

// OpenfluxStart starts the OpenFlux tunnel over a public Yandex Docs URL.
// Set a log writer first: diagnostics go to the standard logger.
func OpenfluxStart(docURL string) error {
	ofMu.Lock()
	defer ofMu.Unlock()
	if ofTunnel != nil {
		return openflux.ErrAlreadyRunning
	}
	t, err := openflux.Start(strings.TrimSpace(docURL))
	if err != nil {
		return err //nolint:wrapcheck // sentinel errors from openflux
	}
	ofTunnel = t
	return nil
}

// OpenfluxStop stops the tunnel. Safe to call when not running.
func OpenfluxStop() {
	ofMu.Lock()
	t := ofTunnel
	ofTunnel = nil
	ofMu.Unlock()
	if t != nil {
		t.Stop()
	}
}

// OpenfluxIsConnected reports whether the document websocket is up.
func OpenfluxIsConnected() bool {
	if t := ofCurrent(); t != nil {
		return t.Connected()
	}
	return false
}

// OpenfluxWritePacket forwards one IPv4 packet from the device.
func OpenfluxWritePacket(pkt []byte) {
	if t := ofCurrent(); t != nil {
		t.WritePacket(pkt)
	}
}

// OpenfluxReadPacket blocks up to timeoutMillis for a packet for the device.
// Returns nil on timeout or when stopped; 0 polls without blocking.
func OpenfluxReadPacket(timeoutMillis int) []byte {
	t := ofCurrent()
	if t == nil {
		return nil
	}
	return t.ReadPacket(time.Duration(timeoutMillis) * time.Millisecond)
}

// OpenfluxTunnelAddress is the device address the exit node expects.
func OpenfluxTunnelAddress() string {
	return openflux.TunnelAddress
}

// OpenfluxBypassAddrs lists IPv4 addresses (comma separated) that must not be
// routed into the tunnel: the DoT resolvers used for device DNS.
func OpenfluxBypassAddrs() string {
	return strings.Join(openflux.DoTBypassAddrs(), ",")
}

func ofCurrent() *openflux.Tunnel {
	ofMu.Lock()
	defer ofMu.Unlock()
	return ofTunnel
}
