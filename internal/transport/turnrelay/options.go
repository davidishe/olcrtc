// Package turnrelay carries olcrtc bytes over a KCP session whose UDP path
// is a VK TURN allocation (client) or a plain public UDP listener (server).
//
// This mirrors the Lionheart / vk-turn-proxy model: the phone only talks to
// VK TURN; the NL agent exposes a public UDP KCP endpoint. Upper layers
// (muxconn AEAD + smux + SOCKS5) stay unchanged.
package turnrelay

import "github.com/openlibrecommunity/olcrtc/internal/transport"

// Options tunes turnrelay. Zero values mean "use transport.Config fields /
// package defaults".
type Options struct {
	// Endpoint is the peer agent host:port the client dials through TURN
	// (e.g. "195.133.81.165:56000").
	Endpoint string
	// ListenAddr is the server bind address (e.g. "0.0.0.0:56000").
	ListenAddr string
	// Direct skips TURN and dials Endpoint over plain UDP. Intended for
	// local tests; production clients must leave this false.
	Direct bool
}

// TransportOptions marks Options as a transport.Options value.
func (Options) TransportOptions() {}

var _ transport.Options = Options{}
