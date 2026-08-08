// Package tunnel exposes olcrtc's server-side tunnel as an embeddable Go library.
//
// A [Server] accepts encrypted tunnel connections over a WebRTC SFU carrier
// and proxies their traffic to arbitrary TCP targets. Consumers plug in
// authorization and observability via the [Config] hooks:
//
//	srv, err := tunnel.New(tunnel.Config{
//	    Transport: "datachannel",
//	    Carrier:   "jitsi",
//	    RoomURL:   "https://meet.small-dm.ru/myroom",
//	    KeyHex:    "<64-char hex>",
//	    DNSServer: "8.8.8.8:53",
//	    AuthHook: func(deviceID string, claims map[string]any) (string, error) {
//	        return db.IssueSession(deviceID, claims)
//	    },
//	})
//	if err != nil { log.Fatal(err) }
//	go srv.Run(ctx)
//	_ = srv.DisconnectDevice("device-guid")
//
// Call [RegisterDefaults] once at program start to register the built-in
// carriers (jitsi, telemost, wbstream, vkcalls) and transports (datachannel,
// videochannel, seichannel, vp8channel).
package tunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
	"github.com/openlibrecommunity/olcrtc/internal/handshake"
	"github.com/openlibrecommunity/olcrtc/internal/server"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/transport/turnrelay"
	"github.com/openlibrecommunity/olcrtc/internal/transport/vp8channel"
)

// TransportOptions is the marker type for transport-specific tuning options.
type TransportOptions = transport.Options

// NewVp8TransportOptions builds vp8channel.Options for [Config.TransportOptions].
// Zero fps/batch fall back to vp8channel package defaults at transport init.
func NewVp8TransportOptions(fps, batchSize int) TransportOptions {
	return vp8channel.Options{FPS: fps, BatchSize: batchSize}
}

// NewTurnRelayOptions builds turnrelay.Options for [Config.TransportOptions].
// endpoint is the client-side agent host:port; listen is the server bind addr.
func NewTurnRelayOptions(endpoint, listen string, direct bool) TransportOptions {
	return turnrelay.Options{Endpoint: endpoint, ListenAddr: listen, Direct: direct}
}

// AuthFunc is invoked after CLIENT_HELLO to authorize the client and issue a
// session ID. Returning a non-nil error rejects the handshake; the error's
// message is forwarded to the client as the reject reason, so it should not
// leak sensitive details.
type AuthFunc = handshake.AuthFunc

// SessionOpenFunc fires right after a successful handshake, before the server
// starts accepting tunnel streams on that session.
type SessionOpenFunc = server.SessionOpenFunc

// SessionCloseFunc fires when a session ends.
type SessionCloseFunc = server.SessionCloseFunc

// TrafficFunc fires once per tunnel stream after both copy loops finish.
type TrafficFunc = server.TrafficFunc

// SessionSnapshot describes an active tunnel session.
type SessionSnapshot struct {
	SessionID string
	DeviceID  string
	OpenedAt  time.Time
}

// Config holds runtime server configuration.
type Config struct {
	Transport string
	Carrier   string
	RoomURL   string

	Engine string
	URL    string
	// Token is the engine/signaling token for direct carriers (auth.provider=none).
	Token string
	// AuthToken is a pre-issued carrier account token (wbstream moderator JWT,
	// vkcalls OK session_key / anonymToken, etc.). Forwarded to auth.Provider.
	// When empty, Token is used as a fallback so embedders that only set Token
	// (historically Cockney agent CarrierToken) still reach auth providers.
	AuthToken string

	KeyHex         string
	DNSServer      string
	SOCKSProxyAddr string
	SOCKSProxyPort int
	SOCKSProxyUser string
	SOCKSProxyPass string

	// ListenAddr is the turnrelay server UDP bind (e.g. "0.0.0.0:56000").
	ListenAddr string
	// Endpoint is the turnrelay client peer agent host:port.
	Endpoint string

	TransportOptions TransportOptions

	AuthHook       AuthFunc
	OnSessionOpen  SessionOpenFunc
	OnSessionClose SessionCloseFunc
	OnTraffic      TrafficFunc
}

// Server is an embeddable tunnel server with session disconnect controls.
type Server struct {
	cfg   Config
	inner *server.Server
}

// New returns a Server configured by cfg. Call [Server.Run] to start it.
func New(cfg Config) (*Server, error) {
	authToken := cfg.AuthToken
	if authToken == "" {
		authToken = cfg.Token
	}
	opts := cfg.TransportOptions
	if opts == nil && (cfg.ListenAddr != "" || cfg.Endpoint != "") {
		opts = NewTurnRelayOptions(cfg.Endpoint, cfg.ListenAddr, false)
	}
	inner, err := server.New(server.Config{
		Transport:        cfg.Transport,
		Carrier:          cfg.Carrier,
		RoomURL:          cfg.RoomURL,
		Engine:           cfg.Engine,
		URL:              cfg.URL,
		Token:            cfg.Token,
		AuthToken:        authToken,
		KeyHex:           cfg.KeyHex,
		DNSServer:        cfg.DNSServer,
		SOCKSProxyAddr:   cfg.SOCKSProxyAddr,
		SOCKSProxyPort:   cfg.SOCKSProxyPort,
		SOCKSProxyUser:   cfg.SOCKSProxyUser,
		SOCKSProxyPass:   cfg.SOCKSProxyPass,
		ListenAddr:       cfg.ListenAddr,
		TransportOptions: opts,
		AuthHook:         cfg.AuthHook,
		OnSessionOpen:    cfg.OnSessionOpen,
		OnSessionClose:   cfg.OnSessionClose,
		OnTraffic:        cfg.OnTraffic,
	})
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	return &Server{cfg: cfg, inner: inner}, nil
}

// Run starts the server and blocks until ctx is cancelled or the carrier ends.
func (s *Server) Run(ctx context.Context) error {
	if err := s.inner.Run(ctx); err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	return nil
}

// DisconnectSession closes one session by ID.
func (s *Server) DisconnectSession(sessionID string) error {
	return s.inner.DisconnectSession(sessionID)
}

// DisconnectDevice closes all sessions for a device. Returns closed count.
func (s *Server) DisconnectDevice(deviceID string) int {
	return s.inner.DisconnectDevice(deviceID)
}

// ActiveSessions returns currently tracked sessions.
func (s *Server) ActiveSessions() []SessionSnapshot {
	raw := s.inner.ActiveSessions()
	out := make([]SessionSnapshot, len(raw))
	for i, sn := range raw {
		out[i] = SessionSnapshot{
			SessionID: sn.SessionID,
			DeviceID:  sn.DeviceID,
			OpenedAt:  sn.OpenedAt,
		}
	}
	return out
}

// RegisterDefaults registers the built-in carriers, links and transports.
func RegisterDefaults() {
	session.RegisterDefaults()
}
