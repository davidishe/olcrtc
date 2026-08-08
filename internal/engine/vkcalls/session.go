// Package vkcalls implements an engine.Session for the VK/OK Calls SFU
// signaling protocol used by VK Звонки. Auth (joinConversationByLink) lives
// in internal/auth/vkcalls; this engine consumes the WSS endpoint, token and
// ICE servers from Credentials.
//
// Wire protocol (v1, from @vkontakte/calls-sdk + community reverse engineering):
//   - Dial WSS endpoint with platform/version/capabilities/tgt=join
//   - First JSON message carries conversation + participants (connection hello)
//   - accept-call with mediaSettings (video on for vp8channel)
//   - SERVER topology: allocate-consumer with local SDP offer; handle
//     consumer-answered / producer-updated notifications with accept-producer
//   - ICE candidates via transmit-data {candidate}
//   - Raw "ping"/"pong" heartbeats on the socket
package vkcalls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openlibrecommunity/olcrtc/internal/engine"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v4"
)

const (
	defaultSendQueueSize = 5000
	wsReadTimeout        = 60 * time.Second
	wsHandshakeTimeout   = 15 * time.Second
	connectMediaTimeout  = 25 * time.Second

	platformWEB       = "WEB"
	appVersion        = "1.1"
	protocolVersion   = "5"
	deviceBrowser     = "browser"
	capabilitiesFlags = "2F7F"
	clientTypePortal  = "PORTAL" // unused default; VK web uses clientType=VK
	clientTypeVK      = "VK"
	tgtJoin           = "join"
)

var (
	// ErrURLRequired is returned when no signaling URL was supplied.
	ErrURLRequired = errors.New("vkcalls signaling URL required")
	// ErrSessionClosed is returned when the session is closed mid-operation.
	ErrSessionClosed = errors.New("vkcalls session closed")
	// ErrMediaTimeout is returned when media is not ready in time.
	ErrMediaTimeout = errors.New("vkcalls media timeout")
	// ErrByteStreamUnsupported marks the v1 byte path as unavailable.
	ErrByteStreamUnsupported = engine.ErrByteStreamUnsupported
)

// Session is the vkcalls engine handle.
type Session struct {
	name           string
	endpoint       string
	signalingToken string
	conversationID string
	peerID         int64
	uid            string
	extra          map[string]string
	refresh        func(ctx context.Context) (engine.Credentials, error)

	ws     *websocket.Conn
	wsMu   sync.Mutex
	seq    atomic.Int32
	pc     *webrtc.PeerConnection
	pcMu   sync.Mutex

	onData          func([]byte)
	onReconnect     func(*webrtc.DataChannel)
	shouldReconnect func() bool
	onEnded         func(string)

	closeCh       chan struct{}
	mediaReady    chan struct{}
	mediaReadyOnce sync.Once
	closed        atomic.Bool
	sendQueue     chan []byte

	videoTrackMu sync.RWMutex
	videoTracks  []webrtc.TrackLocal
	onVideoTrack func(*webrtc.TrackRemote, *webrtc.RTPReceiver)

	iceServers []webrtc.ICEServer
	wg         sync.WaitGroup
}

// New creates a vkcalls engine session from auth credentials.
func New(_ context.Context, cfg engine.Config) (engine.Session, error) {
	if cfg.URL == "" {
		return nil, ErrURLRequired
	}
	extra := cfg.Extra
	if extra == nil {
		extra = map[string]string{}
	}
	peerID, _ := strconv.ParseInt(extra["peerId"], 10, 64)
	s := &Session{
		name:           cfg.Name,
		endpoint:       cfg.URL,
		signalingToken: cfg.Token,
		conversationID: extra["conversationId"],
		peerID:         peerID,
		uid:            extra["uid"],
		extra:          extra,
		refresh:        cfg.Refresh,
		onData:         cfg.OnData,
		closeCh:        make(chan struct{}),
		mediaReady:     make(chan struct{}),
		sendQueue:      make(chan []byte, defaultSendQueueSize),
		iceServers:     parseICEFromExtra(extra),
	}
	return s, nil
}

func init() { //nolint:gochecknoinits // engine registration is the canonical Go pattern for plugins
	engine.Register("vkcalls", New)
}

// Capabilities reports video-only support in v1.
func (s *Session) Capabilities() engine.Capabilities {
	return engine.Capabilities{ByteStream: false, VideoTrack: true}
}

// Connect joins signaling and establishes the SFU PeerConnection.
func (s *Session) Connect(ctx context.Context) error {
	s.closed.Store(false)
	if err := s.setupPeerConnection(); err != nil {
		return err
	}
	if err := s.dialSignaling(ctx); err != nil {
		return err
	}

	hello, err := s.waitConnectionHello(ctx, 15*time.Second)
	if err != nil {
		return err
	}
	_ = hello

	s.wg.Add(1)
	go s.readLoop()

	if err := s.sendAcceptCall(); err != nil {
		return err
	}
	if err := s.allocateConsumer(ctx); err != nil {
		return err
	}

	select {
	case <-s.mediaReady:
		return nil
	case <-time.After(connectMediaTimeout):
		// SFU may take longer; treat ICE connected as success below.
		if s.pc != nil && s.pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
			return nil
		}
		return ErrMediaTimeout
	case <-ctx.Done():
		return fmt.Errorf("connect cancelled: %w", ctx.Err())
	case <-s.closeCh:
		return ErrSessionClosed
	}
}

func (s *Session) markMediaReady() {
	s.mediaReadyOnce.Do(func() { close(s.mediaReady) })
}

// Send is unsupported in v1 (no stable byte stream).
func (s *Session) Send([]byte) error { return ErrByteStreamUnsupported }

// Close tears down signaling and media.
func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.closeCh)
	s.wsMu.Lock()
	if s.ws != nil {
		_ = s.ws.WriteJSON(map[string]any{
			"command":  "hangup",
			"sequence": s.nextSeq(),
			"reason":   "HUNGUP",
		})
		_ = s.ws.Close()
		s.ws = nil
	}
	s.wsMu.Unlock()
	s.pcMu.Lock()
	if s.pc != nil {
		_ = s.pc.Close()
		s.pc = nil
	}
	s.pcMu.Unlock()
	s.wg.Wait()
	if s.onEnded != nil {
		s.onEnded("closed")
	}
	return nil
}

func (s *Session) SetReconnectCallback(cb func(*webrtc.DataChannel)) { s.onReconnect = cb }
func (s *Session) SetShouldReconnect(fn func() bool)                 { s.shouldReconnect = fn }
func (s *Session) SetEndedCallback(cb func(string))                  { s.onEnded = cb }

// WatchConnection is a no-op placeholder; reconnect is best-effort via Reconnect.
func (s *Session) WatchConnection(context.Context) {}

func (s *Session) CanSend() bool            { return false }
func (s *Session) SubscriberCanSend() bool  { return s.pc != nil && s.pc.ConnectionState() == webrtc.PeerConnectionStateConnected }
func (s *Session) GetSendQueue() chan []byte { return s.sendQueue }
func (s *Session) GetBufferedAmount() uint64 { return 0 }

// Reconnect refreshes credentials and reconnects when possible.
func (s *Session) Reconnect(reason string) {
	logger.Infof("vkcalls reconnect requested: %s", reason)
	if s.shouldReconnect != nil && !s.shouldReconnect() {
		return
	}
	if s.refresh == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		creds, err := s.refresh(ctx)
		if err != nil {
			logger.Infof("vkcalls refresh failed: %v", err)
			return
		}
		_ = s.Close()
		s.endpoint = creds.URL
		s.signalingToken = creds.Token
		s.extra = creds.Extra
		s.iceServers = parseICEFromExtra(creds.Extra)
		s.closeCh = make(chan struct{})
		s.mediaReady = make(chan struct{})
		s.mediaReadyOnce = sync.Once{}
		s.closed.Store(false)
		if err := s.Connect(ctx); err != nil {
			logger.Infof("vkcalls reconnect failed: %v", err)
		}
	}()
}

// AddVideoTrack implements engine.VideoTrackCapable.
func (s *Session) AddVideoTrack(track webrtc.TrackLocal) error {
	s.videoTrackMu.Lock()
	s.videoTracks = append(s.videoTracks, track)
	s.videoTrackMu.Unlock()
	s.pcMu.Lock()
	defer s.pcMu.Unlock()
	if s.pc == nil {
		return nil
	}
	if _, err := s.pc.AddTrack(track); err != nil {
		return fmt.Errorf("add video track: %w", err)
	}
	return nil
}

// SetVideoTrackHandler implements engine.VideoTrackCapable.
func (s *Session) SetVideoTrackHandler(cb func(*webrtc.TrackRemote, *webrtc.RTPReceiver)) {
	s.videoTrackMu.Lock()
	s.onVideoTrack = cb
	s.videoTrackMu.Unlock()
}

func (s *Session) nextSeq() int {
	return int(s.seq.Add(1))
}

func newWebRTCAPI() (*webrtc.API, error) {
	settingEngine := webrtc.SettingEngine{}
	if protect.Protector != nil || runtime.GOOS == "android" {
		pnet, err := protect.NewProtectedNet()
		if err != nil {
			return nil, fmt.Errorf("protected net: %w", err)
		}
		settingEngine.SetNet(pnet)
		settingEngine.SetICEProxyDialer(protect.NewProxyDialer())
		settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	}
	settingEngine.LoggerFactory = logger.NewPionLoggerFactory()
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	settingEngine.SetIPFilter(func(ip net.IP) bool { return ip.To4() != nil })

	mediaEngine := &webrtc.MediaEngine{}
	if err := mediaEngine.RegisterDefaultCodecs(); err != nil {
		return nil, fmt.Errorf("register codecs: %w", err)
	}
	interceptorRegistry := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(mediaEngine, interceptorRegistry); err != nil {
		return nil, fmt.Errorf("register interceptors: %w", err)
	}
	return webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
		webrtc.WithMediaEngine(mediaEngine),
		webrtc.WithInterceptorRegistry(interceptorRegistry),
	), nil
}

func parseICEFromExtra(extra map[string]string) []webrtc.ICEServer {
	var out []webrtc.ICEServer
	for _, key := range []string{"stun_server", "turn_server"} {
		raw := extra[key]
		if raw == "" {
			continue
		}
		var iceBlk struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		}
		if err := json.Unmarshal([]byte(raw), &iceBlk); err != nil {
			continue
		}
		if len(iceBlk.URLs) == 0 {
			continue
		}
		out = append(out, webrtc.ICEServer{
			URLs:       iceBlk.URLs,
			Username:   iceBlk.Username,
			Credential: iceBlk.Credential,
		})
	}
	return out
}
