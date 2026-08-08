// Package vkcalls implements an engine.Session for the VK/OK Calls SFU
// signaling protocol used by VK Звонки. Auth (joinConversationByLink) lives
// in internal/auth/vkcalls; this engine consumes the WSS endpoint, token and
// ICE servers from Credentials.
//
// Wire protocol (v1, from @vkontakte/calls-sdk + community reverse engineering):
//   - Dial WSS endpoint with platform/version/capabilities/tgt=join
//   - First JSON message carries conversation + participants (connection hello)
//   - accept-call with mediaSettings (video on for vp8channel)
//   - SERVER topology: allocate-consumer with capabilities only (no local SDP);
//     SFU sends producer-updated (remote offer) → accept-producer (local answer)
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
	"strings"
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
	connectMediaTimeout = 40 * time.Second
	connectPeerTimeout  = 2 * time.Minute

	platformWEB = "WEB"
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
	peerID             int64
	remoteParticipantID int64
	uid                string
	extra              map[string]string
	refresh            func(ctx context.Context) (engine.Credentials, error)

	ws     *websocket.Conn
	wsMu   sync.Mutex
	seq    atomic.Int32
	pc     *webrtc.PeerConnection
	pcMu   sync.Mutex

	onData          func([]byte)
	onReconnect     func(*webrtc.DataChannel)
	shouldReconnect func() bool
	onEnded         func(string)

	closeCh        chan struct{}
	mediaReady     chan struct{}
	mediaReadyOnce sync.Once
	topologySERVER chan struct{}
	topologyOnce   sync.Once
	acceptPeers    chan []int64
	closed         atomic.Bool
	sendQueue      chan []byte
	directMode     atomic.Bool
	answeredRemote atomic.Bool
	mediaEverReady atomic.Bool
	rearming       atomic.Bool
	awaitingRearm  atomic.Bool
	endedOnce      sync.Once

	videoTrackMu sync.RWMutex
	videoTracks  []webrtc.TrackLocal
	onVideoTrack func(*webrtc.TrackRemote, *webrtc.RTPReceiver)
	pendingRemote []pendingRemoteTrack

	iceServers []webrtc.ICEServer
	wg         sync.WaitGroup
}

type pendingRemoteTrack struct {
	track    *webrtc.TrackRemote
	receiver *webrtc.RTPReceiver
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
		topologySERVER: make(chan struct{}),
		acceptPeers:    make(chan []int64, 1),
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

// Connect joins signaling and establishes the PeerConnection (SERVER SFU or DIRECT P2P).
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

	s.wg.Add(1)
	go s.readLoop()

	if err := s.sendAcceptCall(); err != nil {
		return err
	}

	topology := strings.ToUpper(strings.TrimSpace(hello.Conversation.Topology))
	logger.Infof("vkcalls: conversation topology=%s participants=%d", topology, len(hello.Conversation.Participants))

	remoteID := pickRemoteParticipant(hello, s.uid)
	// DIRECT: arm answer path before accept-call peers settle so an early
	// remote offer is not answered-and-dropped (directMode was false).
	if (topology == "" || topology == "DIRECT") && remoteID != 0 {
		s.remoteParticipantID = remoteID
		s.directMode.Store(true)
	}

	if topology == "" || topology == "DIRECT" {
		// Agent often joins an empty 1:1 room and must wait for the phone.
		waitPeer := time.NewTimer(connectPeerTimeout)
		defer waitPeer.Stop()
		logger.Infof("vkcalls: DIRECT waiting for remote participant (timeout=%s)", connectPeerTimeout)
		for remoteID == 0 {
			select {
			case ids := <-s.acceptPeers:
				if len(ids) > 0 {
					remoteID = ids[0]
				}
			case <-waitPeer.C:
				return fmt.Errorf("%w: DIRECT call has no remote participant yet", ErrMediaTimeout)
			case <-ctx.Done():
				return ctx.Err()
			case <-s.closeCh:
				return ErrSessionClosed
			case <-time.After(250 * time.Millisecond):
				if s.remoteParticipantID != 0 {
					remoteID = s.remoteParticipantID
				}
			}
		}
		s.remoteParticipantID = remoteID
		s.directMode.Store(true)
		logger.Infof("vkcalls: DIRECT P2P with participantId=%d self=%d", remoteID, s.selfParticipantID())
		if err := s.connectDirect(ctx, remoteID); err != nil {
			return err
		}
	} else {
		select {
		case ids := <-s.acceptPeers:
			if len(ids) > 0 {
				remoteID = ids[0]
				s.remoteParticipantID = remoteID
			}
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := s.allocateConsumer(ctx); err != nil {
			return err
		}
	}

	select {
	case <-s.mediaReady:
		return nil
	case <-time.After(connectMediaTimeout):
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

func pickRemoteParticipant(hello *connectionHello, selfUID string) int64 {
	self := strings.TrimSpace(selfUID)
	for _, p := range hello.Conversation.Participants {
		idStr := strconv.FormatInt(p.ID, 10)
		if self != "" && (idStr == self || p.ExternalID.ID == self) {
			continue
		}
		if p.ID != 0 {
			return p.ID
		}
	}
	return 0
}

func (s *Session) selfParticipantID() int64 {
	if id, err := strconv.ParseInt(strings.TrimSpace(s.uid), 10, 64); err == nil && id != 0 {
		return id
	}
	return s.peerID
}

// connectDirect sets up 1:1 WebRTC.
//
// Role: Cockney NL agent (directRole=offer) offers after a short grace period
// so a phone that still CreateOffer's first can be answered without glare.
// Mobile (directRole=answer) only waits for the remote offer.
func (s *Session) connectDirect(ctx context.Context, remoteParticipantID int64) error {
	s.remoteParticipantID = remoteParticipantID
	s.directMode.Store(true)
	logger.Infof("vkcalls: ICE servers configured=%d", len(s.iceServers))

	selfID := s.selfParticipantID()
	if !s.preferDirectOffer() {
		logger.Infof("vkcalls: DIRECT answerer self=%d remote=%d (waiting for offer)", selfID, remoteParticipantID)
		_ = ctx
		return nil
	}

	// Older phone builds always CreateOffer. Wait briefly so we can answer
	// their offer while still Stable — pion cannot SDP-rollback glare.
	grace := 3 * time.Second
	logger.Infof("vkcalls: DIRECT offerer self=%d remote=%d (grace=%s for remote offer)", selfID, remoteParticipantID, grace)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	for !s.answeredRemote.Load() {
		select {
		case <-timer.C:
			goto createLocalOffer
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closeCh:
			return ErrSessionClosed
		case <-time.After(50 * time.Millisecond):
		}
	}
	logger.Infof("vkcalls: DIRECT answered remote offer during grace (skip local offer)")
	return nil

createLocalOffer:
	if s.answeredRemote.Load() {
		logger.Infof("vkcalls: DIRECT answered remote offer during grace (skip local offer)")
		return nil
	}
	logger.Infof("vkcalls: DIRECT creating local offer self=%d remote=%d", selfID, remoteParticipantID)

	s.pcMu.Lock()
	pc := s.pc
	s.pcMu.Unlock()
	if pc == nil {
		return fmt.Errorf("peer connection not ready")
	}

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local offer: %w", err)
	}
	local := pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("nil local description after offer")
	}
	_ = ctx
	return s.sendSDP(*local)
}

// preferDirectOffer reports whether this session should CreateOffer in DIRECT.
// Authorized agent (auth.token = OK session_key) offers; guest/anonym answers.
// Fall back to lower userId only when directRole is unset (older binaries).
func (s *Session) preferDirectOffer() bool {
	if s.extra != nil {
		switch strings.ToLower(strings.TrimSpace(s.extra["directRole"])) {
		case "offer", "offerer", "agent":
			return true
		case "answer", "answerer", "client", "guest":
			return false
		}
	}
	selfID := s.selfParticipantID()
	return selfID == 0 || selfID < s.remoteParticipantID
}

func (s *Session) markMediaReady() {
	s.mediaEverReady.Store(true)
	s.mediaReadyOnce.Do(func() { close(s.mediaReady) })
}

// signalEnded notifies the transport that the session is over (cancels Run).
// Safe to call multiple times; only the first fires onEnded.
func (s *Session) signalEnded(reason string) {
	s.endedOnce.Do(func() {
		logger.Infof("vkcalls: session ended reason=%s", reason)
		if s.onEnded != nil {
			s.onEnded(reason)
		}
	})
}

func (s *Session) peerConnectionDead() bool {
	s.pcMu.Lock()
	defer s.pcMu.Unlock()
	if s.pc == nil {
		return true
	}
	switch s.pc.ConnectionState() {
	case webrtc.PeerConnectionStateFailed, webrtc.PeerConnectionStateClosed:
		return true
	default:
		return false
	}
}

func (s *Session) tearDownPeerConnection() {
	s.pcMu.Lock()
	old := s.pc
	s.pc = nil
	s.pcMu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

// handlePeerMediaLost clears the dead PeerConnection and waits for the remote
// to rejoin (participant-joined → rearmDirect). Ends the session if nobody
// returns within connectPeerTimeout so the agent auto-restart can rejoin.
func (s *Session) handlePeerMediaLost(reason string) {
	if s.closed.Load() || s.rearming.Load() {
		return
	}
	if !s.awaitingRearm.CompareAndSwap(false, true) {
		return
	}
	logger.Infof("vkcalls: peer media lost (%s) — reset PC, wait for participant-joined", reason)
	s.tearDownPeerConnection()
	s.answeredRemote.Store(false)
	s.remoteParticipantID = 0
	go s.waitRearmOrEnd()
}

func (s *Session) waitRearmOrEnd() {
	timer := time.NewTimer(connectPeerTimeout)
	defer timer.Stop()
	for {
		if s.closed.Load() {
			return
		}
		if !s.awaitingRearm.Load() {
			return
		}
		if !s.peerConnectionDead() {
			s.awaitingRearm.Store(false)
			return
		}
		select {
		case <-timer.C:
			if s.closed.Load() {
				return
			}
			if s.awaitingRearm.Load() && s.peerConnectionDead() {
				s.signalEnded("await-rearm-timeout")
			}
			return
		case <-s.closeCh:
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// noteRemoteParticipant records a remote peer id from signaling. When media
// already ran and the PC is dead, starts a fresh DIRECT offer/answer cycle.
func (s *Session) noteRemoteParticipant(id int64, source string) {
	if id == 0 {
		return
	}
	self := s.selfParticipantID()
	if self != 0 && id == self {
		return
	}
	dead := s.peerConnectionDead()
	if !dead && s.remoteParticipantID != 0 && s.remoteParticipantID != id {
		return
	}
	if !dead && s.remoteParticipantID == id {
		return
	}
	logger.Infof("vkcalls: remote participant from %s id=%d (pcDead=%v mediaReady=%v)",
		source, id, dead, s.mediaEverReady.Load())
	s.remoteParticipantID = id
	select {
	case s.acceptPeers <- []int64{id}:
	default:
	}
	if dead && s.mediaEverReady.Load() {
		go s.rearmDirect(id)
	}
}

// rearmDirect rebuilds the PeerConnection and re-runs DIRECT signaling for a
// remote that rejoined after hungup / PC close.
func (s *Session) rearmDirect(remoteID int64) {
	if s.closed.Load() {
		return
	}
	if !s.rearming.CompareAndSwap(false, true) {
		return
	}
	defer s.rearming.Store(false)

	logger.Infof("vkcalls: rearm DIRECT remote=%d", remoteID)
	s.tearDownPeerConnection()
	s.answeredRemote.Store(false)
	s.remoteParticipantID = remoteID
	s.directMode.Store(true)

	if err := s.setupPeerConnection(); err != nil {
		logger.Infof("vkcalls: rearm setup PC failed: %v", err)
		s.signalEnded("rearm-pc-failed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectMediaTimeout+5*time.Second)
	defer cancel()
	if err := s.connectDirect(ctx, remoteID); err != nil {
		logger.Infof("vkcalls: rearm connectDirect failed: %v", err)
		s.signalEnded("rearm-offer-failed")
		return
	}
	if err := s.waitPCConnected(ctx); err != nil {
		logger.Infof("vkcalls: rearm wait connected failed: %v", err)
		s.signalEnded("rearm-media-timeout")
		return
	}
	logger.Infof("vkcalls: rearm media ready remote=%d", remoteID)
	s.awaitingRearm.Store(false)
	if s.onReconnect != nil {
		s.onReconnect(nil)
	}
}

func (s *Session) waitPCConnected(ctx context.Context) error {
	for {
		s.pcMu.Lock()
		pc := s.pc
		s.pcMu.Unlock()
		if pc != nil && pc.ConnectionState() == webrtc.PeerConnectionStateConnected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %v", ErrMediaTimeout, ctx.Err())
		case <-s.closeCh:
			return ErrSessionClosed
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *Session) markTopologySERVER() {
	s.topologyOnce.Do(func() { close(s.topologySERVER) })
}

func (s *Session) switchTopologySERVER() error {
	return s.writeJSON(map[string]any{
		"command":  "switch-topology",
		"sequence": s.nextSeq(),
		"topology": "SERVER",
		"force":    true,
	})
}

func (s *Session) waitTopologySERVER(timeout time.Duration) bool {
	select {
	case <-s.topologySERVER:
		return true
	case <-time.After(timeout):
		return false
	case <-s.closeCh:
		return false
	}
}

// Send is unsupported in v1 (no stable byte stream).
func (s *Session) Send([]byte) error { return ErrByteStreamUnsupported }

// Close tears down signaling and media. Best-effort hangup so the remote
// leaves the DIRECT room instead of lingering as a zombie participant.
func (s *Session) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.closeCh)
	s.wsMu.Lock()
	if s.ws != nil {
		_ = s.ws.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = s.ws.WriteJSON(map[string]any{
			"command":  "hangup",
			"sequence": s.nextSeq(),
			"reason":   "HUNGUP",
		})
		_ = s.ws.SetWriteDeadline(time.Time{})
		_ = s.ws.Close()
		s.ws = nil
	}
	s.wsMu.Unlock()
	s.tearDownPeerConnection()
	s.wg.Wait()
	s.signalEnded("closed")
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
		s.signalEnded(reason)
		return
	}
	if s.refresh == nil {
		// No refresh hook: end so the agent/client can restart the shard.
		s.signalEnded(reason)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		creds, err := s.refresh(ctx)
		if err != nil {
			logger.Infof("vkcalls refresh failed: %v", err)
			s.signalEnded("refresh-failed")
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
		s.topologySERVER = make(chan struct{})
		s.topologyOnce = sync.Once{}
		s.acceptPeers = make(chan []int64, 1)
		s.answeredRemote.Store(false)
		s.directMode.Store(false)
		s.mediaEverReady.Store(false)
		s.rearming.Store(false)
		s.awaitingRearm.Store(false)
		s.remoteParticipantID = 0
		s.endedOnce = sync.Once{}
		s.closed.Store(false)
		if err := s.Connect(ctx); err != nil {
			logger.Infof("vkcalls reconnect failed: %v", err)
			s.signalEnded("reconnect-failed")
			return
		}
		if s.onReconnect != nil {
			s.onReconnect(nil)
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
	pending := s.pendingRemote
	s.pendingRemote = nil
	s.videoTrackMu.Unlock()
	for _, p := range pending {
		logger.Infof("vkcalls: delivering queued remote track id=%s", p.track.ID())
		cb(p.track, p.receiver)
	}
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
	// UDP for host/srflx + TCP so turns:/turn?transport=tcp can gather when
	// LTE UDP to VK TURN is blocked.
	settingEngine.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeTCP4,
	})
	// mDNS hostnames are useless across the internet and fail on iOS NE
	// ("no usable interfaces"); disable so gathering focuses on host/srflx/relay.
	settingEngine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	// LTE NAT bindings die quietly; give ICE longer before Failed.
	settingEngine.SetICETimeouts(30*time.Second, 60*time.Second, 2*time.Second)
	// After SDP renegotiation VK may deliver RTCP before the new track is
	// bound; without this OnTrack never fires and vp8channel starves.
	settingEngine.SetFireOnTrackBeforeFirstRTP(true)
	settingEngine.SetHandleUndeclaredSSRCWithoutAnswer(true)
	// Allow RFC1918/CGNAT interfaces so STUN/TURN can gather from them (mobile
	// LTE/Wi‑Fi only has private addresses). Still drop loopback/link-local and
	// Cockney wg-mgmt (10.254.0.0/16), which has no UDP egress on NL agents —
	// binding STUN there used to stall ICE forever.
	settingEngine.SetIPFilter(func(ip net.IP) bool {
		ip4 := ip.To4()
		if ip4 == nil {
			return false
		}
		if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || ip4.IsUnspecified() {
			return false
		}
		// 10.254.0.0/16 — Cockney wireguard management iface on NL.
		if ip4[0] == 10 && ip4[1] == 254 {
			return false
		}
		return true
	})

	mediaEngine := &webrtc.MediaEngine{}
	// VK Calls rejects oversized default-codec SDPs over transmit-data
	// ("invalid-request"). Keep the offer small: VP8 + Opus only.
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000},
		PayloadType:        96,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, fmt.Errorf("register vp8: %w", err)
	}
	if err := mediaEngine.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2},
		PayloadType:        111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, fmt.Errorf("register opus: %w", err)
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
		urls := filterVKICEURLs(iceBlk.URLs)
		if len(urls) == 0 {
			continue
		}
		out = append(out, webrtc.ICEServer{
			URLs:       urls,
			Username:   iceBlk.Username,
			Credential: iceBlk.Credential,
		})
	}
	return out
}

// filterVKICEURLs drops turns: (TLS) URLs. VK TURN often serves short-lived
// TLS certs that are already expired at join time ("certificate has expired"),
// which leaves mobile on fragile srflx-only paths that die after ~15s NAT.
// Prefer plain turn:/stun: UDP (and turn?transport=tcp when TCP4 is enabled).
func filterVKICEURLs(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		lower := strings.ToLower(strings.TrimSpace(u))
		if strings.HasPrefix(lower, "turns:") {
			continue
		}
		out = append(out, u)
	}
	return out
}
