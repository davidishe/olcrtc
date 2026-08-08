package vkcalls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
	"github.com/pion/webrtc/v4"
)

type connectionHello struct {
	Conversation struct {
		ID           string `json:"id"`
		Topology     string `json:"topology"`
		Participants []struct {
			ID         int64 `json:"id"`
			ExternalID struct {
				ID string `json:"id"`
			} `json:"externalId"`
		} `json:"participants"`
	} `json:"conversation"`
	PeerID struct {
		ID int64 `json:"id"`
	} `json:"peerId"`
}

type signalingNotification struct {
	Type         string          `json:"type"`
	Notification string          `json:"notification"`
	Data         json.RawMessage `json:"data"`
}

type consumerAnsweredData struct {
	Description string `json:"description"`
	SessionID   string `json:"sessionId"`
}

type producerUpdatedData struct {
	Description string `json:"description"`
	SessionID   string `json:"sessionId"`
}

func (s *Session) dialSignaling(ctx context.Context) error {
	u, err := buildSignalingURL(s.endpoint, s.signalingToken, s.uid, s.conversationID, s.extra["clientType"])
	if err != nil {
		return err
	}
	dialer := protect.NewWebSocketDialer(wsHandshakeTimeout)
	header := map[string][]string{
		"Origin": {defaultOriginHeader},
	}
	ws, resp, err := dialer.DialContext(ctx, u, header)
	if err != nil {
		return fmt.Errorf("dial signaling: %w", err)
	}
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	s.wsMu.Lock()
	s.ws = ws
	s.wsMu.Unlock()
	_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
	return nil
}

const defaultOriginHeader = "https://vk.ru"

func buildSignalingURL(endpoint, token, userID, conversationID, clientType string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse endpoint: %w", err)
	}
	q := u.Query()
	if q.Get("platform") == "" {
		q.Set("platform", platformWEB)
	}
	if q.Get("appVersion") == "" {
		q.Set("appVersion", appVersion)
	}
	if q.Get("version") == "" {
		q.Set("version", protocolVersion)
	}
	if q.Get("device") == "" {
		q.Set("device", deviceBrowser)
	}
	if q.Get("capabilities") == "" {
		q.Set("capabilities", capabilitiesFlags)
	}
	if clientType == "" {
		clientType = "VK"
	}
	if q.Get("clientType") == "" {
		q.Set("clientType", clientType)
	}
	if q.Get("tgt") == "" {
		q.Set("tgt", tgtJoin)
	}
	if userID != "" && q.Get("userId") == "" {
		q.Set("userId", userID)
	}
	if conversationID != "" && q.Get("conversationId") == "" {
		q.Set("conversationId", conversationID)
	}
	if token != "" && q.Get("token") == "" {
		q.Set("token", token)
	}
	if q.Get("entityType") == "" {
		q.Set("entityType", "USER")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Session) writeJSON(v any) error {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.ws == nil {
		return ErrSessionClosed
	}
	return s.ws.WriteJSON(v)
}

func (s *Session) sendAcceptCall() error {
	return s.writeJSON(map[string]any{
		"command":  "accept-call",
		"sequence": s.nextSeq(),
		"mediaSettings": map[string]bool{
			"isAudioEnabled":            false,
			"isVideoEnabled":            true,
			"isScreenSharingEnabled":    false,
			"isFastScreenSharingEnabled": false,
			"isAudioSharingEnabled":     false,
			"isAnimojiEnabled":          false,
		},
	})
}

func (s *Session) allocateConsumer(ctx context.Context) error {
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
		return fmt.Errorf("set local description: %w", err)
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	select {
	case <-gatherComplete:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
	}
	local := pc.LocalDescription()
	if local == nil {
		return fmt.Errorf("nil local description")
	}
	return s.writeJSON(map[string]any{
		"command":  "allocate-consumer",
		"sequence": s.nextSeq(),
		"capabilities": map[string]any{
			"sdpSemantics": "unified-plan",
		},
		"description": local.SDP,
	})
}

func (s *Session) waitConnectionHello(ctx context.Context, timeout time.Duration) (*connectionHello, error) {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for connection hello")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.closeCh:
			return nil, ErrSessionClosed
		default:
		}
		s.wsMu.Lock()
		ws := s.ws
		s.wsMu.Unlock()
		if ws == nil {
			return nil, ErrSessionClosed
		}
		_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				continue
			}
			return nil, fmt.Errorf("read hello: %w", err)
		}
		if string(msg) == "ping" {
			_ = s.writePong()
			continue
		}
		var hello connectionHello
		if err := json.Unmarshal(msg, &hello); err != nil {
			continue
		}
		if hello.Conversation.ID != "" || len(hello.Conversation.Participants) > 0 || hello.PeerID.ID != 0 {
			if hello.PeerID.ID != 0 {
				s.peerID = hello.PeerID.ID
			}
			if hello.Conversation.ID != "" {
				s.conversationID = hello.Conversation.ID
			}
			return &hello, nil
		}
	}
}

func (s *Session) writePong() error {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.ws == nil {
		return ErrSessionClosed
	}
	return s.ws.WriteMessage(websocketTextMessage, []byte("pong"))
}

// websocketTextMessage mirrors gorilla's TextMessage without importing the
// constant name clash in tests that stub the dialer.
const websocketTextMessage = 1

func (s *Session) readLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}
		s.wsMu.Lock()
		ws := s.ws
		s.wsMu.Unlock()
		if ws == nil {
			return
		}
		_ = ws.SetReadDeadline(time.Now().Add(wsReadTimeout))
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if !s.closed.Load() {
				logger.Infof("vkcalls signaling read ended: %v", err)
			}
			return
		}
		if string(msg) == "ping" {
			_ = s.writePong()
			continue
		}
		s.handleSignalingMessage(msg)
	}
}

func (s *Session) handleSignalingMessage(msg []byte) {
	var notif signalingNotification
	if err := json.Unmarshal(msg, &notif); err != nil {
		return
	}
	if notif.Type != "notification" {
		// Command responses may carry description for allocate-consumer.
		var resp struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			SessionID   string `json:"sessionId"`
		}
		if err := json.Unmarshal(msg, &resp); err == nil && resp.Description != "" {
			_ = s.applyRemoteSDP(resp.Description, webrtc.SDPTypeAnswer)
		}
		return
	}
	switch notif.Notification {
	case "consumer-answered":
		var data consumerAnsweredData
		if err := json.Unmarshal(notif.Data, &data); err != nil {
			return
		}
		_ = s.applyRemoteSDP(data.Description, webrtc.SDPTypeAnswer)
	case "producer-updated":
		var data producerUpdatedData
		if err := json.Unmarshal(notif.Data, &data); err != nil {
			return
		}
		if err := s.applyRemoteSDP(data.Description, webrtc.SDPTypeOffer); err != nil {
			logger.Infof("vkcalls apply producer offer: %v", err)
			return
		}
		_ = s.sendAcceptProducer(data.SessionID)
	case "transmitted-data":
		s.handleTransmittedData(notif.Data)
	}
}

func (s *Session) handleTransmittedData(raw json.RawMessage) {
	var envelope struct {
		Candidate *webrtc.ICECandidateInit `json:"candidate"`
		SDP       string                   `json:"sdp"`
	}
	// Data may be nested or a raw object.
	if err := json.Unmarshal(raw, &envelope); err != nil {
		var wrapped struct {
			Data json.RawMessage `json:"data"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 == nil {
			_ = json.Unmarshal(wrapped.Data, &envelope)
		}
	}
	if envelope.Candidate != nil {
		s.pcMu.Lock()
		pc := s.pc
		s.pcMu.Unlock()
		if pc != nil {
			_ = pc.AddICECandidate(*envelope.Candidate)
		}
	}
}

func (s *Session) applyRemoteSDP(sdp string, typ webrtc.SDPType) error {
	if strings.TrimSpace(sdp) == "" {
		return nil
	}
	s.pcMu.Lock()
	defer s.pcMu.Unlock()
	if s.pc == nil {
		return ErrSessionClosed
	}
	desc := webrtc.SessionDescription{Type: typ, SDP: sdp}
	if err := s.pc.SetRemoteDescription(desc); err != nil {
		return fmt.Errorf("set remote description (%s): %w", typ.String(), err)
	}
	if typ == webrtc.SDPTypeOffer {
		answer, err := s.pc.CreateAnswer(nil)
		if err != nil {
			return fmt.Errorf("create answer: %w", err)
		}
		if err := s.pc.SetLocalDescription(answer); err != nil {
			return fmt.Errorf("set local answer: %w", err)
		}
	}
	return nil
}

func (s *Session) sendAcceptProducer(sessionID string) error {
	s.pcMu.Lock()
	local := s.pc.LocalDescription()
	s.pcMu.Unlock()
	if local == nil {
		return fmt.Errorf("no local description for accept-producer")
	}
	payload := map[string]any{
		"command":     "accept-producer",
		"sequence":    s.nextSeq(),
		"description": local.SDP,
	}
	if sessionID != "" {
		payload["sessionId"] = sessionID
	}
	return s.writeJSON(payload)
}

func (s *Session) setupPeerConnection() error {
	api, err := newWebRTCAPI()
	if err != nil {
		return err
	}
	cfg := webrtc.Configuration{
		ICEServers:   s.iceServers,
		SDPSemantics: webrtc.SDPSemanticsUnifiedPlan,
	}
	pc, err := api.NewPeerConnection(cfg)
	if err != nil {
		return fmt.Errorf("new peer connection: %w", err)
	}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logger.Infof("vkcalls pc state: %s", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			s.markMediaReady()
		}
	})
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		if track.Kind() != webrtc.RTPCodecTypeVideo {
			return
		}
		s.videoTrackMu.RLock()
		cb := s.onVideoTrack
		s.videoTrackMu.RUnlock()
		if cb != nil {
			cb(track, receiver)
		}
		s.markMediaReady()
		go func() {
			buf := make([]byte, 1500)
			for {
				if _, _, err := receiver.Read(buf); err != nil {
					return
				}
			}
		}()
	})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil || s.peerID == 0 {
			return
		}
		init := c.ToJSON()
		_ = s.writeJSON(map[string]any{
			"command":         "transmit-data",
			"sequence":        s.nextSeq(),
			"participantId":   s.peerID,
			"participantType": "USER",
			"data":            map[string]any{"candidate": init},
		})
	})

	s.videoTrackMu.RLock()
	tracks := append([]webrtc.TrackLocal(nil), s.videoTracks...)
	s.videoTrackMu.RUnlock()
	for _, track := range tracks {
		if _, err := pc.AddTrack(track); err != nil {
			_ = pc.Close()
			return fmt.Errorf("add pending track: %w", err)
		}
	}

	s.pcMu.Lock()
	s.pc = pc
	s.pcMu.Unlock()
	return nil
}
