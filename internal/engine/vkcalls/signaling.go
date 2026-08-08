package vkcalls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
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
	_ = ctx
	// SDK ServerTransport._allocateConsumer sends capabilities only — the SFU
	// answers with producer-updated (remote offer). Sending a local offer here
	// leaves the PC stuck in have-local-offer and ICE never connects.
	return s.writeJSON(map[string]any{
		"command":  "allocate-consumer",
		"sequence": s.nextSeq(),
		"capabilities": map[string]any{
			"estimatedPerformanceIndex":               10,
			"audioMix":                                true,
			"consumerUpdate":                          true,
			"producerNotificationDataChannelVersion":  8,
			"producerCommandDataChannelVersion":       3,
			"consumerScreenDataChannelVersion":        1,
			"producerScreenDataChannelVersion":        1,
			"asrDataChannelVersion":                   0,
			"animojiDataChannelVersion":               1,
			"animojiBackendRender":                    true,
			"onDemandTracks":                          true,
			"unifiedPlan":                             true,
			"singleSession":                           true,
			"videoTracksCount":                        1,
			"red":                                     true,
			"audioShare":                              false,
			"fastScreenShare":                         false,
			"videoSuspend":                            false,
			"simulcast":                               false,
			"consumerFastScreenShare":                 false,
			"consumerFastScreenShareQualityOnDemand":  false,
			"transparentAudio":                        false,
		},
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
		var resp struct {
			Type            string  `json:"type"`
			Response        string  `json:"response"`
			Description     string  `json:"description"`
			SessionID       string  `json:"sessionId"`
			ParticipantIDs  []int64 `json:"participantIds"`
			Error           string  `json:"error"`
		}
		if err := json.Unmarshal(msg, &resp); err != nil {
			return
		}
		if resp.Type == "error" && resp.Error != "" {
			var full struct {
				Message string `json:"message"`
				Error   string `json:"error"`
			}
			_ = json.Unmarshal(msg, &full)
			logger.Infof("vkcalls signaling error: %s (%s)", full.Error, full.Message)
			return
		}
		if resp.Response == "accept-call" {
			select {
			case s.acceptPeers <- resp.ParticipantIDs:
			default:
			}
			return
		}
		if resp.Description != "" {
			_ = s.applyRemoteSDP(resp.Description, webrtc.SDPTypeAnswer)
		}
		return
	}
	switch notif.Notification {
	case "consumer-answered":
		// SDK puts description on the notification object itself (not data{}).
		var data consumerAnsweredData
		if err := json.Unmarshal(msg, &data); err != nil || data.Description == "" {
			_ = json.Unmarshal(notif.Data, &data)
		}
		if data.Description == "" {
			logger.Infof("vkcalls: consumer-answered without description")
			return
		}
		if err := s.applyRemoteSDP(data.Description, webrtc.SDPTypeAnswer); err != nil {
			logger.Infof("vkcalls apply consumer answer: %v", err)
		}
	case "producer-updated":
		var data producerUpdatedData
		if err := json.Unmarshal(msg, &data); err != nil || data.Description == "" {
			_ = json.Unmarshal(notif.Data, &data)
		}
		if data.Description == "" {
			logger.Infof("vkcalls: producer-updated without description")
			return
		}
		logger.Infof("vkcalls: producer-updated sessionId=%s sdp_len=%d", data.SessionID, len(data.Description))
		if err := s.applyRemoteSDP(data.Description, webrtc.SDPTypeOffer); err != nil {
			logger.Infof("vkcalls apply producer offer: %v", err)
			return
		}
		if err := s.sendAcceptProducer(data.SessionID); err != nil {
			logger.Infof("vkcalls accept-producer: %v", err)
		}
	case "topology-changed":
		var body struct {
			Topology string `json:"topology"`
		}
		_ = json.Unmarshal(msg, &body)
		logger.Infof("vkcalls: topology-changed %s", body.Topology)
		if strings.EqualFold(body.Topology, "SERVER") {
			s.markTopologySERVER()
		}
	case "transmitted-data":
		// Prefer nested data; also accept top-level candidate/sdp.
		if len(notif.Data) > 0 {
			s.handleTransmittedData(notif.Data)
		}
		var top struct {
			Candidate *webrtc.ICECandidateInit `json:"candidate"`
			SDP       json.RawMessage          `json:"sdp"`
			Data      json.RawMessage          `json:"data"`
			ParticipantID int64                `json:"participantId"`
		}
		if err := json.Unmarshal(msg, &top); err == nil {
			if len(top.Data) > 0 {
				s.handleTransmittedData(top.Data)
			} else {
				raw, _ := json.Marshal(top)
				s.handleTransmittedData(raw)
			}
			if top.ParticipantID != 0 && s.remoteParticipantID == 0 {
				s.remoteParticipantID = top.ParticipantID
			}
		}
	}
}

func (s *Session) handleTransmittedData(raw json.RawMessage) {
	var envelope struct {
		Candidate *webrtc.ICECandidateInit `json:"candidate"`
		SDP       json.RawMessage          `json:"sdp"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		var wrapped struct {
			Data json.RawMessage `json:"data"`
		}
		if err2 := json.Unmarshal(raw, &wrapped); err2 == nil {
			_ = json.Unmarshal(wrapped.Data, &envelope)
		}
	}
	if len(envelope.SDP) > 0 {
		s.handleRemoteSDPPayload(envelope.SDP)
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

func (s *Session) handleRemoteSDPPayload(raw json.RawMessage) {
	// SDK sends RTCSessionDescriptionInit as object {type,sdp} or sometimes a bare string.
	var obj struct {
		Type string `json:"type"`
		SDP  string `json:"sdp"`
	}
	sdp := ""
	typ := webrtc.SDPTypeAnswer
	if err := json.Unmarshal(raw, &obj); err == nil && obj.SDP != "" {
		sdp = obj.SDP
		switch strings.ToLower(obj.Type) {
		case "offer":
			typ = webrtc.SDPTypeOffer
		case "answer", "pranswer":
			typ = webrtc.SDPTypeAnswer
		}
	} else {
		_ = json.Unmarshal(raw, &sdp)
	}
	if strings.TrimSpace(sdp) == "" {
		return
	}
	logger.Infof("vkcalls: remote SDP type=%s len=%d", typ.String(), len(sdp))
	if err := s.applyRemoteSDP(sdp, typ); err != nil {
		logger.Infof("vkcalls apply remote sdp: %v", err)
		return
	}
	if typ == webrtc.SDPTypeOffer && s.directMode.Load() {
		s.pcMu.Lock()
		local := s.pc.LocalDescription()
		s.pcMu.Unlock()
		if local != nil {
			_ = s.sendSDP(*local)
		}
	}
}

func (s *Session) sendSDP(desc webrtc.SessionDescription) error {
	if s.remoteParticipantID == 0 {
		return fmt.Errorf("no remote participant for sendSdp")
	}
	return s.writeJSON(map[string]any{
		"command":         "transmit-data",
		"sequence":        s.nextSeq(),
		"participantId":   s.remoteParticipantID,
		"participantType": "USER",
		"data": map[string]any{
			"sdp": map[string]string{
				"type": desc.Type.String(),
				"sdp":  desc.SDP,
			},
		},
	})
}

// composeParticipantID is kept for tests/docs; wire protocol uses numeric
// participantId + participantType (SDK decomposes "u"+id before send).
func composeParticipantID(id int64, idType string, deviceIdx int) string {
	prefix := "u"
	if strings.EqualFold(idType, "GROUP") {
		prefix = "g"
	}
	out := prefix + strconv.FormatInt(id, 10)
	if deviceIdx != 0 {
		out += ":d" + strconv.Itoa(deviceIdx)
	}
	return out
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
	// Ignore duplicate answers once signaling is already stable.
	if typ == webrtc.SDPTypeAnswer && s.pc.SignalingState() == webrtc.SignalingStateStable {
		return nil
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
	pc := s.pc
	s.pcMu.Unlock()
	if pc == nil {
		return fmt.Errorf("no peer connection for accept-producer")
	}
	// Prefer complete local SDP (host + srflx) so SFU can connect without
	// relying on trickle ICE, which SERVER topology may ignore.
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	select {
	case <-gatherComplete:
	case <-time.After(8 * time.Second):
	}
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
		// DIRECT: wait until local SDP is sent (remoteParticipantID set and
		// trickle after offer). Candidates before the offer are rejected.
		if c == nil || s.remoteParticipantID == 0 || !s.directMode.Load() {
			return
		}
		init := c.ToJSON()
		logger.Infof("vkcalls: trickle ICE candidate typ=%s", c.Typ.String())
		cand := map[string]any{"candidate": init.Candidate}
		if init.SDPMid != nil {
			cand["sdpMid"] = *init.SDPMid
		}
		if init.SDPMLineIndex != nil {
			cand["sdpMLineIndex"] = *init.SDPMLineIndex
		}
		_ = s.writeJSON(map[string]any{
			"command":         "transmit-data",
			"sequence":        s.nextSeq(),
			"participantId":   s.remoteParticipantID,
			"participantType": "USER",
			"data":            map[string]any{"candidate": cand},
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
	// VK DIRECT offers include audio+video (SDK offerToReceiveAudio/Video).
	// A video-only SDP is rejected as invalid-request on transmit-data.
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendrecv,
	}); err != nil {
		_ = pc.Close()
		return fmt.Errorf("add audio transceiver: %w", err)
	}

	s.pcMu.Lock()
	s.pc = pc
	s.pcMu.Unlock()
	return nil
}
