package vkcalls

import (
	"net/url"
	"testing"
)

func TestBuildSignalingURL(t *testing.T) {
	got, err := buildSignalingURL("wss://sig.example/ws", "tok", "uid-1", "conv-1", "VK")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("tgt") != "join" || q.Get("token") != "tok" || q.Get("userId") != "uid-1" {
		t.Fatalf("query=%v", q)
	}
	if q.Get("platform") != "WEB" || q.Get("capabilities") != "2F7F" || q.Get("clientType") != "VK" {
		t.Fatalf("platform/caps=%v", q)
	}
}

func TestBuildSignalingURLPreservesEndpointQuery(t *testing.T) {
	in := "wss://videowebrtc.okcdn.ru/ws2?userId=1&entityType=USER&conversationId=c1&token=t1&peerId=9"
	got, err := buildSignalingURL(in, "ignored", "", "", "VK")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("token") != "t1" || q.Get("peerId") != "9" || q.Get("tgt") != "join" {
		t.Fatalf("query=%v", q)
	}
}

func TestParseICEFromExtra(t *testing.T) {
	servers := parseICEFromExtra(map[string]string{
		"stun_server": `{"urls":["stun:stun.example:3478"]}`,
		"turn_server": `{"urls":["turn:turn.example:3478"],"username":"u","credential":"p"}`,
	})
	if len(servers) != 2 {
		t.Fatalf("len=%d", len(servers))
	}
	if servers[1].Username != "u" || servers[1].Credential != "p" {
		t.Fatalf("%+v", servers[1])
	}
}

func TestPeerConnectionDeadNil(t *testing.T) {
	s := &Session{}
	if !s.peerConnectionDead() {
		t.Fatal("nil PC should be dead")
	}
}

func TestNoteRemoteParticipantIgnoresSelf(t *testing.T) {
	s := &Session{
		uid:         "42",
		acceptPeers: make(chan []int64, 1),
	}
	s.noteRemoteParticipant(42, "test")
	if s.remoteParticipantID != 0 {
		t.Fatalf("self id recorded: %d", s.remoteParticipantID)
	}
}

func TestNoteRemoteParticipantSetsWhileWaiting(t *testing.T) {
	s := &Session{
		uid:         "1",
		acceptPeers: make(chan []int64, 1),
	}
	// PC nil → dead, but media never ready → only record id (Connect wait path).
	s.noteRemoteParticipant(99, "participant-joined")
	if s.remoteParticipantID != 99 {
		t.Fatalf("remote=%d", s.remoteParticipantID)
	}
	select {
	case ids := <-s.acceptPeers:
		if len(ids) != 1 || ids[0] != 99 {
			t.Fatalf("acceptPeers=%v", ids)
		}
	default:
		t.Fatal("expected acceptPeers push")
	}
}

func TestPreferDirectOfferFromExtra(t *testing.T) {
	offer := &Session{extra: map[string]string{"directRole": "offer"}}
	if !offer.preferDirectOffer() {
		t.Fatal("offer role")
	}
	answer := &Session{extra: map[string]string{"directRole": "answer"}}
	if answer.preferDirectOffer() {
		t.Fatal("answer role")
	}
}
