package vkcalls

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
)

func withCallsAPIServer(t *testing.T, h http.Handler) {
	t.Helper()
	old := callsAPIURL
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		callsAPIURL = old
		srv.Close()
	})
	callsAPIURL = srv.URL
}

func TestParseJoinLink(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://vk.com/call/join/abc-123", "abc-123"},
		{"https://vk.ru/call/join/xyz", "xyz"},
		{"/call/join/rawid", "rawid"},
		{"rawid", "rawid"},
		{"  rawid  ", "rawid"},
	}
	for _, tc := range cases {
		got, err := ParseJoinLink(tc.in)
		if err != nil {
			t.Fatalf("ParseJoinLink(%q) err=%v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseJoinLink(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	if _, err := ParseJoinLink(""); !errors.Is(err, errJoinLinkRequired) {
		t.Fatalf("empty: %v", err)
	}
}

func TestIssueWithPreissuedToken(t *testing.T) {
	var sawJoinAnonymToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("method") {
		case "auth.anonymLogin":
			_ = json.NewEncoder(w).Encode(loginResponse{
				UID:            "uid-1",
				SessionKey:     "sess-1",
				ExternalUserID: "ext-1",
			})
		case "vchat.joinConversationByLink":
			sawJoinAnonymToken = r.Form.Get("anonymToken")
			_ = json.NewEncoder(w).Encode(JoinResponse{
				ID:       "conv-1",
				Endpoint: "wss://sig.example/ws?token=abc",
				Token:    "sig-token",
				PeerID:   42,
				TurnServer: &IceServer{
					URLs:       []string{"turn:turn.example:3478"},
					Username:   "u",
					Credential: "p",
				},
				StunServer: &IceServer{URLs: []string{"stun:stun.example:3478"}},
			})
		default:
			t.Fatalf("unexpected method %q", r.Form.Get("method"))
		}
	})
	withCallsAPIServer(t, mux)

	creds, err := (Provider{}).Issue(context.Background(), auth.Config{
		RoomURL: "https://vk.com/call/join/room-99",
		Name:    "peer",
		Token:   "preissued-anonym",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sawJoinAnonymToken != "preissued-anonym" {
		t.Fatalf("anonymToken=%q", sawJoinAnonymToken)
	}
	if creds.URL != "wss://sig.example/ws?token=abc" || creds.Token != "sig-token" {
		t.Fatalf("creds=%+v", creds)
	}
	if creds.Extra["conversationId"] != "conv-1" || creds.Extra["joinLink"] != "room-99" {
		t.Fatalf("extra=%v", creds.Extra)
	}
	if !strings.Contains(creds.Extra["turn_server"], "turn:turn.example") {
		t.Fatalf("turn_server=%q", creds.Extra["turn_server"])
	}
}

func TestIssueWithSessionKey(t *testing.T) {
	var sawAnonymToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("method") {
		case "auth.anonymLogin":
			t.Fatal("authorized session_key path must not call anonymLogin")
		case "vchat.joinConversationByLink":
			sawAnonymToken = r.Form.Get("anonymToken")
			if r.Form.Get("session_key") != "-w-preissued-session" {
				t.Fatalf("session_key=%q", r.Form.Get("session_key"))
			}
			_ = json.NewEncoder(w).Encode(JoinResponse{
				ID:       "5deca2ec-5d49-4124-bc51-52ea98ab85ea",
				Endpoint: "wss://videowebrtc.okcdn.ru/ws2?userId=587&entityType=USER&conversationId=5deca2ec-5d49-4124-bc51-52ea98ab85ea&token=sig&peerId=99",
				Token:    "sig",
				ClientType: "VK",
				TurnServer: &IceServer{URLs: []string{"turn:193.203.43.12:19302"}, Username: "u", Credential: "p"},
			})
		default:
			t.Fatalf("unexpected method %q", r.Form.Get("method"))
		}
	})
	withCallsAPIServer(t, mux)

	creds, err := (Provider{}).Issue(context.Background(), auth.Config{
		RoomURL: "https://vk.ru/call/join/uHN9M6IvIY6dnv-OfpQGRY6yzsohzKWRDI0KCLvkAi0",
		Token:   "-w-preissued-session",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if sawAnonymToken != "" {
		t.Fatalf("anonymToken should be omitted, got %q", sawAnonymToken)
	}
	if creds.Extra["peerId"] != "99" || creds.Extra["clientType"] != "VK" {
		t.Fatalf("extra=%v", creds.Extra)
	}
	if creds.Extra["joinLink"] != "uHN9M6IvIY6dnv-OfpQGRY6yzsohzKWRDI0KCLvkAi0" {
		t.Fatalf("joinLink=%q", creds.Extra["joinLink"])
	}
}

func TestIssueRequiresRoom(t *testing.T) {
	_, err := (Provider{}).Issue(context.Background(), auth.Config{})
	if !errors.Is(err, auth.ErrRoomIDRequired) {
		t.Fatalf("err=%v", err)
	}
}

func TestAPIErrorSurfaced(t *testing.T) {
	withCallsAPIServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(apiError{ErrorCode: 100, ErrorMsg: "bad"})
	}))
	_, err := anonymLogin(context.Background())
	if err == nil || !errors.Is(err, errAPI) {
		t.Fatalf("err=%v", err)
	}
}
