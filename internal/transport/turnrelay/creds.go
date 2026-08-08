package turnrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	"github.com/openlibrecommunity/olcrtc/internal/auth/vkcalls"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

var (
	errTurnCredsMissing = errors.New("turnrelay: turn credentials missing from carrier join")
	errTurnURLInvalid   = errors.New("turnrelay: turn url invalid")
)

type turnCredentials struct {
	Host     string
	Port     string
	Username string
	Password string
	URLs     []string
}

// issueTurnCredentials joins a VK Calls room solely to harvest TURN
// username/credential/urls. No WSS signaling or PeerConnection is started.
func issueTurnCredentials(ctx context.Context, carrier, roomURL, authToken string) (turnCredentials, error) {
	providerName := strings.TrimSpace(carrier)
	if providerName == "" {
		providerName = "vkcalls"
	}
	provider, err := auth.Get(providerName)
	if err != nil {
		// Fall back to the concrete vkcalls provider when registry is empty
		// (unit tests) or the name is explicitly vkcalls.
		if providerName == "vkcalls" {
			provider = vkcalls.Provider{}
		} else {
			return turnCredentials{}, fmt.Errorf("auth provider %q: %w", providerName, err)
		}
	}

	creds, err := provider.Issue(ctx, auth.Config{
		RoomURL: roomURL,
		Token:   authToken,
		Name:    "turnrelay",
	})
	if err != nil {
		return turnCredentials{}, fmt.Errorf("issue carrier credentials: %w", err)
	}

	raw := ""
	if creds.Extra != nil {
		raw = creds.Extra["turn_server"]
	}
	if strings.TrimSpace(raw) == "" {
		return turnCredentials{}, errTurnCredsMissing
	}

	var ice struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	}
	if err := json.Unmarshal([]byte(raw), &ice); err != nil {
		return turnCredentials{}, fmt.Errorf("decode turn_server: %w", err)
	}
	host, port, err := pickTurnHostPort(ice.URLs)
	if err != nil {
		return turnCredentials{}, err
	}
	logger.Infof("turnrelay: obtained TURN host=%s:%s user=%s urls=%d", host, port, ice.Username, len(ice.URLs))
	return turnCredentials{
		Host:     host,
		Port:     port,
		Username: ice.Username,
		Password: ice.Credential,
		URLs:     ice.URLs,
	}, nil
}

func pickTurnHostPort(urls []string) (string, string, error) {
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		// Prefer plain turn: over turns: (TLS) — UDP Allocate path.
		if strings.HasPrefix(strings.ToLower(raw), "turns:") {
			continue
		}
		host, port, err := parseTurnURL(raw)
		if err != nil {
			continue
		}
		return host, port, nil
	}
	// Fall back to turns: if that is all we have (still try UDP host:port).
	for _, raw := range urls {
		host, port, err := parseTurnURL(raw)
		if err != nil {
			continue
		}
		return host, port, nil
	}
	return "", "", errTurnURLInvalid
}

func parseTurnURL(raw string) (string, string, error) {
	// Accept "turn:host:port", "turn:host:port?transport=udp", bare "host:port".
	s := strings.TrimSpace(raw)
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "turn:"):
		s = s[len("turn:"):]
	case strings.HasPrefix(lower, "turns:"):
		s = s[len("turns:"):]
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	host, port, err := net.SplitHostPort(s)
	if err == nil {
		return host, port, nil
	}
	// host without port — default STUN/TURN 3478
	if !strings.Contains(s, ":") {
		return s, "3478", nil
	}
	// Bracketed IPv6 without port handled by SplitHostPort; try URL parse.
	u, err := url.Parse("turn://" + s)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s", errTurnURLInvalid, raw)
	}
	host = u.Hostname()
	port = u.Port()
	if port == "" {
		port = "3478"
	}
	if host == "" {
		return "", "", fmt.Errorf("%w: %s", errTurnURLInvalid, raw)
	}
	return host, port, nil
}
