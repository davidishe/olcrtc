package subscription

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Document is the Cockney subscription endpoint response (version 1).
type Document struct {
	Version                 int             `json:"version"`
	Device                  DeviceInfo      `json:"device"`
	AccessToken             string          `json:"accessToken"`
	AccessTokenExpiresAtUtc string          `json:"accessTokenExpiresAtUtc"`
	RefreshAfterSeconds     int             `json:"refreshAfterSeconds"`
	Profile                 Profile         `json:"profile"`
}

type DeviceInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	TokenVersion int    `json:"tokenVersion"`
}

type Profile struct {
	Provider  string  `json:"provider"`
	Transport string  `json:"transport"`
	RoomID    string  `json:"roomId"`
	ChannelID *string `json:"channelId"`
	CryptoKey string  `json:"cryptoKey"`
	DNS       string  `json:"dns"`
	SocksHost string  `json:"socksHost"`
	SocksPort int     `json:"socksPort"`
}

// Fetch retrieves a subscription document. Never logs the URL (contains secret token).
func Fetch(ctx context.Context, client *http.Client, subscriptionURL string) (Document, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, nil)
	if err != nil {
		return Document{}, fmt.Errorf("subscription request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Document{}, fmt.Errorf("subscription fetch: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Document{}, fmt.Errorf("subscription read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Document{}, fmt.Errorf("subscription status %d", resp.StatusCode)
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return Document{}, fmt.Errorf("subscription decode: %w", err)
	}
	return doc, nil
}

// ParseRefreshInterval parses cockney.refresh_interval (default 10m).
func ParseRefreshInterval(s string) time.Duration {
	if s == "" {
		return 10 * time.Minute
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 10 * time.Minute
	}
	return d
}
