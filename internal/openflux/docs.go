// SPDX-License-Identifier: WTFPL

package openflux

// ai-generated: Yandex Docs editor bootstrap (client-config parsing).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

// wsVersionPath is the OnlyOffice build segment upstream OpenFlux dials.
// If Yandex rolls the editor forward the dial fails with 404.
const wsVersionPath = "2024.1.1-375"

var (
	errNoClientConfig = errors.New("client-config not found")
	errConfigField    = errors.New("client-config field missing")
	errTooManyRedirs  = errors.New("stopped after 10 redirects")
)

var clientConfigRe = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`) //nolint:gochecknoglobals // compiled once

type docInfo struct {
	cookie  string
	token   string
	docID   string
	origin  string
	host    string
	wsURL   string
	perms   map[string]any
	openCmd map[string]any
}

func fetchDocInfo(ctx context.Context, docURL, userID string) (docInfo, error) {
	client := &http.Client{
		Transport: protect.NewHTTPTransport(),
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errTooManyRedirs
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return docInfo{}, fmt.Errorf("build request: %w", err)
	}
	// Without a browser UA Yandex answers with showcaptcha.
	req.Header.Set("User-Agent", "Mozilla/5.0")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return docInfo{}, fmt.Errorf("get doc: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return docInfo{}, fmt.Errorf("read doc: %w", err)
	}
	final := resp.Request.URL
	logf("openflux: doc fetch status=%d final=%s%s body=%dB took=%dms", resp.StatusCode, final.Host,
		shortPath(final.Path), len(body), time.Since(started).Milliseconds())

	m := clientConfigRe.FindSubmatch(body)
	if len(m) < 2 {
		hint := "no script"
		switch {
		case strings.Contains(final.Path, "showcaptcha"):
			hint = "captcha"
		case strings.Contains(string(body), "passport"):
			hint = "login page"
		}
		return docInfo{}, fmt.Errorf("%w: %s", errNoClientConfig, hint)
	}

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	info, err := parseClientConfig(m[1], userID)
	if err != nil {
		return docInfo{}, err
	}
	info.cookie = strings.Join(cookies, "; ")
	return info, nil
}

func shortPath(p string) string {
	if len(p) > 12 {
		return p[:12] + "..."
	}
	return p
}

func parseClientConfig(raw []byte, userID string) (docInfo, error) {
	var cfg struct {
		OfficeActionData struct {
			BalancerURL  string `json:"balancer_url"`
			EditorConfig struct {
				Token    string `json:"token"`
				Document struct {
					Key         string         `json:"key"`
					FileType    any            `json:"fileType"`
					URL         any            `json:"url"`
					Title       any            `json:"title"`
					Permissions map[string]any `json:"permissions"`
				} `json:"document"`
			} `json:"editor_config"`
		} `json:"officeActionData"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return docInfo{}, fmt.Errorf("parse client-config: %w", err)
	}
	oad := cfg.OfficeActionData
	doc := oad.EditorConfig.Document
	switch {
	case oad.BalancerURL == "":
		return docInfo{}, fmt.Errorf("%w: balancer_url", errConfigField)
	case oad.EditorConfig.Token == "":
		return docInfo{}, fmt.Errorf("%w: token", errConfigField)
	case doc.Key == "":
		return docInfo{}, fmt.Errorf("%w: document.key", errConfigField)
	}
	perms := doc.Permissions
	if perms == nil {
		perms = map[string]any{}
	}
	host := strings.TrimPrefix(oad.BalancerURL, "https://")
	return docInfo{
		token:  oad.EditorConfig.Token,
		docID:  doc.Key,
		origin: oad.BalancerURL,
		host:   host,
		wsURL:  fmt.Sprintf("wss://%s/%s/doc/%s/c/?EIO=4&transport=websocket", host, wsVersionPath, doc.Key),
		perms:  perms,
		openCmd: map[string]any{
			"c": "open", "id": doc.Key, "userid": userID, "format": doc.FileType,
			"url": doc.URL, "title": doc.Title, "lcid": 25,
		},
	}, nil
}

func authMessages(info docInfo, userID string) ([]string, error) {
	auth := map[string]any{
		"type": "auth", "docid": info.docID, "token": "fghhfgsjdgfjs",
		"user": map[string]any{"id": userID}, "editorType": 0,
		"lastOtherSaveTime": -1, "permissions": info.perms,
		"openCmd": info.openCmd, "coEditingMode": "fast", "jwtOpen": info.token,
	}
	part, err := json.Marshal([]any{"message", auth})
	if err != nil {
		return nil, fmt.Errorf("marshal auth: %w", err)
	}
	return []string{fmt.Sprintf(`40{"token":%q}`, info.token), "42" + string(part)}, nil
}
