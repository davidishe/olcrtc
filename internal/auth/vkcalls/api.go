// Package vkcalls is the auth provider for VK Calls (VK Звонки) over the
// shared OK Calls stack (calls.okcdn.ru). Rooms are created in the VK UI;
// this provider joins an existing call by join-link and returns signaling
// credentials for the vkcalls engine.
package vkcalls

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/openlibrecommunity/olcrtc/internal/protect"
)

const (
	defaultCallsAPIURL = "https://calls.okcdn.ru/fb.do"
	defaultAppKey      = "CGMMEJLGDIHBABABA" // VK Calls / VK Video web app key
	defaultOrigin      = "https://vk.ru"
	defaultProtocolVer = "5"
	defaultCapabilities = "2F7F"
	defaultClientType  = "SDK_JS"
	defaultClientVer   = 1.1

	// Public VK Android client used for login.vk.ru anonym tokens when
	// cfg.Token is empty. Captcha may still block getAnonymousToken.
	defaultVKClientID     = "2274003"
	defaultVKClientSecret = "hHbZxrka2uZ6jB1inYsH"
	defaultVKAPIBase      = "https://api.vk.ru"
	defaultVKLoginURL     = "https://login.vk.ru/?act=get_anonym_token"
)

var (
	errJoinLinkRequired = errors.New("vkcalls join link required")
	errJoinLinkInvalid  = errors.New("vkcalls join link invalid")
	errAPI              = errors.New("vkcalls api error")
	errCaptchaRequired  = errors.New("vkcalls captcha required for guest anonym token; set auth.token to a pre-issued anonymToken")
	errAnonymToken      = errors.New("vkcalls anonym token required")
)

//nolint:gochecknoglobals // overridable bases for tests
var (
	callsAPIURL = defaultCallsAPIURL
	vkAPIBase   = defaultVKAPIBase
	vkLoginURL  = defaultVKLoginURL
	appKey      = defaultAppKey
)

// IceServer is the TURN/STUN block returned by joinConversationByLink.
type IceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// JoinResponse is the conversation bootstrap payload for the signaling engine.
type JoinResponse struct {
	ID          string     `json:"id"`
	Endpoint    string     `json:"endpoint"`
	Token       string     `json:"token"`
	PeerID      int64      `json:"peerId"`
	DeviceIdx   int        `json:"device_idx"`
	ClientType  string     `json:"client_type"`
	TurnServer  *IceServer `json:"turn_server"`
	StunServer  *IceServer `json:"stun_server"`
	JoinLink    string     `json:"join_link"`
	WTEndpoint  string     `json:"wt_endpoint"`
}

type loginResponse struct {
	UID              string `json:"uid"`
	SessionKey       string `json:"session_key"`
	SessionSecretKey string `json:"session_secret_key"`
	APIServer        string `json:"api_server"`
	ExternalUserID   string `json:"external_user_id"`
}

type anonymTokenByLinkResponse struct {
	UID   string `json:"uid"`
	Token string `json:"token"`
}

type apiError struct {
	ErrorCode int    `json:"error_code"`
	ErrorMsg  string `json:"error_msg"`
}

func postCalls(ctx context.Context, params url.Values, result any) error {
	params.Set("format", "JSON")
	params.Set("application_key", appKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, callsAPIURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", defaultOrigin)
	req.Header.Set("Referer", defaultOrigin+"/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
	req.Header.Set("Accept", "*/*")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d: %s", errAPI, resp.StatusCode, truncate(string(body), 512))
	}

	var apiErr apiError
	if err := json.Unmarshal(body, &apiErr); err == nil && apiErr.ErrorCode != 0 {
		return fmt.Errorf("%w: %d %s", errAPI, apiErr.ErrorCode, apiErr.ErrorMsg)
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func anonymLogin(ctx context.Context) (*loginResponse, error) {
	sessionData, err := json.Marshal(map[string]any{
		"version":        2,
		"device_id":      uuid.NewString(),
		"client_version": defaultClientVer,
		"client_type":    defaultClientType,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal session_data: %w", err)
	}
	params := url.Values{
		"method":       {"auth.anonymLogin"},
		"session_data": {string(sessionData)},
	}
	var out loginResponse
	if err := postCalls(ctx, params, &out); err != nil {
		return nil, fmt.Errorf("anonymLogin: %w", err)
	}
	if out.SessionKey == "" {
		return nil, fmt.Errorf("anonymLogin: %w: empty session_key", errAPI)
	}
	return &out, nil
}

func getAnonymTokenByLink(ctx context.Context, sessionKey, joinLink, displayName string) (string, error) {
	params := url.Values{
		"method":      {"vchat.getAnonymTokenByLink"},
		"session_key": {sessionKey},
		"joinLink":    {joinLink},
	}
	if displayName != "" {
		params.Set("anonymName", displayName)
	}
	var out anonymTokenByLinkResponse
	if err := postCalls(ctx, params, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("getAnonymTokenByLink: %w", errAnonymToken)
	}
	return out.Token, nil
}

func getVKAnonymAccessToken(ctx context.Context) (string, error) {
	form := url.Values{
		"client_id":     {defaultVKClientID},
		"client_secret": {defaultVKClientSecret},
		"token_type":    {"messages"},
		"version":       {"1"},
		"app_id":        {defaultVKClientID},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vkLoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", defaultOrigin)
	req.Header.Set("Referer", defaultOrigin+"/")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("login.vk anonym token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read login body: %w", err)
	}
	var parsed struct {
		Type string `json:"type"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode login body: %w", err)
	}
	if parsed.Data.AccessToken == "" {
		return "", fmt.Errorf("login.vk anonym token empty: %s", truncate(string(body), 256))
	}
	return parsed.Data.AccessToken, nil
}

func getAnonymousTokenViaVKAPI(ctx context.Context, accessToken, joinLink, displayName string) (string, error) {
	name := displayName
	if name == "" {
		name = "olcrtc"
	}
	form := url.Values{
		"vk_join_link": {fullJoinURL(joinLink)},
		"name":         {name},
		"access_token": {accessToken},
	}
	u := fmt.Sprintf("%s/method/calls.getAnonymousToken?v=5.275&client_id=%s", vkAPIBase, defaultVKClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create getAnonymousToken request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", defaultOrigin)
	req.Header.Set("Referer", defaultOrigin+"/")

	client := protect.NewHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("getAnonymousToken: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read getAnonymousToken body: %w", err)
	}

	var withErr struct {
		Error *struct {
			ErrorCode int    `json:"error_code"`
			ErrorMsg  string `json:"error_msg"`
		} `json:"error"`
		Response *struct {
			Token string `json:"token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &withErr); err != nil {
		return "", fmt.Errorf("decode getAnonymousToken: %w", err)
	}
	if withErr.Error != nil {
		if withErr.Error.ErrorCode == 14 {
			return "", errCaptchaRequired
		}
		return "", fmt.Errorf("%w: vk %d %s", errAPI, withErr.Error.ErrorCode, withErr.Error.ErrorMsg)
	}
	if withErr.Response == nil || withErr.Response.Token == "" {
		return "", fmt.Errorf("getAnonymousToken: %w", errAnonymToken)
	}
	return withErr.Response.Token, nil
}

func resolveAnonymToken(ctx context.Context, sessionKey, joinLink, displayName, preissued string) (string, error) {
	if strings.TrimSpace(preissued) != "" {
		return strings.TrimSpace(preissued), nil
	}
	if token, err := getAnonymTokenByLink(ctx, sessionKey, joinLink, displayName); err == nil {
		return token, nil
	}
	access, err := getVKAnonymAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("vk anonym access: %w", err)
	}
	return getAnonymousTokenViaVKAPI(ctx, access, joinLink, displayName)
}

func joinConversationByLink(ctx context.Context, sessionKey, joinLink, anonymToken string, isVideo bool) (*JoinResponse, error) {
	params := url.Values{
		"method":          {"vchat.joinConversationByLink"},
		"session_key":     {sessionKey},
		"joinLink":        {joinLink},
		"isVideo":         {fmt.Sprintf("%t", isVideo)},
		"protocolVersion": {defaultProtocolVer},
		"capabilities":    {defaultCapabilities},
	}
	if strings.TrimSpace(anonymToken) != "" {
		params.Set("anonymToken", anonymToken)
	}
	var out JoinResponse
	if err := postCalls(ctx, params, &out); err != nil {
		return nil, fmt.Errorf("joinConversationByLink: %w", err)
	}
	if out.Endpoint == "" {
		return nil, fmt.Errorf("joinConversationByLink: %w: empty endpoint", errAPI)
	}
	if out.ID == "" {
		out.ID = joinLink
	}
	enrichJoinFromEndpoint(&out)
	return &out, nil
}

// isOKSessionKey reports whether s looks like an OK/VK Calls session_key
// (HAR: values typically start with "-w-").
func isOKSessionKey(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "-w-") || strings.HasPrefix(s, "session:")
}

func normalizeSessionKey(s string) string {
	s = strings.TrimSpace(s)
	return strings.TrimPrefix(s, "session:")
}

func enrichJoinFromEndpoint(out *JoinResponse) {
	if out == nil || out.Endpoint == "" {
		return
	}
	u, err := url.Parse(out.Endpoint)
	if err != nil {
		return
	}
	q := u.Query()
	if out.PeerID == 0 {
		if p := q.Get("peerId"); p != "" {
			if n, err := strconv.ParseInt(p, 10, 64); err == nil {
				out.PeerID = n
			}
		}
	}
	if out.Token == "" {
		out.Token = q.Get("token")
	}
	if out.ID == "" {
		out.ID = q.Get("conversationId")
	}
	if out.ClientType == "" {
		out.ClientType = "VK"
	}
}


func marshalICE(server *IceServer) string {
	if server == nil {
		return ""
	}
	b, err := json.Marshal(server)
	if err != nil {
		return ""
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
