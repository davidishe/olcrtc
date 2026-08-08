package vkcalls

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/openlibrecommunity/olcrtc/internal/auth"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

// Provider produces vkcalls engine credentials for VK Звонки rooms.
type Provider struct{}

// Engine reports which engine consumes credentials from this auth provider.
func (Provider) Engine() string { return "vkcalls" }

// DefaultServiceURL returns the VK Calls join base URL.
func (Provider) DefaultServiceURL() string { return "https://vk.com/call" }

// Issue joins an existing VK Calls room and returns signaling credentials.
//
// cfg.RoomURL accepts a full join URL (https://vk.com/call/join/<id> or
// https://vk.ru/call/join/<id>) or the raw join id.
//
// cfg.Token semantics:
//   - empty: guest anonymLogin + anonymToken (may hit captcha / IP blocks)
//   - OK Calls session_key (typically starts with "-w-"): join without anonymToken
//     (logged-in VK web path from HAR)
//   - otherwise: treated as pre-issued anonymToken
//
// Room creation is not supported in v1; rooms originate in the VK UI.
func (Provider) Issue(ctx context.Context, cfg auth.Config) (auth.Credentials, error) {
	joinLink, err := ParseJoinLink(cfg.RoomURL)
	if err != nil {
		if err == errJoinLinkRequired {
			return auth.Credentials{}, auth.ErrRoomIDRequired
		}
		return auth.Credentials{}, err
	}

	token := strings.TrimSpace(cfg.Token)
	var (
		sessionKey  string
		anonymToken string
		uid         string
		externalID  string
	)

	if isOKSessionKey(token) {
		sessionKey = normalizeSessionKey(token)
		logger.Infof("vkcalls: using pre-issued OK session_key (authorized join, no anonymToken)")
	} else {
		login, err := anonymLogin(ctx)
		if err != nil {
			return auth.Credentials{}, err
		}
		sessionKey = login.SessionKey
		uid = login.UID
		externalID = login.ExternalUserID

		anonymToken, err = resolveAnonymToken(ctx, sessionKey, joinLink, cfg.Name, token)
		if err != nil {
			return auth.Credentials{}, err
		}
		if token == "" {
			logger.Infof("vkcalls: obtained anonymToken; reuse via auth.token to avoid captcha: %s", anonymToken)
		}
	}

	joined, err := joinConversationByLink(ctx, sessionKey, joinLink, anonymToken, true)
	if err != nil {
		return auth.Credentials{}, err
	}

	clientType := joined.ClientType
	if clientType == "" {
		clientType = "VK"
	}

	extra := map[string]string{
		"conversationId": joined.ID,
		"joinLink":       joinLink,
		"peerId":         strconv.FormatInt(joined.PeerID, 10),
		"deviceIdx":      strconv.Itoa(joined.DeviceIdx),
		"uid":            uid,
		"externalUserId": externalID,
		"clientType":     clientType,
		"sessionKey":     sessionKey,
	}
	// DIRECT role: authorized agent (OK session_key as auth.token) offers;
	// guest/anonym client always answers. Both get an OK-looking sessionKey
	// from anonymLogin, so we must not key off the "-w-" prefix alone.
	if anonymToken == "" && isOKSessionKey(token) {
		extra["directRole"] = "offer"
	} else {
		extra["directRole"] = "answer"
	}
	if uid == "" {
		if u, err := urlUserID(joined.Endpoint); err == nil {
			extra["uid"] = u
		}
	}
	if turn := marshalICE(joined.TurnServer); turn != "" {
		extra["turn_server"] = turn
	}
	if stun := marshalICE(joined.StunServer); stun != "" {
		extra["stun_server"] = stun
	}
	if joined.WTEndpoint != "" {
		extra["wt_endpoint"] = joined.WTEndpoint
	}
	if joined.Token != "" {
		extra["signalingToken"] = joined.Token
	}

	sigToken := joined.Token
	if sigToken == "" {
		sigToken = anonymToken
	}

	return auth.Credentials{
		URL:   joined.Endpoint,
		Token: sigToken,
		Extra: extra,
	}, nil
}

func urlUserID(endpoint string) (string, error) {
	u, err := parseEndpoint(endpoint)
	if err != nil {
		return "", err
	}
	return u.Query().Get("userId"), nil
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	return url.Parse(endpoint)
}

func init() { //nolint:gochecknoinits // auth registration is the canonical Go pattern for plugins
	auth.Register("vkcalls", Provider{})
}
