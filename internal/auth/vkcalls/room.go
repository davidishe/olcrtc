package vkcalls

import (
	"net/url"
	"strings"
)

const (
	joinPathPrefix = "/call/join/"
	joinURLPrefix  = "https://vk.com/call/join/"
)

// ParseJoinLink normalizes a VK Calls room URL or raw join id into the
// joinLink token accepted by vchat.joinConversationByLink.
//
// Accepted forms:
//   - https://vk.com/call/join/<id>
//   - https://vk.ru/call/join/<id>
//   - /call/join/<id>
//   - bare <id>
func ParseJoinLink(roomURL string) (string, error) {
	raw := strings.TrimSpace(roomURL)
	if raw == "" {
		return "", errJoinLinkRequired
	}

	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "/") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		path := u.Path
		if idx := strings.Index(path, joinPathPrefix); idx >= 0 {
			id := strings.Trim(path[idx+len(joinPathPrefix):], "/")
			if id == "" {
				return "", errJoinLinkRequired
			}
			if q := u.RawQuery; q != "" {
				// Join ids are path segments; ignore query noise.
				_ = q
			}
			return id, nil
		}
		// Fall through: treat last path segment as id when host looks like vk.
		host := strings.ToLower(u.Hostname())
		if strings.Contains(host, "vk.com") || strings.Contains(host, "vk.ru") {
			parts := strings.Split(strings.Trim(path, "/"), "/")
			if len(parts) > 0 && parts[len(parts)-1] != "" {
				return parts[len(parts)-1], nil
			}
		}
		return "", errJoinLinkInvalid
	}

	id := strings.Trim(raw, "/")
	if id == "" {
		return "", errJoinLinkRequired
	}
	return id, nil
}

func fullJoinURL(joinLink string) string {
	return joinURLPrefix + joinLink
}
