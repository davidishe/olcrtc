# Cockney VPN fork of olcRTC

Upstream: https://github.com/openlibrecommunity/olcrtc

## Cockney multi-user additions

- YAML `client.device_id` / `client.access_token` → CLIENT_HELLO claims
- YAML `cockney.subscription_url` / `refresh_interval` (subscription bootstrap helpers)
- Embeddable `tunnel.Server`: `DisconnectSession`, `DisconnectDevice`, `ActiveSessions`
- Backward compatible: YAML without `client` / `cockney` still parses

## Pin

See tag `cockney-v1` or branch `cockney-multiuser`.
