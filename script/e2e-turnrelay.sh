#!/usr/bin/env bash
# Smoke turnrelay: optional DIRECT udp, or full VK TURN path.
# Usage:
#   DIRECT=1 ENDPOINT=host:port KEY=... DEVICE=... JWT=... ./script/e2e-turnrelay.sh
#   VK path: JOIN_URL=... AUTH_TOKEN=... ENDPOINT=... KEY=... DEVICE=... JWT=... ./script/e2e-turnrelay.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${OLCRTC_BIN:-$ROOT/olcrtc}"
SOCKS_PORT="${SOCKS_PORT:-18808}"
WORKDIR="${WORKDIR:-/tmp/olcrtc-turnrelay-e2e}"
mkdir -p "$WORKDIR/data"

if [[ ! -x "$BIN" ]]; then
  (cd "$ROOT" && go build -o "$BIN" ./cmd/olcrtc)
fi

ENDPOINT="${ENDPOINT:?set ENDPOINT=host:port}"
KEY="${KEY:?set KEY=64hex}"
DEVICE="${DEVICE:?set DEVICE=uuid}"
JWT="${JWT:?set JWT=access_token}"

if [[ "${DIRECT:-0}" == "1" ]]; then
  cat > "$WORKDIR/client.yaml" <<EOF
mode: cnc
auth: { provider: none }
room: { id: unused }
crypto: { key: "$KEY" }
net: { transport: turnrelay, dns: "8.8.8.8:53" }
turnrelay: { endpoint: "$ENDPOINT", direct: true }
socks: { host: "127.0.0.1", port: $SOCKS_PORT }
client: { device_id: "$DEVICE", access_token: "$JWT" }
data: $WORKDIR/data
debug: true
EOF
else
  JOIN_URL="${JOIN_URL:?set JOIN_URL for VK TURN path}"
  AUTH_TOKEN="${AUTH_TOKEN:?set AUTH_TOKEN (session_key)}"
  cat > "$WORKDIR/client.yaml" <<EOF
mode: cnc
auth: { provider: vkcalls, token: "$AUTH_TOKEN" }
room: { id: "$JOIN_URL" }
crypto: { key: "$KEY" }
net: { transport: turnrelay, dns: "8.8.8.8:53" }
turnrelay: { endpoint: "$ENDPOINT" }
socks: { host: "127.0.0.1", port: $SOCKS_PORT }
client: { device_id: "$DEVICE", access_token: "$JWT" }
data: $WORKDIR/data
debug: true
EOF
fi

"$BIN" "$WORKDIR/client.yaml" > "$WORKDIR/client.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT

for i in $(seq 1 60); do
  if nc -z 127.0.0.1 "$SOCKS_PORT" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "client exited early:" >&2
    cat "$WORKDIR/client.log" >&2
    exit 1
  fi
  sleep 1
done

python3 - <<PY
import socket, struct, sys
port = int("$SOCKS_PORT")
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.sendall(b"\x05\x01\x00")
assert s.recv(2) == b"\x05\x00", "socks auth failed"
req = b"\x05\x01\x00\x01" + bytes([8, 8, 8, 8]) + struct.pack("!H", 443)
s.sendall(req)
s.settimeout(15)
rep = s.recv(10)
if len(rep) < 2 or rep[1] != 0:
    print("socks connect failed", rep, file=sys.stderr)
    sys.exit(1)
print("SOCKS_OK session opened → 8.8.8.8:443")
s.close()
PY
