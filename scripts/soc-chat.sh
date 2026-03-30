#!/usr/bin/env bash
# SOC analyst chat — talk to the wazuh_soc NanoClaw agent from the terminal.
#
# Usage: ./scripts/soc-chat.sh [--jid local:wazuh_soc] [--port 3001]
#
# Opens an SSE stream for responses in the background, then reads analyst
# messages from stdin and POSTs them. Type /quit to exit.

set -euo pipefail

JID="${NANOCLAW_JID:-local:wazuh_soc}"
PORT="${NANOCLAW_PORT:-3001}"
BASE="http://127.0.0.1:${PORT}"

# ──────────────────────────────────────────────────────────────
# Verify NanoClaw is reachable
# ──────────────────────────────────────────────────────────────
if ! curl -sf "${BASE}/health" > /dev/null 2>&1; then
  echo "ERROR: NanoClaw local channel is not responding at ${BASE}"
  echo "  Make sure NanoClaw is running: systemctl --user status nanoclaw"
  exit 1
fi

# ──────────────────────────────────────────────────────────────
# Open SSE stream — print agent responses to stdout
# ──────────────────────────────────────────────────────────────
TMPFIFO=$(mktemp -u /tmp/soc-chat-sse.XXXXXX)
mkfifo "$TMPFIFO"

cleanup() {
  kill "$SSE_PID" 2>/dev/null || true
  rm -f "$TMPFIFO"
}
trap cleanup EXIT

# SSE reader: filter out keep-alive and connection events, pretty-print messages
(curl -sN "${BASE}/chat/stream?jid=${JID}" 2>/dev/null | while IFS= read -r line; do
  if [[ "$line" == data:* ]]; then
    payload="${line#data: }"
    type=$(echo "$payload" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('type',''))" 2>/dev/null || true)
    if [[ "$type" == "message" ]]; then
      text=$(echo "$payload" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('text',''))" 2>/dev/null || true)
      echo ""
      echo -e "\033[1;36m[Agent]\033[0m ${text}"
      echo ""
    fi
  fi
done) &
SSE_PID=$!

echo ""
echo "──────────────────────────────────────────────────"
echo "  Wazuh SOC Agent  (group: ${JID})"
echo "  Type your message and press Enter."
echo "  Type /quit to exit."
echo "──────────────────────────────────────────────────"
echo ""

# ──────────────────────────────────────────────────────────────
# Read analyst input → POST to NanoClaw
# ──────────────────────────────────────────────────────────────
while IFS= read -r -p $'\033[1;33m[You]\033[0m ' message; do
  [[ -z "$message" ]] && continue
  [[ "$message" == "/quit" ]] && break

  response=$(curl -sf -X POST "${BASE}/chat" \
    -H 'Content-Type: application/json' \
    -d "{\"jid\":\"${JID}\",\"text\":$(printf '%s' "$message" | python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))")}" 2>&1) || {
    echo "ERROR: Failed to send message — is NanoClaw running?"
    continue
  }
  echo "(queued)"
done

echo ""
echo "Goodbye."
