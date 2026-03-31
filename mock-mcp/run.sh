#!/usr/bin/env bash
set -e

PORT=${PORT:-3000}
DIR="$(cd "$(dirname "$0")" && pwd)"

pid=$(lsof -ti:$PORT 2>/dev/null)
if [ -n "$pid" ]; then
  echo "Port $PORT in use (pid $pid) — killing..."
  kill -9 $pid
  sleep 1
fi

echo "Starting mock Wazuh MCP server on :$PORT"
exec node "$DIR/index.js"
