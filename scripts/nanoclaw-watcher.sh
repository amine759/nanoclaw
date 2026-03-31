#!/usr/bin/env bash
# nanoclaw-watcher.sh — attaches to the NanoClaw agent container as soon as it spawns

FILTER=${1:-nanoclaw}

echo "Waiting for container matching '${FILTER}'..."

while true; do
  id=$(docker ps -q --filter name="$FILTER")
  if [ -n "$id" ]; then
    name=$(docker ps --filter name="$FILTER" --format '{{.Names}}' | head -1)
    echo "Container found: $name ($id) — attaching logs"
    echo "---"
    docker logs -f "$id" 2>&1
    echo "---"
    echo "Container exited. Waiting for next run..."
  fi
  sleep 0.3
done
