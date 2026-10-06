#!/usr/bin/env bash
set -e

DEMO_DIR=/tmp/sig3tunnel-demo
BFCFG="$DEMO_DIR/cfg"
export PATH="/Users/christianecg/dev/personal/avelor_sig3/bin:/Users/christianecg/.n/bin:/opt/homebrew/bin:/usr/bin:/bin"

# Kill leftovers from prior runs
if [ -f "$DEMO_DIR/relay.pid" ]; then
  kill "$(cat "$DEMO_DIR/relay.pid")" 2>/dev/null || true
fi
if [ -f "$DEMO_DIR/server.pid" ]; then
  kill "$(cat "$DEMO_DIR/server.pid")" 2>/dev/null || true
fi

rm -rf "$DEMO_DIR"
mkdir -p "$BFCFG"

# Simple local HTTP server on port 3001
node -e "
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('ok\n');
}).listen(3001, '127.0.0.1');
" &
echo $! > "$DEMO_DIR/server.pid"

# Start relay in background
SIG3TUNNEL_CONFIG_DIR="$BFCFG" sig3tunnel serve --port 9001 > /dev/null 2>&1 &
echo $! > "$DEMO_DIR/relay.pid"
sleep 0.8

# Issue token, strip ANSI codes, capture raw value
OUT=$(SIG3TUNNEL_CONFIG_DIR="$BFCFG" sig3tunnel token issue --global 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
RAW=$(echo "$OUT" | grep 'token:' | awk '{print $2}' | tr -d '[:space:]')

# Save client config
SIG3TUNNEL_CONFIG_DIR="$BFCFG" sig3tunnel use ws://localhost:9001 "$RAW" > /dev/null

# Pre-schedule curls to fire after connect has time to establish
(sleep 4 && \
  curl -s http://localhost:9001/ > /dev/null && \
  sleep 1 && \
  curl -s http://localhost:9001/status > /dev/null && \
  sleep 1 && \
  curl -s http://localhost:9001/api/users > /dev/null) &

export SIG3TUNNEL_CONFIG_DIR="$BFCFG"
