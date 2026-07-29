#!/usr/bin/env bash
# End-to-end: build TLS material, boot the uWebSockets.js server (HTTP + HTTPS),
# run the probe against BOTH the TLS and the plaintext port, then tear down.
#
#   ./run-e2e.sh
#
# Requires: go, node, openssl, and `npm install` already run in ./server.
set -uo pipefail
cd "$(dirname "$0")"

HOST=127.0.0.1
HTTP_PORT=${HTTP_PORT:-3000}
TLS_PORT=${TLS_PORT:-3443}

echo "== 1/4  install server deps (uWebSockets.js) if needed =="
if [ ! -d server/node_modules/uWebSockets.js ]; then
  ( cd server && npm install --no-audit --no-fund )
fi

echo "== 2/4  generate self-signed cert =="
./server/gen-certs.sh

echo "== 3/4  boot uWebSockets.js server =="
HOST="$HOST" HTTP_PORT="$HTTP_PORT" TLS_PORT="$TLS_PORT" node server/server.js > /tmp/uws-server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT

# wait for both listeners
for i in $(seq 1 50); do
  if grep -q 'HTTPS' /tmp/uws-server.log && grep -q 'HTTP ' /tmp/uws-server.log; then break; fi
  sleep 0.2
done
cat /tmp/uws-server.log

echo
echo "== 4/4  run the probe over TLS, then over plaintext =="
echo "################## HTTPS (TLS) ##################"
go run smuggle_probe_tls.go -k "https://${HOST}:${TLS_PORT}"
echo
echo "################## HTTP (plaintext) ##################"
go run smuggle_probe_tls.go "http://${HOST}:${HTTP_PORT}"
