#!/usr/bin/env bash
# Generate a self-signed certificate for local TLS testing (localhost / 127.0.0.1).
# Produces certs/key.pem and certs/cert.pem, which uWS.SSLApp loads.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  2>/dev/null

echo "wrote certs/key.pem and certs/cert.pem (self-signed, CN=localhost, SAN localhost/127.0.0.1)"
