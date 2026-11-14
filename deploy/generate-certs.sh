#!/usr/bin/env bash
# ==============================================================================
# VIGIL Platform - Local Development TLS Certificate Generator
# Generates self-signed certificates for local HTTPS development and testing.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

mkdir -p "${CERTS_DIR}"

if [[ -f "${CERTS_DIR}/privkey.pem" && -f "${CERTS_DIR}/fullchain.pem" ]]; then
    echo "TLS certificates already exist in ${CERTS_DIR}"
    exit 0
fi

echo "Generating self-signed TLS certificates for localhost..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${CERTS_DIR}/privkey.pem" \
    -out "${CERTS_DIR}/fullchain.pem" \
    -subj "/C=US/ST=Security/L=Operations/O=VIGIL/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

chmod 600 "${CERTS_DIR}/privkey.pem"
chmod 644 "${CERTS_DIR}/fullchain.pem"

echo "TLS certificates generated successfully in ${CERTS_DIR}"

