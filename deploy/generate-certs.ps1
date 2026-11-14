# ==============================================================================
# VIGIL Platform - Local Development TLS Certificate Generator (PowerShell)
# Generates self-signed certificates for local HTTPS development and testing.
# ==============================================================================

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir = Join-Path $ScriptDir "certs"

if (-not (Test-Path $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir -Force | Out-Null
}

$PrivKey = Join-Path $CertsDir "privkey.pem"
$FullChain = Join-Path $CertsDir "fullchain.pem"

if ((Test-Path $PrivKey) -and (Test-Path $FullChain)) {
    Write-Host "TLS certificates already exist in $CertsDir" -ForegroundColor Green
    exit 0
}

Write-Host "Generating self-signed TLS certificates for localhost..." -ForegroundColor Cyan

$openssl = Get-Command "openssl.exe" -ErrorAction SilentlyContinue
if ($openssl) {
    & openssl req -x509 -nodes -days 365 -newkey rsa:2048 `
        -keyout $PrivKey `
        -out $FullChain `
        -subj "/C=US/ST=Security/L=Operations/O=VIGIL/CN=localhost" `
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    Write-Host "TLS certificates generated successfully in $CertsDir" -ForegroundColor Green
} else {
    Write-Warning "OpenSSL not found in PATH. Please install OpenSSL or generate certificates manually."
}

