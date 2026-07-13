#!/usr/bin/env bash
#
# amt-ca-init.sh — create the root CA used to sign Intel AMT TLS server certs.
# Run this ONCE. It refuses to clobber an existing CA.
#
# Usage:
#   ./amt-ca-init.sh
#   CA_DIR=/secure/amt-ca CA_CN="ACME AMT Root CA" ./amt-ca-init.sh
#
set -euo pipefail

CA_DIR="${CA_DIR:-$HOME/amt-ca}"
CA_CN="${CA_CN:-AMT Root CA}"
CA_O="${CA_O:-TM}"
CA_C="${CA_C:-DE}"
CA_DAYS="${CA_DAYS:-3650}"
CA_BITS="${CA_BITS:-2048}"

# --- sanity checks ---------------------------------------------------------
if ! command -v openssl >/dev/null 2>&1; then
  echo "error: openssl not found" >&2
  exit 1
fi

if openssl version | grep -qi libressl; then
  echo "error: this is LibreSSL, not OpenSSL. Install real OpenSSL." >&2
  echo "       macOS: brew install openssl && use \$(brew --prefix openssl)/bin/openssl" >&2
  exit 1
fi

CA_KEY="$CA_DIR/ca/amt-root-ca.key"
CA_CRT="$CA_DIR/ca/amt-root-ca.crt"

if [[ -e "$CA_KEY" || -e "$CA_CRT" ]]; then
  echo "error: a CA already exists in $CA_DIR/ca — refusing to overwrite." >&2
  echo "       Delete it manually if you really want to start over." >&2
  exit 1
fi

# --- build -----------------------------------------------------------------
mkdir -p "$CA_DIR/ca" "$CA_DIR/devices"
chmod 700 "$CA_DIR" "$CA_DIR/ca"

echo ">> generating ${CA_BITS}-bit RSA key"
openssl genrsa -out "$CA_KEY" "$CA_BITS" 2>/dev/null
chmod 600 "$CA_KEY"

echo ">> self-signing root certificate (${CA_DAYS} days)"
openssl req -x509 -new -nodes -sha256 -days "$CA_DAYS" \
  -key "$CA_KEY" \
  -out "$CA_CRT" \
  -subj "/CN=${CA_CN}/O=${CA_O}/C=${CA_C}" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Serial file used by the device script.
echo "01" > "$CA_DIR/ca/amt-root-ca.srl"

echo
echo "CA created:"
openssl x509 -in "$CA_CRT" -noout -subject -dates -ext basicConstraints
echo
cat <<EOF
Files:
  private key : $CA_KEY   (KEEP THIS SAFE — it signs every device)
  certificate : $CA_CRT

Next steps:
  1) Issue device certs:   ./amt-devices.sh issue 192.168.15.11 box11.lan
  2) Trust this root on your workstation:
       sudo cp "$CA_CRT" /usr/local/share/ca-certificates/amt-root-ca.crt
       sudo update-ca-certificates
     (macOS: import into Keychain Access > System > Always Trust)
  3) Upload $CA_CRT to each AMT device as a Trusted Root Certificate.
EOF
