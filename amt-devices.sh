#!/usr/bin/env bash
#
# amt-devices.sh — issue Intel AMT TLS server certs, and test the endpoints.
#
# Requires a CA created by amt-ca-init.sh.
#
# Usage:
#   ./amt-devices.sh issue <ip> <fqdn>            # one device
#   ./amt-devices.sh issue -f hosts.txt           # batch
#   ./amt-devices.sh test  <ip>                   # test one endpoint
#   ./amt-devices.sh test  -f hosts.txt           # test all
#   ./amt-devices.sh list                         # show issued certs
#
# hosts.txt format (whitespace separated, '#' comments ignored):
#   192.168.15.11   box11.lan
#   192.168.15.12   box12.lan
#
# Env:
#   CA_DIR    default $HOME/amt-ca
#   P12_PASS  default "changeme"   — password for the .p12 you feed MeshCommander
#   DAYS      default 1825
#
set -euo pipefail

CA_DIR="${CA_DIR:-$HOME/amt-ca}"
P12_PASS="${P12_PASS:-changeme}"
DAYS="${DAYS:-1825}"
BITS="${BITS:-2048}"
CERT_O="${CERT_O:-TM}"
CERT_C="${CERT_C:-DE}"

CA_KEY="$CA_DIR/ca/amt-root-ca.key"
CA_CRT="$CA_DIR/ca/amt-root-ca.crt"
CA_SRL="$CA_DIR/ca/amt-root-ca.srl"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# --- preflight -------------------------------------------------------------
command -v openssl >/dev/null 2>&1 || { red "openssl not found"; exit 1; }
openssl version | grep -qi libressl && { red "LibreSSL detected; need real OpenSSL"; exit 1; }

# OpenSSL 3 needs -legacy for PKCS#12 that node-forge (MeshCommander) can parse.
P12_COMPAT=(-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1)
if openssl pkcs12 -help 2>&1 | grep -q -- '-legacy'; then
  P12_COMPAT=(-legacy "${P12_COMPAT[@]}")
fi

# AMT 12 doesn't advertise RFC 5746; OpenSSL 3 aborts without this.
S_FLAGS=(-tls1_2)
if openssl s_client -help 2>&1 | grep -q -- '-legacy_renegotiation'; then
  S_FLAGS+=(-legacy_renegotiation)
fi

# --- helpers ---------------------------------------------------------------
parse_hosts() {
  # emits "ip<TAB>fqdn" lines
  local f="$1"
  [[ -r "$f" ]] || { red "cannot read $f"; exit 1; }
  sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$f" | awk '{print $1"\t"$2}'
}

issue_one() {
  local ip="$1" fqdn="$2"
  local d="$CA_DIR/devices/$fqdn"

  [[ -n "$ip" && -n "$fqdn" ]] || { red "issue: need <ip> <fqdn>"; return 1; }

  mkdir -p "$d"
  bold ">> $fqdn ($ip)"

  openssl genrsa -out "$d/$fqdn.key" "$BITS" 2>/dev/null
  chmod 600 "$d/$fqdn.key"

  openssl req -new -key "$d/$fqdn.key" -out "$d/$fqdn.csr" \
    -subj "/CN=${fqdn}/O=${CERT_O}/C=${CERT_C}"

  # SAN carries BOTH the DNS name and the IP, so the cert validates either way.
  cat > "$d/$fqdn.ext" <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${fqdn}, IP:${ip}
EOF

  openssl x509 -req -sha256 -days "$DAYS" \
    -in "$d/$fqdn.csr" \
    -CA "$CA_CRT" -CAkey "$CA_KEY" -CAserial "$CA_SRL" \
    -extfile "$d/$fqdn.ext" \
    -out "$d/$fqdn.crt" 2>/dev/null

  openssl pkcs12 -export \
    -inkey "$d/$fqdn.key" \
    -in "$d/$fqdn.crt" \
    -certfile "$CA_CRT" \
    -out "$d/$fqdn.p12" \
    -name "AMT $fqdn" \
    "${P12_COMPAT[@]}" \
    -passout "pass:${P12_PASS}"
  chmod 600 "$d/$fqdn.p12"

  # verify what we just made
  if ! openssl verify -CAfile "$CA_CRT" "$d/$fqdn.crt" >/dev/null 2>&1; then
    red "   FAIL: cert does not verify against the CA"
    return 1
  fi
  local san eku
  san=$(openssl x509 -in "$d/$fqdn.crt" -noout -ext subjectAltName 2>/dev/null | tail -n1 | xargs)
  eku=$(openssl x509 -in "$d/$fqdn.crt" -noout -ext extendedKeyUsage 2>/dev/null | tail -n1 | xargs)
  grep -q "IP Address:${ip}" <<<"$san" || { red "   FAIL: IP missing from SAN"; return 1; }
  grep -qi "TLS Web Server Authentication" <<<"$eku" || { red "   FAIL: serverAuth EKU missing"; return 1; }

  green "   ok  SAN: $san"
  green "   ok  EKU: $eku"
  echo  "   p12: $d/$fqdn.p12  (password: $P12_PASS)"
}

test_one() {
  local ip="$1"
  bold ">> testing $ip:16993"

  if ! timeout 5 bash -c "</dev/tcp/$ip/16993" 2>/dev/null; then
    red "   port 16993 not reachable — TLS not committed, or firewalled"
    return 1
  fi

  local out
  out=$(openssl s_client -connect "$ip:16993" "${S_FLAGS[@]}" \
          -CAfile "$CA_CRT" </dev/null 2>/dev/null || true)

  if ! grep -q "BEGIN CERTIFICATE" <<<"$out"; then
    red "   handshake failed — no certificate returned"
    return 1
  fi

  local subj dates verify
  subj=$(grep -m1 '^subject=' <<<"$out" | xargs)
  dates=$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' <<<"$out" \
            | openssl x509 -noout -dates 2>/dev/null | tr '\n' ' ')
  verify=$(grep -m1 'Verify return code' <<<"$out" | xargs)

  echo "   $subj"
  echo "   $dates"
  if grep -q 'Verify return code: 0' <<<"$out"; then
    green "   $verify"
  else
    red   "   $verify"
    echo  "   (root not trusted by this shell, or wrong cert bound in AMT)"
    return 1
  fi
}

list_certs() {
  shopt -s nullglob
  for c in "$CA_DIR"/devices/*/*.crt; do
    printf '%-24s %s\n' \
      "$(basename "$c" .crt)" \
      "$(openssl x509 -in "$c" -noout -enddate | cut -d= -f2)"
  done
}

# --- dispatch --------------------------------------------------------------
cmd="${1:-}"; shift || true

case "$cmd" in
  issue)
    [[ -r "$CA_CRT" ]] || { red "no CA at $CA_DIR — run amt-ca-init.sh first"; exit 1; }
    rc=0
    if [[ "${1:-}" == "-f" ]]; then
      while IFS=$'\t' read -r ip fqdn; do
        issue_one "$ip" "$fqdn" || rc=1
        echo
      done < <(parse_hosts "${2:?need a hosts file}")
    else
      issue_one "${1:?need <ip>}" "${2:?need <fqdn>}" || rc=1
    fi
    exit $rc
    ;;
  test)
    rc=0
    if [[ "${1:-}" == "-f" ]]; then
      while IFS=$'\t' read -r ip _; do
        test_one "$ip" || rc=1
        echo
      done < <(parse_hosts "${2:?need a hosts file}")
    else
      test_one "${1:?need <ip>}" || rc=1
    fi
    exit $rc
    ;;
  list)
    list_certs
    ;;
  *)
    sed -n '2,25p' "$0" | sed 's/^#\s\?//'
    exit 1
    ;;
esac
