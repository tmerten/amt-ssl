# Intel AMT over HTTPS, from Linux/macOS

Tooling to get a **real, browser-valid TLS certificate** onto Intel AMT machines and
enable HTTPS on port 16993 — without Windows, and without Intel SCS.

Developed against **Dell OptiPlex 7070, Intel ME 12.0.96, Admin Control Mode (ACM)**.
Should apply to AMT 11–12 generally.

## Why this exists

The obvious path — MeshCommander's *Security Settings → Issue Certificate* — produces a
certificate that **cannot carry a `subjectAltName`**. Chrome and Firefox dropped CN
fallback years ago, so those certs are rejected with `ERR_CERT_COMMON_NAME_INVALID` no
matter how thoroughly you trust the root. See [Gotchas](#gotchas) for the source
evidence.

These scripts build a proper CA, issue SAN certs, install them into AMT firmware over
WS-Management, and turn on TLS.

---

## Requirements

- **OpenSSL 3.x** (not LibreSSL — macOS ships LibreSSL as `openssl`; use `brew install openssl`)
- **Python 3** with `requests`
- AMT activated (ACM or CCM) with a known admin password, reachable on port 16992

---

## Tools

| Tool | Purpose |
|---|---|
| `amt-ca-init.sh` | Create your root CA. Run once. |
| `amt-devices.sh` | Issue per-device SAN certs; test the resulting endpoints. |
| `amt-tls.py` | Install cert + key into AMT firmware and enable TLS (WS-Management). |

---

## How to use

### 1. Create the CA (once)

```bash
./amt-ca-init.sh
```

Creates `~/amt-ca/ca/amt-root-ca.{key,crt}`. Keep the key safe — it signs every device.

Override with env vars if you like:

```bash
CA_DIR=/secure/amt-ca CA_CN="ACME AMT Root CA" ./amt-ca-init.sh
```

### 2. Issue device certificates

```bash
cat > hosts.txt <<'EOF'
# ip            fqdn
192.168.15.11   amt-machine1.lan
192.168.15.12   amt-machine2.lan
EOF

./amt-devices.sh issue -f hosts.txt
```
Note: I assume your IP is the one above, change accordingly when following the README.

Each device gets `.key`, `.crt` and `.p12` under `~/amt-ca/devices/<fqdn>/`.

The certs carry **both** a DNS and an IP SAN, plus the `serverAuth` EKU. The script
hard-fails if either is missing.

> **DHCP warning:** the IP is baked into the SAN, so address changes invalidate the cert.
> If your boxes aren't on static leases, remove `IP:${ip}` from the `subjectAltName` line
> in `issue_one()` and go DNS-only.

### 3. Install into AMT and enable TLS

```bash
pip install requests

./amt-tls.py --host 192.168.15.11 --pass 'YourAMTpass' \
  --key  ~/amt-ca/devices/amt-machine1.lan/amt-machine1.lan.key \
  --cert ~/amt-ca/devices/amt-machine1.lan/amt-machine1.lan.crt \
  --root ~/amt-ca/ca/amt-root-ca.crt
```

What it does, in order:

1. `AMT_TimeSynchronizationService` — sync the firmware clock
2. `AddKey` — import the private key (PKCS#1 DER)
3. `AddTrustedRootCertificate` — your CA root
4. `AddCertificate` — the SAN leaf
5. `AMT_TLSCredentialContext` — bind the leaf to the TLS endpoint (Create, or Put if one exists)
6. `AMT_TLSSettingData` — enable TLS on **both** the 802.3 (remote) and LMS (local) instances
7. `AMT_SetupAndConfigurationService.CommitChanges` — **nothing takes effect without this**

Useful flags:

```bash
--dry-run -v     # print the SOAP without sending it
--skip-clock     # skip time sync if the RTC is already sane
--tls-only       # close port 16992 (ONLY after you've verified 16993 works)
--disable        # revert: turn TLS off, reopen 16992
```

By default port 16992 stays open, so you cannot lock yourself out. Flip `--tls-only`
only once every machine is confirmed green.

### 4. Verify

```bash
./amt-devices.sh test -f hosts.txt
```

Wants `Verify return code: 0 (ok)`. Under the hood:

```bash
openssl s_client -connect 192.168.15.11:16993 -tls1_2 -legacy_renegotiation \
  -CAfile ~/amt-ca/ca/amt-root-ca.crt </dev/null
```

### 5. Trust the CA system-wide

```bash
# Debian/Ubuntu
sudo cp ~/amt-ca/ca/amt-root-ca.crt /usr/local/share/ca-certificates/amt-root-ca.crt
sudo update-ca-certificates
```

macOS: import into Keychain Access → System → **Always Trust**.

`update-ca-certificates` *regenerates* `/etc/ssl/certs/ca-certificates.crt` with your root
included, so afterwards the leaf validates from the default trust store:

```bash
$ openssl verify ~/amt-ca/devices/amt-machine1.lan/amt-machine1.lan.crt
amt-machine1.lan.crt: OK
```

Add the FQDNs to DNS or `/etc/hosts` and connect **by name**, not IP.

---

## Using `wsman` against the result

```bash
wsman identify --hostname amt-machine1.lan --port 16993 \
  --username admin --password 'YourAMTpass' -y digest \
  --cacert /etc/ssl/certs/ca-certificates.crt
```

`--cacert` is what selects the https scheme in `wsmancli` — see
[MAAS-BUG-2146166.md](MAAS-BUG-2146166.md). Do **not** use `--endpoint`.

Power query (this is exactly what MAAS runs):

```bash
wsman --hostname amt-machine1.lan --port 16993 -u admin -p 'YourAMTpass' -y digest \
  --cacert /etc/ssl/certs/ca-certificates.crt \
  --optimize --encoding utf-8 \
  enumerate 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_AssociatedPowerManagementService'
```

`<PowerState>2</PowerState>` = on, `8` = off.

---

## Gotchas

Each of these cost real debugging time.

### OpenSSL 3 refuses AMT 12 out of the box

AMT 12's TLS stack doesn't advertise RFC 5746 secure renegotiation, so OpenSSL 3 aborts
the handshake before it ever sees the certificate:

```
error:0A000152:SSL routines:final_renegotiate:unsafe legacy renegotiation disabled
no peer certificate available
```

This is **not** a certificate problem. `openssl s_client` takes `-legacy_renegotiation`.
`curl` and `wsman` have no such flag, so they need an OpenSSL config shim:

```bash
cat > /tmp/openssl-amt.cnf <<'EOF'
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
Options = UnsafeLegacyRenegotiation
CipherString = DEFAULT@SECLEVEL=0
EOF

OPENSSL_CONF=/tmp/openssl-amt.cnf curl -vk --tlsv1.2 https://amt-machine1.lan:16993/
```

### MeshCommander cannot issue a SAN certificate

From `amt-certificates-0.0.1.js`, `amtcert_createCertificate()`:

```js
cert.setExtensions([ basicConstraints, keyUsage, extKeyUsage, subjectKeyIdentifier, nsCertType ]);
cert.validity.notBefore = new Date(2018, 0, 1);
cert.validity.notAfter  = new Date(2049, 11, 31);
```

No `subjectAltName`, ever. (The hardcoded validity is also why MeshCommander-issued certs
all show `notBefore = 2018-01-01`.) This is the whole reason this repo exists.

### MeshCommander cannot import a device private key

Its "Issue Certificate" flow always has **AMT generate the keypair**:

```js
function issueCertButtonOk3(privateKey, subjectAttributes, cert) {
    xxCaPrivateKey = privateKey;              // ← from the .p12 you supply
    amtstack.AMT_PublicKeyManagementService_GenerateKeyPair(0, 2048, ...);
}
```

The `.p12` it asks for is your **CA cert + CA private key** (the *signer*), not a leaf.
Feed it a leaf and it errors out. `AMT_PublicKeyManagementService.AddKey` exists in the
WS-Man API but is never called from the UI — which is why `amt-tls.py` talks to the
firmware directly.

### `AddKey` wants PKCS#1, not PKCS#8

OpenSSL 3's `genrsa` emits `-----BEGIN PRIVATE KEY-----` (PKCS#8). AMT rejects it.
Convert:

```bash
openssl rsa -in device.key -traditional -outform DER
```

`amt-tls.py` does this for you.

### PKCS#12 must use legacy encryption for MeshCommander

MeshCommander parses `.p12` with node-forge, which supports neither AES nor PBKDF2.
OpenSSL 3 defaults to both. If you're producing a `.p12` for MeshCommander at all:

```bash
openssl pkcs12 -export ... -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
```

### Both TLSSettingData instances must be written

`Intel(r) AMT 802.3 TLS Settings` (remote) **and** `Intel(r) AMT LMS TLS Settings` (local).
Leave the LMS one accepting non-secure connections or you break local host tooling.

### Set the clock before enabling TLS

Intel's docs: *"Enabling TLS or Kerberos after configuration completion will not succeed
if the network time was not set."* If the firmware RTC is wrong, your certificate looks
not-yet-valid and TLS silently refuses to come up.

### Diagnosing "it didn't work"

```bash
nmap -Pn -p 16992,16993 <ip>
```

- `16993 filtered` → TLS was never committed. Did `CommitChanges` run?
- `16993 open`, handshake fails → TLS is on, cert/key material is wrong
- `16993 open`, cert served → check dates, SAN, and client-side trust

---

## License

MIT.
