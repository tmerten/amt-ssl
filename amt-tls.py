#!/usr/bin/env python3
"""
amt-tls.py — install an externally-generated TLS certificate into Intel AMT
             and enable TLS, over WS-Management. Tested against AMT 12.x / ACM.

Does what MeshCommander cannot: installs a certificate that carries a
subjectAltName, so browsers and modern TLS stacks will actually accept it.

Flow:
  1. sync the AMT clock          (AMT_TimeSynchronizationService)
  2. AddKey                      (your RSA private key, PKCS#1 DER)
  3. AddTrustedRootCertificate   (your CA root)
  4. AddCertificate              (the SAN leaf signed by your CA)
  5. AMT_TLSCredentialContext    (bind the leaf to the TLS endpoint)
  6. AMT_TLSSettingData          (enable TLS on remote + local interfaces)
  7. CommitChanges               (nothing takes effect without this)

Usage:
  ./amt-tls.py --host 192.168.15.11 --pass 'AMTpassw0rd!' \
               --key  ~/amt-ca/devices/box11.lan/box11.lan.key \
               --cert ~/amt-ca/devices/box11.lan/box11.lan.crt \
               --root ~/amt-ca/ca/amt-root-ca.crt

  # keep 16992 open while testing (default). Once verified:
  ./amt-tls.py ... --tls-only

  # see the SOAP without sending it:
  ./amt-tls.py ... --dry-run

  # undo (turn TLS back off, reopen 16992):
  ./amt-tls.py --host ... --pass ... --disable

Requires: requests   (pip install requests)
          openssl on PATH
"""

import argparse
import base64
import re
import subprocess
import sys
import time
import uuid

try:
    import requests
    from requests.auth import HTTPDigestAuth
except ImportError:
    sys.exit("need requests:  pip install requests")

AMT = "http://intel.com/wbem/wscim/1/amt-schema/1"
CIM = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2"
XFER = "http://schemas.xmlsoap.org/ws/2004/09/transfer"
ADDR = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
ANON = ADDR + "/role/anonymous"

R_PKM = f"{AMT}/AMT_PublicKeyManagementService"
R_CERT = f"{AMT}/AMT_PublicKeyCertificate"
R_CRED = f"{AMT}/AMT_TLSCredentialContext"
R_TLSD = f"{AMT}/AMT_TLSSettingData"
R_SETUP = f"{AMT}/AMT_SetupAndConfigurationService"
R_TIME = f"{AMT}/AMT_TimeSynchronizationService"
R_TLSEP = f"{AMT}/AMT_TLSProtocolEndpointCollection"
ENUM = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

ENV = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="{addr}" xmlns:w="{wsman}"
            xmlns:x="{xfer}" xmlns:r="{res}">
 <s:Header>
  <a:Action s:mustUnderstand="true">{action}</a:Action>
  <a:To s:mustUnderstand="true">{to}</a:To>
  <w:ResourceURI s:mustUnderstand="true">{res}</w:ResourceURI>
  <a:MessageID s:mustUnderstand="true">uuid:{mid}</a:MessageID>
  <a:ReplyTo><a:Address>{anon}</a:Address></a:ReplyTo>
  <w:OperationTimeout>PT60S</w:OperationTimeout>
  {selectors}
 </s:Header>
 <s:Body>{body}</s:Body>
</s:Envelope>"""


class Amt:
    def __init__(self, host, user, password, dry=False, verbose=False):
        self.url = f"http://{host}:16992/wsman"
        self.auth = HTTPDigestAuth(user, password)
        self.dry = dry
        self.verbose = verbose
        self.s = requests.Session()

    def _selectors(self, sel):
        if not sel:
            return ""
        items = "".join(
            f'<w:Selector Name="{k}">{v}</w:Selector>' for k, v in sel.items()
        )
        return f"<w:SelectorSet>{items}</w:SelectorSet>"

    def call(self, action, res, body="", sel=None):
        xml = ENV.format(
            addr=ADDR,
            wsman=WSMAN,
            xfer=XFER,
            anon=ANON,
            action=action,
            to=self.url,
            res=res,
            mid=uuid.uuid4(),
            selectors=self._selectors(sel),
            body=body,
        )
        if self.dry or self.verbose:
            print(f"\n--- POST {action}\n{xml}\n")
        if self.dry:
            return ""
        r = self.s.post(
            self.url,
            data=xml.encode(),
            headers={"Content-Type": "application/soap+xml;charset=UTF-8"},
            auth=self.auth,
            timeout=30,
        )
        if r.status_code == 401:
            raise SystemExit("401 — wrong AMT password, or digest auth rejected")
        if r.status_code != 200:
            raise SystemExit(f"HTTP {r.status_code}\n{r.text[:3000]}")
        if self.verbose:
            print(f"--- RESP\n{r.text}\n")
        fault = re.search(r"<[^>]*Reason>.*?<[^>]*Text[^>]*>(.*?)<", r.text, re.S)
        if fault:
            raise SystemExit(f"WSMAN fault: {fault.group(1).strip()}")
        return r.text

    def invoke(self, res, method, body_inner="", sel=None):
        body = f"<r:{method}_INPUT>{body_inner}</r:{method}_INPUT>"
        return self.call(f"{res}/{method}", res, body, sel)


def rv(xml, tag="ReturnValue"):
    m = re.search(rf"<[^>]*{tag}>(.*?)</", xml, re.S)
    return m.group(1).strip() if m else None


def instance_id(xml):
    """Pull the InstanceID selector out of a returned EPR."""
    m = re.search(r'Selector Name="InstanceID">(.*?)<', xml, re.S)
    return m.group(1).strip() if m else None


def b64_der(path, kind):
    """PEM -> base64 DER, stripped of headers."""
    if kind == "key":
        der = subprocess.run(
            ["openssl", "rsa", "-in", path, "-traditional", "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout  # AMT AddKey wants PKCS#1, NOT PKCS#8
    else:
        der = subprocess.run(
            ["openssl", "x509", "-in", path, "-outform", "DER"],
            capture_output=True,
            check=True,
        ).stdout
    return base64.b64encode(der).decode()


def epr(res, sel_name, sel_val):
    return (
        f"<a:Address>/wsman</a:Address>"
        f"<a:ReferenceParameters>"
        f"<w:ResourceURI>{res}</w:ResourceURI>"
        f'<w:SelectorSet><w:Selector Name="{sel_name}">{sel_val}</w:Selector></w:SelectorSet>'
        f"</a:ReferenceParameters>"
    )


def credential_context_exists(amt):
    """Enumerate AMT_TLSCredentialContext; True if an instance is already bound."""
    body = (
        f'<e:Enumerate xmlns:e="{ENUM}">'
        f"<w:OptimizeEnumeration/><w:MaxElements>999</w:MaxElements>"
        f"</e:Enumerate>"
    )
    x = amt.call(f"{ENUM}/Enumerate", R_CRED, body)
    return "ElementInContext" in x


def sync_clock(amt):
    print(">> syncing AMT clock")
    x = amt.invoke(
        R_TIME,
        "GetLowAccuracyTimeSynch",
        sel={"Name": "Intel(r) AMT Time Synchronization Service"},
    )
    if amt.dry:
        return
    ta0 = rv(x, "Ta0")
    now = int(time.time())
    amt.invoke(
        R_TIME,
        "SetHighAccuracyTimeSynch",
        f"<r:Ta0>{ta0}</r:Ta0><r:Tm1>{now}</r:Tm1><r:Tm2>{now}</r:Tm2>",
        sel={"Name": "Intel(r) AMT Time Synchronization Service"},
    )
    print("   clock set")


def set_tls(amt, enabled, accept_nonsecure):
    """Both instances must be written: the remote (802.3) and local (LMS) one."""
    for inst in ("Intel(r) AMT 802.3 TLS Settings", "Intel(r) AMT LMS TLS Settings"):
        # LMS interface: leave non-TLS reachable or you break local tooling.
        nonsecure = "true" if (accept_nonsecure or "LMS" in inst) else "false"
        body = (
            f'<r:AMT_TLSSettingData xmlns:r="{R_TLSD}">'
            f"<r:AcceptNonSecureConnections>{nonsecure}</r:AcceptNonSecureConnections>"
            f"<r:ElementName>Intel(r) AMT LMS TLS Settings</r:ElementName>"
            f"<r:Enabled>{'true' if enabled else 'false'}</r:Enabled>"
            f"<r:InstanceID>{inst}</r:InstanceID>"
            f"<r:MutualAuthentication>false</r:MutualAuthentication>"
            f"</r:AMT_TLSSettingData>"
        )
        body = body.replace(
            "<r:ElementName>Intel(r) AMT LMS TLS Settings</r:ElementName>",
            f"<r:ElementName>{inst}</r:ElementName>",
        )
        amt.call(f"{XFER}/Put", R_TLSD, body, sel={"InstanceID": inst})
        print(f"   {inst}: Enabled={enabled} AcceptNonSecure={nonsecure}")


def commit(amt):
    print(">> CommitChanges")
    amt.invoke(
        R_SETUP,
        "CommitChanges",
        sel={"Name": "Intel(r) AMT Setup and Configuration Service"},
    )
    print("   committed — AMT is rebuilding its network stack (~30s)")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="admin")
    p.add_argument("--pass", dest="password", required=True)
    p.add_argument("--key", help="device private key (PEM)")
    p.add_argument("--cert", help="device cert w/ SAN (PEM)")
    p.add_argument("--root", help="CA root cert (PEM)")
    p.add_argument(
        "--tls-only",
        action="store_true",
        help="close port 16992 (do this only after testing!)",
    )
    p.add_argument("--disable", action="store_true", help="turn TLS back off")
    p.add_argument("--skip-clock", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()

    amt = Amt(a.host, a.user, a.password, a.dry_run, a.verbose)

    if a.disable:
        print(f">> disabling TLS on {a.host}")
        set_tls(amt, enabled=False, accept_nonsecure=True)
        commit(amt)
        return

    if not (a.key and a.cert and a.root):
        p.error("--key, --cert and --root are required unless --disable")

    if not a.skip_clock:
        sync_clock(amt)

    print(">> AddKey (private key -> firmware)")
    amt.invoke(
        R_PKM,
        "AddKey",
        f"<r:KeyBlob>{b64_der(a.key, 'key')}</r:KeyBlob>",
        sel={"Name": "Intel(r) AMT Public Key Management Service"},
    )

    print(">> AddTrustedRootCertificate")
    amt.invoke(
        R_PKM,
        "AddTrustedRootCertificate",
        f"<r:CertificateBlob>{b64_der(a.root, 'cert')}</r:CertificateBlob>",
        sel={"Name": "Intel(r) AMT Public Key Management Service"},
    )

    print(">> AddCertificate (SAN leaf)")
    resp = amt.invoke(
        R_PKM,
        "AddCertificate",
        f"<r:CertificateBlob>{b64_der(a.cert, 'cert')}</r:CertificateBlob>",
        sel={"Name": "Intel(r) AMT Public Key Management Service"},
    )
    inst = instance_id(resp) or "DRY-RUN-INSTANCE"
    print(f"   installed as InstanceID={inst}")

    print(">> binding cert to the TLS endpoint (TLSCredentialContext)")
    # The CIM class fields are ElementInContext / ElementProvidingContext.
    # AMT wants a RELATIVE address (/wsman), not the absolute URL.
    body = (
        f'<r:AMT_TLSCredentialContext xmlns:r="{R_CRED}">'
        f"<r:ElementInContext>"
        f"{epr(R_CERT, 'InstanceID', inst)}"
        f"</r:ElementInContext>"
        f"<r:ElementProvidingContext>"
        f"{epr(R_TLSEP, 'ElementName', 'TLSProtocolEndpointInstances Collection')}"
        f"</r:ElementProvidingContext>"
        f"</r:AMT_TLSCredentialContext>"
    )
    # If a context already exists (e.g. left over from a previous TLS setup),
    # AMT rejects Create — you have to Put over the existing one.
    if credential_context_exists(amt):
        print("   existing context found -> Put (re-pointing it at the new cert)")
        amt.call(f"{XFER}/Put", R_CRED, body)
    else:
        print("   no existing context -> Create")
        amt.call(f"{XFER}/Create", R_CRED, body)

    print(">> enabling TLS")
    set_tls(amt, enabled=True, accept_nonsecure=not a.tls_only)
    commit(amt)

    print(f"\nverify with:")
    print(
        f"  openssl s_client -connect {a.host}:16993 -tls1_2 "
        f"-legacy_renegotiation -CAfile {a.root} </dev/null 2>&1 | grep 'Verify return'"
    )


if __name__ == "__main__":
    main()
