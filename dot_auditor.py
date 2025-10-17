#!/usr/bin/env python3
"""
DoT (DNS-over-TLS) Auditor - A security audit tool for DNS-over-TLS servers.

Analyzes TLS certificates on DNS servers running on port 853, performing
comprehensive certificate validation and reporting.

Copyright (c) 2025, Babak Farrokhi
All rights reserved.

SPDX-License-Identifier: BSD-2-Clause

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import argparse
import csv
import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import ssl
import sys
from datetime import datetime, timezone

import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import SubjectAlternativeName

DEFAULT_PORT = 853

# ---------------- Utilities ----------------
def is_ip(s: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def now_utc() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)

# ---------------- DNS helpers (with tiny caches) ----------------
_dns_ns_cache: dict[str, list[str]] = {}
_dns_addr_cache: dict[str, set[str]] = {}

def dns_get_ns(domain: str, timeout: float = 5.0) -> list[str]:
    """Query and cache NS records for a domain."""
    key = domain.lower()
    if key in _dns_ns_cache:
        return _dns_ns_cache[key]
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout  = timeout
    try:
        ans = r.resolve(domain, "NS")
        hosts = [str(rr.target).rstrip(".") for rr in ans]
        _dns_ns_cache[key] = hosts
        return hosts
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        _dns_ns_cache[key] = []
        return []

def dns_get_addrs(name: str, timeout: float = 5.0) -> set[str]:
    """Query and cache A/AAAA records for a hostname."""
    key = name.lower()
    if key in _dns_addr_cache:
        return _dns_addr_cache[key]
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    r.timeout  = timeout
    out = set()
    try:
        for rr in r.resolve(name, "A"):
            out.add(str(rr))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    try:
        for rr in r.resolve(name, "AAAA"):
            out.add(str(rr))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        pass
    _dns_addr_cache[key] = out
    return out

def find_matching_ns_for_ip(ip: str, domain: str, timeout: float = 5.0) -> list[str]:
    """Find which NS hostnames resolve to the given IP."""
    matches = []
    for ns in dns_get_ns(domain, timeout=timeout):
        if ip in dns_get_addrs(ns, timeout=timeout):
            matches.append(ns)
    return matches

# ---------------- TLS / cert helpers ----------------
def extract_cns(cert_dict: dict) -> list[str]:
    """Return all CommonName values from subject, de-duped."""
    cns = []
    for rdn in cert_dict.get("subject", ()):
        for attr in rdn:
            if isinstance(attr, (tuple, list)) and len(attr) >= 2:
                k, v = attr[0], attr[1]
                if str(k).lower() == "commonname":
                    if v not in cns:
                        cns.append(v)
    return cns

def names_from_cert(cert_dict: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (cn_list, san_dns_list, san_ip_list), all de-duped."""
    cn_list = extract_cns(cert_dict)
    dns_names, ip_addrs = [], []
    for entry in cert_dict.get("subjectAltName", ()):
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        k, v = entry[0], entry[1]
        if k == "DNS":
            if v not in dns_names:
                dns_names.append(v)
        elif k in ("IP Address", "IP"):
            if v not in ip_addrs:
                ip_addrs.append(v)
    # include CNs into DNS/IP buckets
    for cn in cn_list:
        if is_ip(cn):
            if cn not in ip_addrs:
                ip_addrs.append(cn)
        else:
            if cn not in dns_names:
                dns_names.append(cn)
    return cn_list, dns_names, ip_addrs

def parse_times(cert_dict: dict) -> tuple[datetime | None, datetime | None]:
    """Parse notBefore and notAfter from certificate dictionary."""
    fmt = "%b %d %H:%M:%S %Y %Z"  # e.g., 'Oct 16 12:34:56 2025 GMT'
    nb, na = cert_dict.get("notBefore"), cert_dict.get("notAfter")
    def _p(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return _p(nb), _p(na)

def subjects_equal(a: tuple, b: tuple) -> bool:
    """Check if two certificate subjects are equal."""
    return a == b

def extract_issuer_cn(cert_dict: dict) -> str | None:
    """
    Extract a readable issuer name from certificate.

    Tries to construct a meaningful issuer name by combining CN and O fields.
    For example: "E5" (CN) + "Let's Encrypt" (O) = "Let's Encrypt (E5)"
    """
    issuer = cert_dict.get("issuer")
    if not issuer:
        return None

    cn = None
    org = None

    for rdn in issuer:
        for attr in rdn:
            if isinstance(attr, (tuple, list)) and len(attr) >= 2:
                k, v = attr[0], attr[1]
                attr_name = str(k).lower()
                if attr_name == "commonname":
                    cn = v
                elif attr_name in ("organizationname", "organization"):
                    org = v

    # Construct a readable issuer name
    if org and cn:
        # If both exist, combine them
        return f"{org} ({cn})"
    if cn:
        # Just CN
        return cn
    if org:
        # Just organization
        return org

    return None

def der_cert_to_dict(der_bytes: bytes) -> dict:
    """
    Convert DER-encoded certificate to dict format similar to getpeercert().

    This allows us to parse self-signed certificates that fail SSL validation.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        result: dict = {}

        # Subject
        subject_attrs = []
        for attr in cert.subject:
            subject_attrs.append(((attr.oid._name, attr.value),))  # pylint: disable=protected-access
        result["subject"] = tuple(subject_attrs)

        # Issuer
        issuer_attrs = []
        for attr in cert.issuer:
            issuer_attrs.append(((attr.oid._name, attr.value),))  # pylint: disable=protected-access
        result["issuer"] = tuple(issuer_attrs)

        # Validity dates
        result["notBefore"] = cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT")
        result["notAfter"] = cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_value: SubjectAlternativeName = san_ext.value  # type: ignore[assignment]
            san_list = []
            for name in san_value:
                if isinstance(name, x509.DNSName):
                    san_list.append(("DNS", name.value))
                elif isinstance(name, x509.IPAddress):
                    san_list.append(("IP Address", str(name.value)))
            result["subjectAltName"] = tuple(san_list)
        except x509.ExtensionNotFound:
            pass

        return result
    except Exception:  # pylint: disable=broad-except
        return {}


def tls_handshake_to_ip(
    ip: str,
    port: int,
    sni: str | None,
    timeout: float = 5.0,
    verify: bool = False
) -> tuple[bool, dict | None, str | None, str | None]:
    """
    Connect to IP:port with TLS. Returns
    (ok, cert_dict_or_None, peer_ip_or_None, error_str_or_None).
    """
    if verify:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        # For non-verifying handshake, use default context with CERT_OPTIONAL
        # This retrieves the cert but doesn't strictly require validation to succeed
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

    try:
        infos = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, None, None, f"getaddrinfo failed: {e}"

    last_err: Exception | None = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            with socket.socket(family, socktype, proto) as raw:
                raw.settimeout(timeout)
                raw.connect(sockaddr)  # accepts IPv4 2-tuple and IPv6 4-tuple
                sni_host = sni if (sni and not is_ip(sni)) else None
                with ctx.wrap_socket(raw, server_hostname=sni_host) as tls:
                    cert = tls.getpeercert()
                    peer_ip = tls.getpeername()[0]
                    return True, cert, peer_ip, None
        except ssl.SSLCertVerificationError as e:
            # For non-verify mode, try to get DER cert from self-signed server
            if not verify:
                try:
                    with socket.socket(family, socktype, proto) as raw:
                        raw.settimeout(timeout)
                        raw.connect(sockaddr)
                        # Use CERT_NONE context to get certificate without validation
                        ctx_no_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx_no_verify.check_hostname = False
                        ctx_no_verify.verify_mode = ssl.CERT_NONE
                        sni_host = sni if (sni and not is_ip(sni)) else None
                        with ctx_no_verify.wrap_socket(raw, server_hostname=sni_host) as tls:
                            # Get binary DER certificate
                            der_cert = tls.getpeercert(binary_form=True)
                            peer_ip = tls.getpeername()[0]
                            if der_cert:
                                # Convert DER to dict format
                                cert_dict = der_cert_to_dict(der_cert)
                                if cert_dict:
                                    return True, cert_dict, peer_ip, None
                except Exception:  # pylint: disable=broad-except
                    pass
            last_err = e
            continue
        except (OSError, ssl.SSLError, TimeoutError) as e:
            last_err = e
            continue
    error_msg = f"{type(last_err).__name__}: {last_err}" if last_err else "connection failed"
    return False, None, None, error_msg

# ---------------- Per-row check ----------------
def check_row(ip: str, domain: str, port: int, timeout: float) -> dict:
    """
    Check TLS certificate for a single IP/domain pair.

    Returns a dict with all certificate information and validation results.
    """
    # 1) Which NS names resolve to this IP?
    matching_ns = find_matching_ns_for_ip(ip, domain, timeout=timeout)

    # 2) Choose SNI: first matching NS, else the domain (if not IP), else None.
    sni_used = matching_ns[0] if matching_ns else (domain if not is_ip(domain) else None)

    # 3) Do a non-verifying handshake to fetch the cert
    ok1, cert, peer_ip, err1 = tls_handshake_to_ip(
        ip, port, sni_used, timeout=timeout, verify=False
    )

    out = {
        "ip": ip,
        "domain": domain,
        "port": port,
        "matching_ns": matching_ns,
        "sni_used": sni_used,
        "tls_ok": ok1,
        "error_tls": None if ok1 else err1,
        "leaf_cert_received": bool(cert),
        "connected_ip": peer_ip,
        "not_before": None,
        "not_after": None,
        "is_expired": None,
        "is_self_signed": None,
        "issued_by_trusted_ca": None,
        "issuer_cn": None,
        "cn_list": [],
        "san_dns": [],
        "san_ips": [],
        "connected_ip_in_cert": None,
    }

    if not (ok1 and cert):
        return out

    # 4) Parse the certificate
    nb, na = parse_times(cert)
    out["not_before"] = nb.isoformat() if nb else None
    out["not_after"]  = na.isoformat() if na else None
    out["is_expired"] = (na is not None and now_utc() > na)

    subj, issuer = cert.get("subject"), cert.get("issuer")
    out["is_self_signed"] = (subjects_equal(subj, issuer) if subj and issuer else None)
    out["issuer_cn"] = extract_issuer_cn(cert)

    cns, san_dns, san_ips = names_from_cert(cert)
    out["cn_list"] = cns
    out["san_dns"] = san_dns
    out["san_ips"] = san_ips
    if peer_ip:
        out["connected_ip_in_cert"] = peer_ip in set(san_ips)

    # 5) Verify chain to OS trust (same SNI)
    ok2, _, _, _ = tls_handshake_to_ip(
        ip, port, sni_used, timeout=timeout, verify=True
    )
    out["issued_by_trusted_ca"] = bool(ok2)
    # (We're not doing hostname matching—this is pure chain trust.)

    return out

# ---------------- Output Formatters ----------------
def format_verbose(results: list[dict]) -> str:
    """Format results as human-readable verbose output."""
    output = []
    for r in results:
        output.append(f"=== {r['ip']} ({r['domain']}) :{r['port']} ===")
        ns_list = ', '.join(r['matching_ns']) if r['matching_ns'] else 'none'
        output.append(f" Matching NS hostname(s): {ns_list}")
        output.append(f" SNI used: {r['sni_used'] or 'None'}")
        tls_status = 'OK' if r['tls_ok'] else f"FAIL ({r['error_tls']})"
        output.append(f" TLS: {tls_status}")
        output.append(f" Leaf certificate received: {'yes' if r['leaf_cert_received'] else 'no'}")

        if r["cn_list"]:
            output.append(" CN(s):")
            for cn in r["cn_list"]:
                output.append(f"   - {cn}")

        if r["san_dns"]:
            output.append(" SAN DNS:")
            for d in r["san_dns"]:
                output.append(f"   - {d}")

        if r["san_ips"]:
            output.append(" SAN IPs:")
            for ip in r["san_ips"]:
                output.append(f"   - {ip}")

        if r["not_before"] or r["not_after"]:
            validity_line = (
                f" Validity: {r['not_before'] or '-'} -> {r['not_after'] or '-'} "
                f"(expired: {r['is_expired']})"
            )
            output.append(validity_line)

        if r["issuer_cn"]:
            output.append(f" Issued by: {r['issuer_cn']}")

        if r["is_self_signed"] is not None:
            output.append(f" Self-signed: {r['is_self_signed']}")

        if r["issued_by_trusted_ca"] is not None:
            output.append(f" Chains to system CA: {r['issued_by_trusted_ca']}")

        if r["connected_ip_in_cert"] is not None:
            output.append(f" Connected IP listed in cert IP SANs: {r['connected_ip_in_cert']}")

        output.append("")

    return "\n".join(output)

def format_markdown(results: list[dict]) -> str:
    """Format results as a Markdown table."""
    output = []
    headers = [
        "IP", "Domain", "SNI Used", "Matching NS",
        "TLS", "Leaf Cert", "Chain Trusted", "Expired",
        "Self-Signed", "Issued By", "CN(s)", "SAN DNS", "SAN IPs"
    ]
    output.append("| " + " | ".join(headers) + " |")
    output.append("|" + "|".join(["---"] * len(headers)) + "|")

    for r in results:
        row = [
            f"`{r['ip']}`",
            f"`{r['domain']}`",
            f"`{r['sni_used']}`" if r["sni_used"] else "-",
            ", ".join(f"`{ns}`" for ns in r["matching_ns"]) if r["matching_ns"] else "-",
            "✅" if r["tls_ok"] else "❌",
            "✅" if r["leaf_cert_received"] else "❌",
            ("✅" if r["issued_by_trusted_ca"] else "❌"
             if r["issued_by_trusted_ca"] is not None else "-"),
            ("❌" if r["is_expired"] else "✅"
             if r["is_expired"] is not None else "-"),
            ("Yes" if r["is_self_signed"] else "No"
             if r["is_self_signed"] is not None else "-"),
            f"`{r['issuer_cn']}`" if r["issuer_cn"] else "-",
            ", ".join(f"`{cn}`" for cn in r["cn_list"]) if r["cn_list"] else "-",
            ", ".join(f"`{dns}`" for dns in r["san_dns"]) if r["san_dns"] else "-",
            ", ".join(f"`{ip}`" for ip in r["san_ips"]) if r["san_ips"] else "-",
        ]
        output.append("| " + " | ".join(row) + " |")

    return "\n".join(output)

def format_json(results: list[dict]) -> str:
    """Format results as JSON."""
    return json.dumps(results, indent=2)

def format_html(results: list[dict], title: str = "DoT Audit Report") -> str:
    """Format results as HTML table with inline CSS."""
    # CSS styles (inline to match sample)
    css = """
    /* Default styles provided by pandoc.
    ** See https://pandoc.org/MANUAL.html#variables for config info.
    */
    code{white-space: pre-wrap;}
    span.smallcaps{font-variant: small-caps;}
    div.columns{display: flex; gap: min(4vw, 1.5em);}
    div.column{flex: auto; overflow-x: auto;}
    div.hanging-indent{margin-left: 1.5em; text-indent: -1.5em;}
    /* The extra [class] is a hack that increases specificity enough to
       override a similar rule in reveal.js */
    ul.task-list[class]{list-style: none;}
    ul.task-list li input[type="checkbox"] {
      font-size: inherit;
      width: 0.8em;
      margin: 0 0.8em 0.2em -1.6em;
      vertical-align: middle;
    }
    .display.math{display: block; text-align: center; margin: 0.5rem auto;}
    /* Table styles */
    table {
      border-collapse: separate;
      border-spacing: 0 8px;
      width: 100%;
      font-family: Arial, sans-serif;
      font-size: 14px;
      color: #333;
    }
    thead th {
      background-color: #f5f5f5;
      font-weight: 600;
      text-align: left;
      padding: 8px 12px;
      border-bottom: 2px solid #ccc;
    }
    tbody td {
      background-color: #fff;
      padding: 8px 12px;
      border-top: 1px solid #ddd;
      vertical-align: middle;
    }
    tbody tr:hover td {
      background-color: #f0f8ff;
    }
    code {
      font-family: Consolas, monospace;
      background-color: #eee;
      padding: 2px 4px;
      border-radius: 3px;
    }
    """

    output = []
    output.append('<!DOCTYPE html>')
    output.append('<html xmlns="http://www.w3.org/1999/xhtml" lang="" xml:lang="">')
    output.append('<head>')
    output.append('  <meta charset="utf-8" />')
    output.append('  <meta name="generator" content="DoT Auditor" />')
    output.append('  <meta name="viewport" content="width=device-width, '
                  'initial-scale=1.0, user-scalable=yes" />')
    output.append(f'  <title>{title}</title>')
    output.append('  <style>')
    output.append(css)
    output.append('  </style>')
    output.append('</head>')
    output.append('<body>')
    output.append('<p>Generated with <a href="https://github.com/farrokhi/dot_auditor">'
                  'DoT Auditor</a></p>')
    output.append('<table style="width:100%;">')

    # Column groups (13 columns, ~7% each)
    output.append('<colgroup>')
    for _ in range(13):
        output.append('<col style="width: 7%" />')
    output.append('</colgroup>')

    # Table headers
    output.append('<thead>')
    output.append('<tr>')
    headers = [
        "IP", "Domain", "SNI Used", "Matching NS",
        "TLS", "Leaf Cert", "Chain Trusted", "Expired",
        "Self-Signed", "Issued By", "CN(s)", "SAN DNS", "SAN IPs"
    ]
    for header in headers:
        output.append(f'<th>{header}</th>')
    output.append('</tr>')
    output.append('</thead>')

    # Table body
    output.append('<tbody>')
    for r in results:
        output.append('<tr>')

        # IP and Domain with code tags
        output.append(f'<td><code>{r["ip"]}</code></td>')
        output.append(f'<td><code>{r["domain"]}</code></td>')

        # SNI Used
        if r["sni_used"]:
            output.append(f'<td><code>{r["sni_used"]}</code></td>')
        else:
            output.append('<td>-</td>')

        # Matching NS
        if r["matching_ns"]:
            ns_list = ", ".join(f'<code>{ns}</code>' for ns in r["matching_ns"])
            output.append(f'<td>{ns_list}</td>')
        else:
            output.append('<td>-</td>')

        # TLS status
        output.append(f'<td>{"✅" if r["tls_ok"] else "❌"}</td>')

        # Leaf Cert
        output.append(f'<td>{"✅" if r["leaf_cert_received"] else "❌"}</td>')

        # Chain Trusted
        if r["issued_by_trusted_ca"] is not None:
            output.append(f'<td>{"✅" if r["issued_by_trusted_ca"] else "❌"}</td>')
        else:
            output.append('<td>-</td>')

        # Expired
        if r["is_expired"] is not None:
            output.append(f'<td>{"❌" if r["is_expired"] else "✅"}</td>')
        else:
            output.append('<td>-</td>')

        # Self-Signed
        if r["is_self_signed"] is not None:
            output.append(f'<td>{"Yes" if r["is_self_signed"] else "No"}</td>')
        else:
            output.append('<td>-</td>')

        # Issued By
        if r["issuer_cn"]:
            output.append(f'<td><code>{r["issuer_cn"]}</code></td>')
        else:
            output.append('<td>-</td>')

        # CN(s)
        if r["cn_list"]:
            cn_list = ", ".join(f'<code>{cn}</code>' for cn in r["cn_list"])
            output.append(f'<td>{cn_list}</td>')
        else:
            output.append('<td>-</td>')

        # SAN DNS
        if r["san_dns"]:
            dns_list = ", ".join(f'<code>{dns}</code>' for dns in r["san_dns"])
            output.append(f'<td>{dns_list}</td>')
        else:
            output.append('<td>-</td>')

        # SAN IPs
        if r["san_ips"]:
            ip_list = ", ".join(f'<code>{ip}</code>' for ip in r["san_ips"])
            output.append(f'<td>{ip_list}</td>')
        else:
            output.append('<td>-</td>')

        output.append('</tr>')

    output.append('</tbody>')
    output.append('</table>')
    output.append('</body>')
    output.append('</html>')

    return "\n".join(output)

# ---------------- CLI ----------------
def main() -> None:
    """Main entry point for the DoT Auditor CLI."""
    ap = argparse.ArgumentParser(
        description=(
            "Check DoT (TLS/853) servers from CSV, "
            "map IP->NS hostname, and use it as SNI."
        )
    )
    ap.add_argument("csv_file", help="CSV with at least two columns: IP,domain.")
    ap.add_argument(
        "--has-header", action="store_true", default=False,
        help="Skip first CSV row as header."
    )
    ap.add_argument("--delimiter", default=",", help="CSV delimiter (default: ,)")
    ap.add_argument(
        "--ip-col", type=int, default=0,
        help="Zero-based IP column index (default: 0)"
    )
    ap.add_argument(
        "--domain-col", type=int, default=1,
        help="Zero-based domain column index (default: 1)"
    )
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to check (default: 853)")
    ap.add_argument("--timeout", type=float, default=5.0, help="Per-connection and DNS timeout (s)")
    ap.add_argument("--workers", type=int, default=64, help="Concurrency (default: 64)")
    ap.add_argument(
        "--format", dest="output_format",
        choices=["verbose", "markdown", "json", "html"],
        default="verbose",
        help="Output format: verbose, markdown, json, or html (default: verbose)"
    )
    ap.add_argument(
        "-o", "--output", dest="output_file",
        type=str, default=None,
        help="Output file path (default: stdout)"
    )
    args = ap.parse_args()

    # Validate arguments
    if args.port < 1 or args.port > 65535:
        print("Error: Port must be between 1 and 65535", file=sys.stderr)
        sys.exit(1)

    if args.timeout <= 0:
        print("Error: Timeout must be positive", file=sys.stderr)
        sys.exit(1)

    if args.workers < 1:
        print("Error: Workers must be at least 1", file=sys.stderr)
        sys.exit(1)

    if args.ip_col < 0 or args.domain_col < 0:
        print("Error: Column indices must be non-negative", file=sys.stderr)
        sys.exit(1)

    # Read CSV rows
    rows = []
    try:
        with open(args.csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=args.delimiter)
            for i, row in enumerate(reader):
                if not row or len(row) <= max(args.ip_col, args.domain_col):
                    continue
                if i == 0 and args.has_header:
                    continue
                ip_txt = row[args.ip_col].strip()
                dom    = row[args.domain_col].strip().rstrip(".")
                if not ip_txt or not dom:
                    continue
                try:
                    ip_norm = str(ipaddress.ip_address(ip_txt))
                except ValueError:
                    print(f"Warning: Invalid IP address '{ip_txt}' on line {i+1}, skipping",
                          file=sys.stderr)
                    continue
                rows.append((ip_norm, dom))
    except FileNotFoundError:
        print(f"Error: File '{args.csv_file}' not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading '{args.csv_file}'", file=sys.stderr)
        sys.exit(1)
    except csv.Error as e:
        print(f"Error: CSV parsing error: {e}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("Error: No valid IP/domain pairs found in CSV file", file=sys.stderr)
        sys.exit(1)

    # Process
    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(check_row, ip, dom, args.port, args.timeout) for (ip, dom) in rows]
        for fut in cf.as_completed(futs):
            results.append(fut.result())

    # Preserve CSV order
    order = { (ip, dom): i for i, (ip, dom) in enumerate(rows) }
    results.sort(key=lambda r: order.get((r["ip"], r["domain"]), 0))

    # Format and output results
    # Extract filename without extension for HTML title
    csv_basename = os.path.basename(args.csv_file)
    csv_name = os.path.splitext(csv_basename)[0]

    if args.output_format == "html":
        output = format_html(results, title=f"DoT Audit Report: {csv_name}")
    elif args.output_format == "markdown":
        output = format_markdown(results)
    elif args.output_format == "json":
        output = format_json(results)
    else:  # verbose
        output = format_verbose(results)

    # Write output to file or stdout
    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Output written to {args.output_file}", file=sys.stderr)
        except OSError as e:
            print(f"Error writing to file {args.output_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output)

if __name__ == "__main__":
    main()
