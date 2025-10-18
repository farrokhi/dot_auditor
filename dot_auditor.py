#!/usr/bin/env python3
"""
DoT (DNS-over-TLS) Auditor - A security audit tool for DNS-over-TLS servers.

Analyzes TLS certificates on DNS servers running on port 853, performing
comprehensive certificate validation and reporting.

Copyright (c) 2025, Babak Farrokhi
All rights reserved.

SPDX-License-Identifier: BSD-2-Clause
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

_dns_ns_cache: dict[str, list[str]] = {}
_dns_addr_cache: dict[str, set[str]] = {}


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


def dns_get_ns(domain: str, timeout: float = 5.0) -> list[str]:
    """Query and cache NS records for a domain."""
    key = domain.lower()
    if key in _dns_ns_cache:
        return _dns_ns_cache[key]

    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = timeout
    try:
        ans = r.resolve(domain, "NS")
        _dns_ns_cache[key] = [str(rr.target).rstrip(".") for rr in ans]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        _dns_ns_cache[key] = []
    return _dns_ns_cache[key]


def dns_get_addrs(name: str, timeout: float = 5.0) -> set[str]:
    """Query and cache A/AAAA records for a hostname."""
    key = name.lower()
    if key in _dns_addr_cache:
        return _dns_addr_cache[key]

    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = timeout
    out = set()
    for rtype in ("A", "AAAA"):
        try:
            out.update(str(rr) for rr in r.resolve(name, rtype))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            pass
    _dns_addr_cache[key] = out
    return out


def find_matching_ns_for_ip(ip: str, domain: str, timeout: float = 5.0) -> list[str]:
    """Find which NS hostnames resolve to the given IP."""
    return [
        ns for ns in dns_get_ns(domain, timeout) if ip in dns_get_addrs(ns, timeout)
    ]


def extract_cns(cert_dict: dict) -> list[str]:
    """Return all CommonName values from subject, de-duped."""
    cns = []
    for rdn in cert_dict.get("subject", ()):
        for attr in rdn:
            if (
                isinstance(attr, (tuple, list))
                and len(attr) >= 2
                and str(attr[0]).lower() == "commonname"
            ):
                if attr[1] not in cns:
                    cns.append(attr[1])
    return cns


def names_from_cert(cert_dict: dict) -> tuple[list[str], list[str], list[str]]:
    """Return (cn_list, san_dns_list, san_ip_list), all de-duped."""
    cn_list = extract_cns(cert_dict)
    dns_names, ip_addrs = [], []

    for entry in cert_dict.get("subjectAltName", ()):
        if not isinstance(entry, (tuple, list)) or len(entry) < 2:
            continue
        k, v = entry[0], entry[1]
        if k == "DNS" and v not in dns_names:
            dns_names.append(v)
        elif k in ("IP Address", "IP") and v not in ip_addrs:
            ip_addrs.append(v)

    for cn in cn_list:
        target = ip_addrs if is_ip(cn) else dns_names
        if cn not in target:
            target.append(cn)

    return cn_list, dns_names, ip_addrs


def parse_times(cert_dict: dict) -> tuple[datetime | None, datetime | None]:
    """Parse notBefore and notAfter from certificate dictionary."""
    fmt = "%b %d %H:%M:%S %Y %Z"

    def parse(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    return parse(cert_dict.get("notBefore")), parse(cert_dict.get("notAfter"))


def extract_issuer_cn(cert_dict: dict) -> str | None:
    """Extract a readable issuer name from certificate."""
    issuer = cert_dict.get("issuer")
    if not issuer:
        return None

    cn = org = None
    for rdn in issuer:
        for attr in rdn:
            if isinstance(attr, (tuple, list)) and len(attr) >= 2:
                attr_name = str(attr[0]).lower()
                if attr_name == "commonname":
                    cn = attr[1]
                elif attr_name in ("organizationname", "organization"):
                    org = attr[1]

    if org and cn:
        return f"{org} ({cn})"
    return cn or org


def der_cert_to_dict(der_bytes: bytes) -> dict:
    """Convert DER-encoded certificate to dict format similar to getpeercert()."""
    try:
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        result = {
            "subject": tuple(((attr.oid._name, attr.value),) for attr in cert.subject),
            "issuer": tuple(((attr.oid._name, attr.value),) for attr in cert.issuer),
            "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        }

        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_value: SubjectAlternativeName = san_ext.value
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
    except Exception:
        return {}


def tls_handshake_to_ip(
    ip: str, port: int, sni: str | None, timeout: float = 5.0, verify: bool = False
) -> tuple[bool, dict | None, str | None, str | None]:
    """Connect to IP:port with TLS. Returns (ok, cert_dict, peer_ip, error_msg)."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_OPTIONAL

    try:
        infos = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as e:
        return False, None, None, f"getaddrinfo failed: {e}"

    last_err: Exception | None = None
    for family, socktype, proto, _, sockaddr in infos:
        try:
            with socket.socket(family, socktype, proto) as raw:
                raw.settimeout(timeout)
                raw.connect(sockaddr)
                sni_host = sni if (sni and not is_ip(sni)) else None
                with ctx.wrap_socket(raw, server_hostname=sni_host) as tls:
                    return True, tls.getpeercert(), tls.getpeername()[0], None
        except ssl.SSLCertVerificationError as e:
            if not verify:
                try:
                    with socket.socket(family, socktype, proto) as raw:
                        raw.settimeout(timeout)
                        raw.connect(sockaddr)
                        ctx_no_verify = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx_no_verify.check_hostname = False
                        ctx_no_verify.verify_mode = ssl.CERT_NONE
                        sni_host = sni if (sni and not is_ip(sni)) else None
                        with ctx_no_verify.wrap_socket(
                            raw, server_hostname=sni_host
                        ) as tls:
                            der_cert = tls.getpeercert(binary_form=True)
                            peer_ip = tls.getpeername()[0]
                            if der_cert and (cert_dict := der_cert_to_dict(der_cert)):
                                return True, cert_dict, peer_ip, None
                except Exception:
                    pass
            last_err = e
        except (OSError, ssl.SSLError, TimeoutError) as e:
            last_err = e

    error_msg = (
        f"{type(last_err).__name__}: {last_err}" if last_err else "connection failed"
    )
    return False, None, None, error_msg


def check_row(ip: str, domain: str, port: int, timeout: float) -> dict:
    """Check TLS certificate for a single IP/domain pair."""
    matching_ns = find_matching_ns_for_ip(ip, domain, timeout)
    sni_used = (
        matching_ns[0] if matching_ns else (domain if not is_ip(domain) else None)
    )
    ok1, cert, peer_ip, err1 = tls_handshake_to_ip(
        ip, port, sni_used, timeout, verify=False
    )

    out = {
        "ip": ip,
        "domain": domain,
        "port": port,
        "matching_ns": matching_ns,
        "sni_used": sni_used,
        "tls_ok": ok1,
        "error_tls": err1 if not ok1 else None,
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

    nb, na = parse_times(cert)
    out["not_before"] = nb.isoformat() if nb else None
    out["not_after"] = na.isoformat() if na else None
    out["is_expired"] = na is not None and now_utc() > na

    subj, issuer = cert.get("subject"), cert.get("issuer")
    out["is_self_signed"] = (subj == issuer) if (subj and issuer) else None
    out["issuer_cn"] = extract_issuer_cn(cert)

    cns, san_dns, san_ips = names_from_cert(cert)
    out["cn_list"], out["san_dns"], out["san_ips"] = cns, san_dns, san_ips
    if peer_ip:
        out["connected_ip_in_cert"] = peer_ip in set(san_ips)

    ok2, _, _, _ = tls_handshake_to_ip(ip, port, sni_used, timeout, verify=True)
    out["issued_by_trusted_ca"] = bool(ok2)

    return out


def format_verbose(results: list[dict]) -> str:
    """Format results as human-readable verbose output."""
    output = []
    for r in results:
        output.append(f"=== {r['ip']} ({r['domain']}) :{r['port']} ===")
        output.append(
            f" Matching NS hostname(s): {', '.join(r['matching_ns']) or 'none'}"
        )
        output.append(f" SNI used: {r['sni_used'] or 'None'}")
        output.append(f" TLS: {'OK' if r['tls_ok'] else f'FAIL ({r['error_tls']})'}")
        output.append(
            f" Leaf certificate received: {'yes' if r['leaf_cert_received'] else 'no'}"
        )

        for key, label in [
            ("cn_list", "CN(s)"),
            ("san_dns", "SAN DNS"),
            ("san_ips", "SAN IPs"),
        ]:
            if r[key]:
                output.append(f" {label}:")
                output.extend(f"   - {item}" for item in r[key])

        if r["not_before"] or r["not_after"]:
            output.append(
                f" Validity: {r['not_before'] or '-'} -> {r['not_after'] or '-'} (expired: {r['is_expired']})"
            )

        if r["issuer_cn"]:
            output.append(f" Issued by: {r['issuer_cn']}")
        if r["is_self_signed"] is not None:
            output.append(f" Self-signed: {r['is_self_signed']}")
        if r["issued_by_trusted_ca"] is not None:
            output.append(f" Chains to system CA: {r['issued_by_trusted_ca']}")
        if r["connected_ip_in_cert"] is not None:
            output.append(
                f" Connected IP listed in cert IP SANs: {r['connected_ip_in_cert']}"
            )
        output.append("")

    return "\n".join(output)


def format_markdown(results: list[dict]) -> str:
    """Format results as a Markdown table."""
    headers = [
        "IP",
        "Domain",
        "SNI Used",
        "Matching NS",
        "TLS",
        "Leaf Cert",
        "Chain Trusted",
        "IP in Cert",
        "Expired",
        "Self-Signed",
        "Issued By",
        "CN(s)",
        "SAN DNS",
        "SAN IPs",
    ]

    output = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["---"] * len(headers)) + "|",
    ]

    for r in results:
        row = [
            f"`{r['ip']}`",
            f"`{r['domain']}`",
            f"`{r['sni_used']}`" if r["sni_used"] else "-",
            (
                ", ".join(f"`{ns}`" for ns in r["matching_ns"])
                if r["matching_ns"]
                else "-"
            ),
            "✅" if r["tls_ok"] else "❌",
            "✅" if r["leaf_cert_received"] else "❌",
            (
                "✅"
                if r["issued_by_trusted_ca"]
                else "❌" if r["issued_by_trusted_ca"] is not None else "-"
            ),
            (
                "YES"
                if r["connected_ip_in_cert"]
                else "NO" if r["connected_ip_in_cert"] is not None else "-"
            ),
            "YES" if r["is_expired"] else "NO" if r["is_expired"] is not None else "-",
            (
                "YES"
                if r["is_self_signed"]
                else "NO" if r["is_self_signed"] is not None else "-"
            ),
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
    """Format results as HTML table with DataTables for sorting and filtering."""
    timestamp = now_utc().isoformat().replace("+00:00", "")

    css = """
    body { margin: 0; padding: 10px; font-family: Arial, sans-serif; }
    td.monospace { font-family: Consolas, monospace; background-color: #f9f9f9; }
    table.dataTable { font-size: 14px; color: #333; }
    table.dataTable thead th { background-color: #f5f5f5; font-weight: 600; position: relative; cursor: help; }
    table.dataTable tbody td { vertical-align: middle; }
    table.dataTable tfoot th { background-color: #e8e8e8; padding: 8px 12px; }
    table.dataTable tfoot input { padding: 4px 6px; font-size: 13px; border: 1px solid #ccc; border-radius: 3px; }
    table.dataTable tfoot input:focus { outline: none; border-color: #4a90e2; box-shadow: 0 0 3px rgba(74, 144, 226, 0.5); }
    .legend { margin-top: 30px; padding: 20px; background-color: #f9f9f9; border-radius: 5px; }
    .legend h3 { margin-top: 0; color: #333; }
    .legend dl { margin: 0; }
    .legend dt { font-weight: bold; margin-top: 10px; color: #555; }
    .legend dd { margin-left: 20px; color: #666; }
    """

    # Headers with tooltips (header_text, tooltip_description)
    headers_with_tooltips = [
        ("IP", "IP address being audited"),
        ("Domain", "Domain name associated with the IP"),
        ("SNI Used", "Server Name Indication used in TLS handshake"),
        ("Matching NS", "NS hostnames that resolve to this IP"),
        ("TLS", "TLS connection successful"),
        ("Leaf Cert", "Leaf certificate received from server"),
        ("Chain Trusted", "Certificate chain validates against system CA store"),
        ("IP in Cert", "Connected IP address is listed in certificate's SAN IPs"),
        ("Expired", "Certificate has expired"),
        ("Self-Signed", "Certificate is self-signed"),
        ("Issued By", "Certificate issuer (CA organization and CN)"),
        ("CN(s)", "Common Name(s) from certificate subject"),
        ("SAN DNS", "DNS names from Subject Alternative Name extension"),
        ("SAN IPs", "IP addresses from Subject Alternative Name extension"),
    ]

    headers = [h[0] for h in headers_with_tooltips]

    output = [
        "<!DOCTYPE html>",
        '<html xmlns="http://www.w3.org/1999/xhtml" lang="" xml:lang="">',
        "<head>",
        '  <meta charset="utf-8" />',
        '  <meta name="generator" content="DoT Auditor" />',
        '  <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes" />',
        f"  <title>{title}</title>",
        '  <link rel="stylesheet" href="https://cdn.datatables.net/2.1.8/css/dataTables.dataTables.min.css" />',
        f"  <style>{css}</style>",
        "</head>",
        "<body>",
        f"<h1>{title}</h1>",
        '<table id="auditTable" class="display" style="width:100%;">',
        "<thead><tr>" + "".join(f'<th title="{desc}">{name}</th>' for name, desc in headers_with_tooltips) + "</tr></thead>",
        "<tfoot><tr>"
        + "".join(
            f'<th><input type="text" placeholder="Filter {h}" style="width:100%; box-sizing:border-box;" /></th>'
            for h in headers
        )
        + "</tr></tfoot>",
        "<tbody>",
    ]

    for r in results:
        cells = [
            f'<td class="monospace">{r["ip"]}</td>',
            f'<td class="monospace">{r["domain"]}</td>',
            (
                f'<td class="monospace">{r["sni_used"]}</td>'
                if r["sni_used"]
                else "<td>-</td>"
            ),
            (
                f'<td class="monospace">{", ".join(r["matching_ns"])}</td>'
                if r["matching_ns"]
                else "<td>-</td>"
            ),
            f'<td>{"✅" if r["tls_ok"] else "❌"}</td>',
            f'<td>{"✅" if r["leaf_cert_received"] else "❌"}</td>',
            (
                f'<td>{"✅" if r["issued_by_trusted_ca"] else "❌"}</td>'
                if r["issued_by_trusted_ca"] is not None
                else "<td>-</td>"
            ),
            (
                "<td>YES</td>"
                if r["connected_ip_in_cert"]
                else "<td>NO</td>" if r["connected_ip_in_cert"] is not None else "<td>-</td>"
            ),
            (
                '<td><span style="color: red; font-weight: bold;">YES</span></td>'
                if r["is_expired"]
                else "<td>NO</td>" if r["is_expired"] is not None else "<td>-</td>"
            ),
            (
                '<td><span style="color: red; font-weight: bold;">YES</span></td>'
                if r["is_self_signed"]
                else "<td>NO</td>" if r["is_self_signed"] is not None else "<td>-</td>"
            ),
            (
                f'<td class="monospace">{r["issuer_cn"]}</td>'
                if r["issuer_cn"]
                else "<td>-</td>"
            ),
            (
                f'<td class="monospace">{", ".join(r["cn_list"])}</td>'
                if r["cn_list"]
                else "<td>-</td>"
            ),
            (
                f'<td class="monospace">{", ".join(r["san_dns"])}</td>'
                if r["san_dns"]
                else "<td>-</td>"
            ),
            (
                f'<td class="monospace">{", ".join(r["san_ips"])}</td>'
                if r["san_ips"]
                else "<td>-</td>"
            ),
        ]
        output.append("<tr>" + "".join(cells) + "</tr>")

    output.extend(
        [
            "</tbody>",
            "</table>",
            '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>',
            '<script src="https://cdn.datatables.net/2.1.8/js/dataTables.min.js"></script>',
            "<script>",
            "$(document).ready(function() {",
            '  var table = $("#auditTable").DataTable({',
            '    "pageLength": 50,',
            '    "order": [[0, "asc"]],',
            '    "columnDefs": [{ "orderable": true, "targets": "_all" }],',
            '    "dom": "lfrtip<\\"bottom-info\\">",',
            '    "language": {',
            '      "search": "Filter records:",',
            '      "lengthMenu": "Show _MENU_ entries per page",',
            '      "info": "Showing _START_ to _END_ of _TOTAL_ servers"',
            "    },",
            '    "drawCallback": function() {',
            f'      $(".bottom-info").html(\'<div style="text-align: center; margin-top: 20px; color: #666;">Generated with <a href="https://github.com/Quad9DNS/dot_auditor">DoT Auditor</a> at {timestamp} UTC</div>\');',
            "    },",
            '    "initComplete": function() {',
            "      this.api().columns().every(function() {",
            "        var column = this;",
            "        $('input', this.footer()).on('keyup change clear', function() {",
            "          if (column.search() !== this.value) {",
            "            column.search(this.value).draw();",
            "          }",
            "        });",
            "      });",
            "    }",
            "  });",
            "});",
            "</script>",
            '<div class="legend">',
            "  <h3>Column Descriptions</h3>",
            "  <dl>",
        ]
    )

    # Add legend entries
    for name, desc in headers_with_tooltips:
        output.extend([f"    <dt>{name}</dt>", f"    <dd>{desc}</dd>"])

    output.extend(["  </dl>", "</div>", "</body>", "</html>"])

    return "\n".join(output)


def main() -> None:
    """Main entry point for the DoT Auditor CLI."""
    ap = argparse.ArgumentParser(
        description="Check DoT (TLS/853) servers from CSV, map IP->NS hostname, and use it as SNI."
    )
    ap.add_argument("csv_file", help="CSV with at least two columns: IP,domain.")
    ap.add_argument(
        "--has-header", action="store_true", help="Skip first CSV row as header."
    )
    ap.add_argument("--delimiter", default=",", help="CSV delimiter (default: ,)")
    ap.add_argument(
        "--ip-col", type=int, default=0, help="Zero-based IP column index (default: 0)"
    )
    ap.add_argument(
        "--domain-col",
        type=int,
        default=1,
        help="Zero-based domain column index (default: 1)",
    )
    ap.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help="Port to check (default: 853)"
    )
    ap.add_argument(
        "--timeout", type=float, default=5.0, help="Per-connection and DNS timeout (s)"
    )
    ap.add_argument("--workers", type=int, default=64, help="Concurrency (default: 64)")
    ap.add_argument(
        "--format",
        dest="output_format",
        choices=["verbose", "markdown", "json", "html"],
        default="verbose",
        help="Output format (default: verbose)",
    )
    ap.add_argument(
        "-o", "--output", dest="output_file", help="Output file path (default: stdout)"
    )
    args = ap.parse_args()

    if not (1 <= args.port <= 65535):
        sys.exit("Error: Port must be between 1 and 65535")
    if args.timeout <= 0:
        sys.exit("Error: Timeout must be positive")
    if args.workers < 1:
        sys.exit("Error: Workers must be at least 1")
    if args.ip_col < 0 or args.domain_col < 0:
        sys.exit("Error: Column indices must be non-negative")

    rows = []
    try:
        with open(args.csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f, delimiter=args.delimiter)
            for i, row in enumerate(reader):
                if not row or len(row) <= max(args.ip_col, args.domain_col):
                    continue
                if i == 0 and args.has_header:
                    continue
                ip_txt, dom = row[args.ip_col].strip(), row[
                    args.domain_col
                ].strip().rstrip(".")
                if not ip_txt or not dom:
                    continue
                try:
                    rows.append((str(ipaddress.ip_address(ip_txt)), dom))
                except ValueError:
                    print(
                        f"Warning: Invalid IP address '{ip_txt}' on line {i+1}, skipping",
                        file=sys.stderr,
                    )
    except FileNotFoundError:
        sys.exit(f"Error: File '{args.csv_file}' not found")
    except PermissionError:
        sys.exit(f"Error: Permission denied reading '{args.csv_file}'")
    except csv.Error as e:
        sys.exit(f"Error: CSV parsing error: {e}")

    if not rows:
        sys.exit("Error: No valid IP/domain pairs found in CSV file")

    results = []
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [
            ex.submit(check_row, ip, dom, args.port, args.timeout) for ip, dom in rows
        ]
        results = [fut.result() for fut in cf.as_completed(futs)]

    order = {(ip, dom): i for i, (ip, dom) in enumerate(rows)}
    results.sort(key=lambda r: order.get((r["ip"], r["domain"]), 0))

    csv_name = os.path.splitext(os.path.basename(args.csv_file))[0]
    formatters = {
        "html": lambda: format_html(results, title=f"DoT Audit Report: {csv_name}"),
        "markdown": lambda: format_markdown(results),
        "json": lambda: format_json(results),
        "verbose": lambda: format_verbose(results),
    }
    output = formatters[args.output_format]()

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"Output written to {args.output_file}", file=sys.stderr)
        except OSError as e:
            sys.exit(f"Error writing to file {args.output_file}: {e}")
    else:
        print(output)


if __name__ == "__main__":
    main()
