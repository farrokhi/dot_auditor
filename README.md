# DoT Auditor

[![CI](https://github.com/Quad9DNS/dot_auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/Quad9DNS/dot_auditor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Quad9DNS/dot_auditor/branch/main/graph/badge.svg)](https://codecov.io/gh/Quad9DNS/dot_auditor)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A tool for auditing TLS certificates on DNS-over-TLS servers.

## Overview

Analyzes TLS certificates on DoT servers (port 853). Resolves NS records for each domain, uses them as SNI during TLS handshake, and extracts certificate information.

## Features

- Automatic SNI selection from NS records
- Certificate analysis (CN, SAN, validity, chain trust, issuer)
- Multiple output formats (verbose, markdown, JSON, HTML)
- Self-signed and expired certificate detection with visual highlighting
- Interactive HTML reports with DataTables (sorting, filtering, search)
- Per-column filtering in HTML output
- Concurrent processing with configurable workers
- Detailed certificate validation and chain trust verification

## Installation

Requires Python 3.10 or later.

```bash
pip install dnspython cryptography
```

## Usage

### Basic Usage

```bash
python3 dot_auditor.py input.csv
```

### Input Format

The CSV file should contain at least two columns: IP address and domain name.

Example `input.csv`:
```csv
45.55.10.200,powerdns.com
206.189.140.177,technitium.com
2604:a880:1:20::132:5001,powerdns.com
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `csv_file` | CSV file with IP and domain columns (required) |
| `--has-header` | Skip the first CSV row as header |
| `--delimiter` | CSV delimiter (default: `,`) |
| `--ip-col` | Zero-based index of the IP column (default: `0`) |
| `--domain-col` | Zero-based index of the domain column (default: `1`) |
| `--port` | Port to check (default: `853`) |
| `--timeout` | Timeout for DNS and TLS operations in seconds (default: `5.0`) |
| `--workers` | Number of concurrent checks (default: `64`) |
| `--format` | Output format: `verbose`, `markdown`, `json`, or `html` (default: `verbose`) |
| `-o`, `--output` | Output file path (default: stdout) |

### Output Formats

#### Verbose (Default)

Detailed human-readable output with all certificate information:

```bash
python3 dot_auditor.py input.csv --format=verbose
```

```
=== 45.55.10.200 (powerdns.com) :853 ===
 Matching NS hostname(s): pdns-public-ns2.powerdns.com
 SNI used: pdns-public-ns2.powerdns.com
 TLS: OK
 Leaf certificate received: yes
 CN(s):
   - *.powerdns.com
 SAN DNS:
   - *.powerdns.com
   - powerdns.com
 Validity: 2025-01-15T12:00:00+00:00 -> 2026-01-15T12:00:00+00:00 (expired: False)
 Issued by: Let's Encrypt (R12)
 Self-signed: False
 Chains to system CA: True
 Connected IP listed in cert IP SANs: False
```

#### Markdown

Formatted as a table for documentation and reports:

```bash
python3 dot_auditor.py input.csv --format=markdown
```

| IP | Domain | SNI Used | Matching NS | TLS | Leaf Cert | Chain Trusted | Expired | Self-Signed | Issued By | CN(s) | SAN DNS | SAN IPs |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `45.55.10.200` | `powerdns.com` | `pdns-public-ns2.powerdns.com` | `pdns-public-ns2.powerdns.com` | ✅ | ✅ | ✅ | NO | NO | `Let's Encrypt (R12)` | `*.powerdns.com` | `*.powerdns.com`, `powerdns.com` | - |

#### JSON

Machine-readable structured output for automation:

```bash
python3 dot_auditor.py input.csv --format=json
```

```json
[
  {
    "ip": "45.55.10.200",
    "domain": "powerdns.com",
    "port": 853,
    "matching_ns": ["pdns-public-ns2.powerdns.com"],
    "sni_used": "pdns-public-ns2.powerdns.com",
    "tls_ok": true,
    "error_tls": null,
    "leaf_cert_received": true,
    "connected_ip": "45.55.10.200",
    "not_before": "2025-01-15T12:00:00+00:00",
    "not_after": "2026-01-15T12:00:00+00:00",
    "is_expired": false,
    "is_self_signed": false,
    "issued_by_trusted_ca": true,
    "issuer_cn": "Let's Encrypt (R12)",
    "cn_list": ["*.powerdns.com"],
    "san_dns": ["*.powerdns.com", "powerdns.com"],
    "san_ips": [],
    "connected_ip_in_cert": false
  }
]
```

#### HTML

Interactive HTML reports with DataTables integration for advanced filtering and sorting:

```bash
python3 dot_auditor.py input.csv --format=html -o report.html
```

Features:
- **Sortable columns**: Click any column header to sort
- **Global search**: Filter across all columns at once
- **Per-column filtering**: Individual search boxes for each column
- **Pagination**: Navigate through large datasets (50 entries per page)
- **Visual highlighting**: Expired and self-signed certificates shown in red
- **Generation timestamp**: UTC timestamp displayed at bottom of report
- **Responsive design**: Works on desktop and mobile browsers

The HTML output uses monospace fonts for technical data (IPs, domains, hostnames) and includes all certificate details in a clean, professional format.

Interactive features powered by [DataTables](https://datatables.net/) - a powerful jQuery plugin for enhanced HTML tables.

## How It Works

1. Query NS records for the domain
2. Resolve NS hostnames to find which matches the target IP
3. Use matching NS hostname as SNI during TLS handshake
4. Retrieve certificate and validate against system CA store
5. Extract certificate details (CN, SAN, validity, chain trust)

## Use Cases

- Audit DoT server certificate configurations
- Monitor certificate expiration
- Verify certificate chain trust
- Check for self-signed certificates

## Examples

### Audit a list of public DNS servers

```bash
python3 dot_auditor.py public-dns-servers.csv --format=markdown -o audit-report.md
```

### Check with custom timeout and port

```bash
python3 dot_auditor.py servers.csv --port=8853 --timeout=10.0 --workers=32
```

### Export results as JSON for further processing

```bash
python3 dot_auditor.py servers.csv --format=json -o results.json
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and contribution guidelines.

## Dependencies

This project relies on the following excellent open-source libraries:

- **[dnspython](https://www.dnspython.org/)** - DNS toolkit for Python
- **[cryptography](https://cryptography.io/)** - Cryptographic recipes and primitives
- **[DataTables](https://datatables.net/)** - jQuery plugin for interactive HTML tables (used in HTML output)

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

**Babak Farrokhi**

Copyright (c) 2025, Babak Farrokhi
