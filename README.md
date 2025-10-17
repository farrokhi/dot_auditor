# DoT Auditor

A DNS-over-TLS (DoT) security audit tool that analyzes TLS certificates on DNS servers running on port 853.

## Overview

Given a CSV file containing IP addresses and their corresponding domain names, DoT Auditor performs comprehensive TLS certificate analysis for each DNS server. It intelligently maps IP addresses to nameserver hostnames and uses them as SNI (Server Name Indication) during the TLS handshake to retrieve and inspect certificates.

## Features

- **Smart SNI Selection**: Automatically resolves NS records and uses matching NS hostnames as SNI
- **Comprehensive Certificate Analysis**:
  - Common Names (CN) and Subject Alternative Names (SAN)
  - Certificate validity period and expiration status
  - Self-signed certificate detection
  - Chain of trust validation against system CA store
  - IP address presence in certificate SANs
- **Multiple Output Formats**: Verbose, Markdown table, or JSON
- **High Performance**: Concurrent processing with configurable worker threads
- **IPv4 and IPv6 Support**: Full dual-stack support

## Installation

### Requirements

- Python 3.10 or later
- dnspython library

### Install Dependencies

```bash
pip install dnspython
```

Or if using the virtual environment already set up:

```bash
source .venv/bin/activate
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
| `--format` | Output format: `verbose`, `markdown`, or `json` (default: `verbose`) |

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
 Self-signed: False
 Chains to system CA: True
 Connected IP listed in cert IP SANs: False
```

#### Markdown

Formatted as a table for documentation and reports:

```bash
python3 dot_auditor.py input.csv --format=markdown
```

| IP | Domain | SNI Used | Matching NS | TLS | Leaf Cert | Chain Trusted | Expired | Self-Signed | CN(s) | SAN DNS | SAN IPs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 45.55.10.200 | powerdns.com | pdns-public-ns2.powerdns.com | pdns-public-ns2.powerdns.com | ✅ | ✅ | ✅ | ❌ | ❌ | *.powerdns.com | *.powerdns.com, powerdns.com | - |

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
    "cn_list": ["*.powerdns.com"],
    "san_dns": ["*.powerdns.com", "powerdns.com"],
    "san_ips": [],
    "connected_ip_in_cert": false
  }
]
```

## How It Works

1. **DNS Discovery**: For each IP/domain pair, queries NS records and resolves each NS hostname
2. **Smart SNI Selection**: Finds which NS hostnames resolve to the target IP and uses the first match as SNI (or falls back to the domain name)
3. **TLS Handshake**: Connects to the IP on port 853 and performs two handshakes:
   - First with verification disabled to retrieve the certificate
   - Second with verification enabled to test CA chain trust
4. **Certificate Analysis**: Extracts and reports CN, SAN DNS/IP entries, validity dates, self-signed status, and CA trust

## Use Cases

- **Security Audits**: Verify DoT server certificate configurations across your infrastructure
- **Certificate Monitoring**: Identify expired or soon-to-expire certificates
- **Compliance Checking**: Ensure certificates meet security policies (no self-signed certs, valid CA chains)
- **DNS Privacy Infrastructure**: Validate proper TLS setup for DNS privacy services

## Examples

### Audit a list of public DNS servers

```bash
python3 dot_auditor.py public-dns-servers.csv --format=markdown > audit-report.md
```

### Check with custom timeout and port

```bash
python3 dot_auditor.py servers.csv --port=8853 --timeout=10.0 --workers=32
```

### Export results as JSON for further processing

```bash
python3 dot_auditor.py servers.csv --format=json > results.json
```

## License

This project is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.

## Author

**Babak Farrokhi**

Copyright (c) 2025, Babak Farrokhi
