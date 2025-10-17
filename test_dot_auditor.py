"""
Unit tests for DoT Auditor.

Copyright (c) 2025, Babak Farrokhi
SPDX-License-Identifier: BSD-2-Clause
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import dot_auditor


class TestUtilities:
    """Test utility functions."""

    def test_is_ip_valid_ipv4(self):
        """Test is_ip with valid IPv4 address."""
        assert dot_auditor.is_ip("192.168.1.1") is True
        assert dot_auditor.is_ip("8.8.8.8") is True

    def test_is_ip_valid_ipv6(self):
        """Test is_ip with valid IPv6 address."""
        assert dot_auditor.is_ip("2001:4860:4860::8888") is True
        assert dot_auditor.is_ip("::1") is True

    def test_is_ip_invalid(self):
        """Test is_ip with invalid IP addresses."""
        assert dot_auditor.is_ip("not-an-ip") is False
        assert dot_auditor.is_ip("999.999.999.999") is False
        assert dot_auditor.is_ip("") is False

    def test_now_utc(self):
        """Test now_utc returns datetime with UTC timezone."""
        result = dot_auditor.now_utc()
        assert isinstance(result, datetime)
        assert result.tzinfo == timezone.utc


class TestCertHelpers:
    """Test certificate helper functions."""

    def test_extract_cns_empty(self):
        """Test extract_cns with empty cert."""
        cert = {}
        assert dot_auditor.extract_cns(cert) == []

    def test_extract_cns_single_cn(self):
        """Test extract_cns with single CommonName."""
        cert = {
            "subject": (
                (("commonName", "example.com"),),
            )
        }
        assert dot_auditor.extract_cns(cert) == ["example.com"]

    def test_extract_cns_multiple_cn(self):
        """Test extract_cns with multiple CommonNames (de-duped)."""
        cert = {
            "subject": (
                (("commonName", "example.com"),),
                (("commonName", "example.com"),),  # duplicate
                (("commonName", "test.com"),),
            )
        }
        result = dot_auditor.extract_cns(cert)
        assert "example.com" in result
        assert "test.com" in result
        assert len(result) == 2  # de-duped

    def test_names_from_cert_with_san(self):
        """Test names_from_cert with SAN entries."""
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "subjectAltName": (
                ("DNS", "www.example.com"),
                ("DNS", "mail.example.com"),
                ("IP Address", "192.168.1.1"),
            )
        }
        cn_list, san_dns, san_ips = dot_auditor.names_from_cert(cert)

        assert "example.com" in cn_list
        assert "example.com" in san_dns  # CN added to DNS list
        assert "www.example.com" in san_dns
        assert "mail.example.com" in san_dns
        assert "192.168.1.1" in san_ips

    def test_parse_times_valid(self):
        """Test parse_times with valid dates."""
        cert = {
            "notBefore": "Jan 1 00:00:00 2025 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT"
        }
        nb, na = dot_auditor.parse_times(cert)

        assert isinstance(nb, datetime)
        assert isinstance(na, datetime)
        assert nb.year == 2025
        assert na.year == 2025
        assert nb.tzinfo == timezone.utc

    def test_parse_times_invalid(self):
        """Test parse_times with invalid/missing dates."""
        cert = {
            "notBefore": "invalid date",
            "notAfter": None
        }
        nb, na = dot_auditor.parse_times(cert)

        assert nb is None
        assert na is None

    def test_subjects_equal(self):
        """Test subjects_equal function."""
        subj1 = (("CN", "example.com"),)
        subj2 = (("CN", "example.com"),)
        subj3 = (("CN", "different.com"),)

        assert dot_auditor.subjects_equal(subj1, subj2) is True
        assert dot_auditor.subjects_equal(subj1, subj3) is False


class TestDNSHelpers:
    """Test DNS helper functions."""

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_ns_success(self, mock_resolver_class):
        """Test dns_get_ns with successful response."""
        # Clear cache before test
        dot_auditor._dns_ns_cache.clear()

        # Mock the resolver
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # Mock DNS response
        mock_rr = MagicMock()
        mock_rr.target = "ns1.example.com."
        mock_resolver.resolve.return_value = [mock_rr]

        result = dot_auditor.dns_get_ns("example.com")

        assert result == ["ns1.example.com"]
        assert "example.com" in dot_auditor._dns_ns_cache

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_ns_cached(self, mock_resolver_class):
        """Test dns_get_ns returns cached result."""
        # Set cache
        dot_auditor._dns_ns_cache["test.com"] = ["cached.ns.com"]

        result = dot_auditor.dns_get_ns("test.com")

        assert result == ["cached.ns.com"]
        # Resolver should not be called for cached result
        mock_resolver_class.assert_not_called()

    @patch('dot_auditor.dns.resolver.Resolver')
    def test_dns_get_addrs_success(self, mock_resolver_class):
        """Test dns_get_addrs with successful A/AAAA responses."""
        # Clear cache before test
        dot_auditor._dns_addr_cache.clear()

        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        # Mock A record
        mock_a = MagicMock()
        mock_a.__str__ = lambda self: "192.168.1.1"

        # Mock AAAA record
        mock_aaaa = MagicMock()
        mock_aaaa.__str__ = lambda self: "2001:db8::1"

        mock_resolver.resolve.side_effect = [
            [mock_a],  # A record response
            [mock_aaaa]  # AAAA record response
        ]

        result = dot_auditor.dns_get_addrs("example.com")

        assert "192.168.1.1" in result
        assert "2001:db8::1" in result


class TestFormatters:
    """Test output formatter functions."""

    def test_format_verbose(self):
        """Test verbose formatter."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "port": 853,
            "matching_ns": ["ns1.example.com"],
            "sni_used": "ns1.example.com",
            "tls_ok": True,
            "error_tls": None,
            "leaf_cert_received": True,
            "cn_list": ["example.com"],
            "san_dns": ["www.example.com"],
            "san_ips": ["192.168.1.100"],
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",
            "is_expired": False,
            "is_self_signed": False,
            "issued_by_trusted_ca": True,
            "connected_ip_in_cert": False,
        }]

        output = dot_auditor.format_verbose(results)

        assert "192.168.1.1" in output
        assert "example.com" in output
        assert "ns1.example.com" in output
        assert "www.example.com" in output
        assert "192.168.1.100" in output
        assert "TLS: OK" in output

    def test_format_markdown(self):
        """Test markdown formatter with backticks for IPs and hostnames."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "port": 853,
            "matching_ns": ["ns1.example.com"],
            "sni_used": "ns1.example.com",
            "tls_ok": True,
            "error_tls": None,
            "leaf_cert_received": True,
            "cn_list": ["*.example.com"],
            "san_dns": ["*.example.com", "example.com"],
            "san_ips": ["192.168.1.100"],
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",
            "is_expired": False,
            "is_self_signed": False,
            "issued_by_trusted_ca": True,
            "connected_ip_in_cert": False,
        }]

        output = dot_auditor.format_markdown(results)

        assert "|" in output
        assert "IP" in output
        assert "Domain" in output
        assert "`192.168.1.1`" in output
        assert "`example.com`" in output
        assert "`ns1.example.com`" in output
        assert "`*.example.com`" in output
        assert "`192.168.1.100`" in output
        assert "✅" in output  # Successful TLS

    def test_format_json(self):
        """Test JSON formatter."""
        results = [{
            "ip": "192.168.1.1",
            "domain": "example.com",
            "tls_ok": True,
        }]

        output = dot_auditor.format_json(results)

        assert '"ip": "192.168.1.1"' in output
        assert '"domain": "example.com"' in output
        assert '"tls_ok": true' in output


class TestIntegration:
    """Integration tests."""

    def test_check_row_structure(self):
        """Test that check_row returns properly structured dict."""
        with patch('dot_auditor.find_matching_ns_for_ip', return_value=[]):
            with patch('dot_auditor.tls_handshake_to_ip',
                      return_value=(False, None, None, "timeout")):
                result = dot_auditor.check_row("192.168.1.1", "example.com", 853, 5.0)

                # Verify all expected keys are present
                expected_keys = {
                    "ip", "domain", "port", "matching_ns", "sni_used",
                    "tls_ok", "error_tls", "leaf_cert_received",
                    "connected_ip", "not_before", "not_after",
                    "is_expired", "is_self_signed", "issued_by_trusted_ca",
                    "cn_list", "san_dns", "san_ips", "connected_ip_in_cert"
                }

                assert set(result.keys()) == expected_keys
                assert result["ip"] == "192.168.1.1"
                assert result["domain"] == "example.com"
                assert result["tls_ok"] is False


class TestInputValidation:
    """Test input validation and error handling."""

    def test_invalid_port_low(self, capsys):
        """Test port validation with value too low."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--port=0']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Port must be between 1 and 65535" in captured.err

    def test_invalid_port_high(self, capsys):
        """Test port validation with value too high."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--port=65536']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Port must be between 1 and 65535" in captured.err

    def test_invalid_timeout_zero(self, capsys):
        """Test timeout validation with zero value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--timeout=0']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Timeout must be positive" in captured.err

    def test_invalid_timeout_negative(self, capsys):
        """Test timeout validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--timeout=-1']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Timeout must be positive" in captured.err

    def test_invalid_workers_zero(self, capsys):
        """Test workers validation with zero value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--workers=0']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Workers must be at least 1" in captured.err

    def test_invalid_workers_negative(self, capsys):
        """Test workers validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--workers=-1']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Workers must be at least 1" in captured.err

    def test_invalid_ip_column(self, capsys):
        """Test IP column validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--ip-col=-1']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Column indices must be non-negative" in captured.err

    def test_invalid_domain_column(self, capsys):
        """Test domain column validation with negative value."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', 'test.csv', '--domain-col=-1']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Column indices must be non-negative" in captured.err

    def test_file_not_found(self, capsys):
        """Test handling of non-existent CSV file."""
        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', '/nonexistent/file.csv']):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "File" in captured.err
        assert "not found" in captured.err

    def test_empty_csv(self, tmp_path, capsys):
        """Test handling of empty CSV file."""
        empty_file = tmp_path / "empty.csv"
        empty_file.write_text("")

        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', str(empty_file)]):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "No valid IP/domain pairs found" in captured.err

    def test_invalid_ip_warning(self, tmp_path, capsys):
        """Test warning for invalid IP addresses in CSV."""
        csv_file = tmp_path / "invalid_ip.csv"
        csv_file.write_text("invalid-ip,example.com\n")

        with pytest.raises(SystemExit) as exc:
            with patch('sys.argv', ['dot_auditor.py', str(csv_file)]):
                dot_auditor.main()

        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "Invalid IP address" in captured.err
        assert "No valid IP/domain pairs found" in captured.err
