"""
CyberShield Tests
=================
"""

import pytest
from cybershield.phishing import PhishingDetector
from cybershield.vuln_scanner import VulnerabilityScanner


class TestPhishingDetector:
    """Tests for phishing detection module."""

    def setup_method(self):
        self.detector = PhishingDetector()

    def test_safe_url(self):
        result = self.detector.analyze_url("https://google.com")
        assert result["risk_level"] in ["SAFE", "LOW"]
        assert result["is_phishing"] is False

    def test_suspicious_url(self):
        result = self.detector.analyze_url("http://paypal-login.secure.verify.com")
        assert result["risk_score"] > 0

    def test_ip_address_url(self):
        result = self.detector.analyze_url("http://192.168.1.1/login")
        assert result["risk_score"] > 0

    def test_suspicious_tld(self):
        result = self.detector.analyze_url("https://malicious.tk")
        assert result["risk_score"] > 0

    def test_long_url(self):
        long_url = "https://example.com/" + "a" * 100
        result = self.detector.analyze_url(long_url)
        assert result["risk_score"] > 0

    def test_batch_scan(self):
        urls = ["https://google.com", "https://github.com"]
        results = self.detector.batch_scan(urls)
        assert len(results) == 2


class TestVulnerabilityScanner:
    """Tests for vulnerability scanner module."""

    def setup_method(self):
        self.scanner = VulnerabilityScanner()

    def test_quick_scan(self):
        results = self.scanner.quick_scan("https://example.com")
        assert isinstance(results, list)

    def test_security_headers_check(self):
        findings = self.scanner._check_security_headers("https://example.com")
        assert isinstance(findings, list)

    def test_information_disclosure(self):
        findings = self.scanner._check_information_disclosure("https://example.com")
        assert isinstance(findings, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
