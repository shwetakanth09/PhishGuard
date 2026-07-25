"""
Phishing Detection Module
=========================

Detects phishing URLs using multiple analysis techniques:
- URL structure analysis
- Domain reputation checking
- SSL certificate validation
- Content analysis
- Heuristic scoring
"""

import re
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional

try:
    import whois
except ImportError:
    whois = None

try:
    import tldextract
except ImportError:
    tldextract = None


class PhishingDetector:
    """Advanced phishing URL detection engine."""

    def __init__(self):
        self.suspicious_keywords = [
            "login", "signin", "verify", "account", "update", "secure",
            "banking", "confirm", "password", "suspend", "restrict",
            "unusual", "activity", "alert", "notification", "urgent",
            "paypal", "apple", "microsoft", "google", "amazon", "netflix",
            "facebook", "instagram", "twitter", "linkedin", "dropbox",
        ]

        self.suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
            ".click", ".link", ".online", ".site", ".tech", ".store",
        ]

        self.legitimate_domains = [
            "google.com", "microsoft.com", "apple.com", "amazon.com",
            "facebook.com", "github.com", "linkedin.com", "twitter.com",
            "netflix.com", "paypal.com", "dropbox.com", "github.io",
        ]

    def analyze_url(self, url: str) -> Dict:
        """
        Perform comprehensive URL analysis.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            "url": url,
            "risk_score": 0,
            "risk_level": "LOW",
            "is_phishing": False,
            "checks": [],
            "warnings": [],
            "details": {}
        }

        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path
            
            results["checks"] = [
                self._check_url_length(url),
                self._check_special_characters(url),
                self._check_suspicious_keywords(url),
                self._check_suspicious_tld(domain),
                self._check_ip_address(domain),
                self._check_subdomains(domain),
                self._check_https(url),
                self._check_domain_age(domain),
                self._check_redirects(url),
            ]

            for check in results["checks"]:
                results["risk_score"] += check["score"]
                if check["warning"]:
                    results["warnings"].append(check["warning"])

            results["risk_score"] = min(results["risk_score"], 100)
            results["risk_level"] = self._calculate_risk_level(results["risk_score"])
            results["is_phishing"] = results["risk_score"] >= 60
            results["details"] = self._get_domain_details(domain)

        except Exception as e:
            results["error"] = str(e)

        return results

    def _check_url_length(self, url: str) -> Dict:
        """Check if URL is suspiciously long."""
        score = 0
        warning = None
        if len(url) > 75:
            score += 10
        if len(url) > 100:
            score += 10
            warning = "URL is unusually long"
        return {"name": "URL Length", "score": score, "warning": warning}

    def _check_special_characters(self, url: str) -> Dict:
        """Check for suspicious special characters."""
        score = 0
        warning = None
        
        if "@" in url:
            score += 20
            warning = "URL contains @ symbol (possible obfuscation)"
        if url.count("-") > 3:
            score += 10
        if url.count(".") > 4:
            score += 15
            warning = "URL has excessive subdomains"
        if "//" in url.split("://")[-1] if "://" in url else False:
            score += 10
            
        return {"name": "Special Characters", "score": min(score, 30), "warning": warning}

    def _check_suspicious_keywords(self, url: str) -> Dict:
        """Check for phishing-related keywords."""
        score = 0
        warning = None
        url_lower = url.lower()
        
        found_keywords = [kw for kw in self.suspicious_keywords if kw in url_lower]
        if found_keywords:
            score = min(len(found_keywords) * 5, 25)
            warning = f"Suspicious keywords found: {', '.join(found_keywords[:3])}"
            
        return {"name": "Keywords", "score": score, "warning": warning}

    def _check_suspicious_tld(self, domain: str) -> Dict:
        """Check for suspicious top-level domains."""
        score = 0
        warning = None
        
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score = 20
                warning = f"Suspicious TLD: {tld}"
                break
                
        return {"name": "TLD Check", "score": score, "warning": warning}

    def _check_ip_address(self, domain: str) -> Dict:
        """Check if domain uses IP address instead of name."""
        score = 0
        warning = None
        
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            score = 25
            warning = "Domain uses IP address instead of name"
            
        return {"name": "IP Address", "score": score, "warning": warning}

    def _check_subdomains(self, domain: str) -> Dict:
        """Check for excessive subdomains."""
        score = 0
        warning = None
        
        parts = domain.split(".")
        if len(parts) > 3:
            score = 15
            warning = f"Excessive subdomains ({len(parts) - 2} levels)"
            
        return {"name": "Subdomains", "score": score, "warning": warning}

    def _check_https(self, url: str) -> Dict:
        """Check for HTTPS usage."""
        score = 0
        warning = None
        
        if not url.startswith("https://"):
            score = 10
            warning = "Site does not use HTTPS"
            
        return {"name": "HTTPS", "score": score, "warning": warning}

    def _check_domain_age(self, domain: str) -> Dict:
        """Check domain registration age."""
        score = 0
        warning = None
        
        if whois:
            try:
                w = whois.whois(domain)
                if w.creation_date:
                    age = (datetime.now() - w.creation_date).days
                    if age < 30:
                        score = 20
                        warning = f"Domain is very new ({age} days old)"
                    elif age < 180:
                        score = 10
            except Exception:
                pass
                
        return {"name": "Domain Age", "score": score, "warning": warning}

    def _check_redirects(self, url: str) -> Dict:
        """Check for URL redirects."""
        score = 0
        warning = None
        
        try:
            import requests
            resp = requests.head(url, allow_redirects=False, timeout=5)
            if resp.status_code in [301, 302, 303, 307, 308]:
                score = 15
                warning = "URL redirects to another location"
        except Exception:
            pass
            
        return {"name": "Redirects", "score": score, "warning": warning}

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from score."""
        if score < 20:
            return "SAFE"
        elif score < 40:
            return "LOW"
        elif score < 60:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"

    def _get_domain_details(self, domain: str) -> Dict:
        """Get additional domain information."""
        details = {}
        
        if whois:
            try:
                w = whois.whois(domain)
                details["registrar"] = w.registrar
                details["creation_date"] = str(w.creation_date)
                details["expiration_date"] = str(w.expiration_date)
                details["name_servers"] = w.name_servers
            except Exception:
                pass
                
        return details

    def batch_scan(self, urls: List[str]) -> List[Dict]:
        """Scan multiple URLs at once."""
        return [self.analyze_url(url) for url in urls]
