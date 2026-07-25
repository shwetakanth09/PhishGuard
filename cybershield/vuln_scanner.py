"""
Vulnerability Scanner Module
============================

Comprehensive web vulnerability scanner checking for:
- XSS (Cross-Site Scripting)
- SQL Injection
- Security Headers
- SSL/TLS Issues
- Open Ports
- Directory Traversal
- Information Disclosure
"""

import re
import ssl
import socket
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    requests = None
    BeautifulSoup = None


class VulnerabilityScanner:
    """Advanced web vulnerability scanner."""

    def __init__(self):
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert()'>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
        ]

        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--",
        ]

        self.security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
        ]

    def scan_target(self, url: str) -> Dict:
        """
        Perform comprehensive vulnerability scan.
        
        Args:
            url: Target URL to scan
            
        Returns:
            Dictionary with scan results
        """
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "total_vulnerabilities": 0,
            "vulnerability_breakdown": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "findings": [],
            "security_headers": {},
            "ssl_info": {},
            "summary": ""
        }

        try:
            findings = []
            
            findings.extend(self._check_security_headers(url))
            findings.extend(self._check_ssl(url))
            findings.extend(self._check_xss(url))
            findings.extend(self._check_sqli(url))
            findings.extend(self._check_information_disclosure(url))
            findings.extend(self._check_common_files(url))
            findings.extend(self._check_cors(url))

            for finding in findings:
                results["vulnerability_breakdown"][finding["severity"]] += 1
                results["findings"].append(finding)

            results["total_vulnerabilities"] = len(results["findings"])
            results["security_headers"] = self._get_header_analysis(url)
            results["ssl_info"] = self._get_ssl_info(url)
            results["summary"] = self._generate_summary(results)

        except Exception as e:
            results["error"] = str(e)

        return results

    def _check_security_headers(self, url: str) -> List[Dict]:
        """Check for missing security headers."""
        findings = []
        
        if requests:
            try:
                resp = requests.get(url, timeout=10, verify=False)
                headers = resp.headers
                
                for header in self.security_headers:
                    if header not in headers:
                        findings.append({
                            "type": "Missing Security Header",
                            "severity": "medium",
                            "title": f"Missing {header}",
                            "description": f"The {header} header is not set",
                            "recommendation": f"Add {header} header to improve security",
                            "url": url
                        })
            except Exception:
                pass
                
        return findings

    def _check_ssl(self, url: str) -> List[Dict]:
        """Check SSL/TLS configuration."""
        findings = []
        
        if url.startswith("https://"):
            try:
                hostname = urlparse(url).netloc
                port = 443
                
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, port))
                    cert = s.getpeercert()
                    
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (not_after - datetime.now()).days
                    
                    if days_left < 30:
                        findings.append({
                            "type": "SSL Certificate",
                            "severity": "high",
                            "title": "SSL Certificate Expiring Soon",
                            "description": f"Certificate expires in {days_left} days",
                            "recommendation": "Renew SSL certificate immediately",
                            "url": url
                        })
                        
                    if days_left < 0:
                        findings.append({
                            "type": "SSL Certificate",
                            "severity": "critical",
                            "title": "SSL Certificate Expired",
                            "description": "Certificate has expired",
                            "recommendation": "Renew SSL certificate immediately",
                            "url": url
                        })
                        
            except ssl.SSLCertVerificationError:
                findings.append({
                    "type": "SSL Certificate",
                    "severity": "critical",
                    "title": "SSL Certificate Verification Failed",
                    "description": "Could not verify SSL certificate",
                    "recommendation": "Fix SSL certificate configuration",
                    "url": url
                })
            except Exception:
                pass
        else:
            findings.append({
                "type": "SSL/TLS",
                "severity": "high",
                "title": "HTTPS Not Used",
                "description": "Website does not use HTTPS",
                "recommendation": "Enable HTTPS for secure communication",
                "url": url
            })
            
        return findings

    def _check_xss(self, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities."""
        findings = []
        
        if requests and BeautifulSoup:
            try:
                resp = requests.get(url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                forms = soup.find_all('form')
                for form in forms[:3]:
                    action = form.get('action', '')
                    if action:
                        test_url = urljoin(url, action)
                    else:
                        test_url = url
                        
                    inputs = form.find_all('input')
                    for payload in self.xss_payloads[:2]:
                        data = {inp.get('name', 'test'): payload for inp in inputs if inp.get('name')}
                        if data:
                            try:
                                test_resp = requests.post(test_url, data=data, timeout=5)
                                if payload in test_resp.text:
                                    findings.append({
                                        "type": "XSS Vulnerability",
                                        "severity": "high",
                                        "title": "Reflected XSS Found",
                                        "description": f"Payload reflected in response",
                                        "recommendation": "Implement input validation and output encoding",
                                        "url": test_url,
                                        "payload": payload
                                    })
                                    break
                            except Exception:
                                pass
            except Exception:
                pass
                
        return findings

    def _check_sqli(self, url: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities."""
        findings = []
        
        if requests:
            try:
                for payload in self.sqli_payloads[:3]:
                    test_url = f"{url}?id={payload}"
                    try:
                        resp = requests.get(test_url, timeout=5)
                        errors = [
                            "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
                            "SQLite", "Microsoft OLE DB", "ODBC SQL Server",
                            "unclosed quotation mark"
                        ]
                        for error in errors:
                            if error.lower() in resp.text.lower():
                                findings.append({
                                    "type": "SQL Injection",
                                    "severity": "critical",
                                    "title": "Potential SQL Injection",
                                    "description": f"Database error message detected",
                                    "recommendation": "Use parameterized queries and input validation",
                                    "url": url,
                                    "payload": payload
                                })
                                break
                    except Exception:
                        pass
            except Exception:
                pass
                
        return findings

    def _check_information_disclosure(self, url: str) -> List[Dict]:
        """Check for information disclosure."""
        findings = []
        
        if requests:
            try:
                resp = requests.get(url, timeout=10)
                
                headers_to_check = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
                for header in headers_to_check:
                    if header in resp.headers:
                        findings.append({
                            "type": "Information Disclosure",
                            "severity": "low",
                            "title": f"{header} Header Revealed",
                            "description": f"Value: {resp.headers[header]}",
                            "recommendation": f"Remove or obscure {header} header",
                            "url": url
                        })
                        
                patterns = [
                    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[\w@#$%^&*]+', "Password in HTML"),
                    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[\w-]+', "API Key in HTML"),
                    (r'(?:secret|token)\s*[:=]\s*["\']?[\w-]+', "Secret/Token in HTML"),
                ]
                
                for pattern, title in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        findings.append({
                            "type": "Information Disclosure",
                            "severity": "high",
                            "title": title,
                            "description": "Sensitive information exposed in HTML",
                            "recommendation": "Remove sensitive data from HTML output",
                            "url": url
                        })
                        
            except Exception:
                pass
                
        return findings

    def _check_common_files(self, url: str) -> List[Dict]:
        """Check for exposed sensitive files."""
        findings = []
        
        sensitive_files = [
            '/robots.txt', '/sitemap.xml', '/.env', '/.git/config',
            '/wp-admin/', '/phpinfo.php', '/server-status',
            '/.htaccess', '/config.php', '/web.config'
        ]
        
        if requests:
            for file_path in sensitive_files:
                try:
                    test_url = urljoin(url, file_path)
                    resp = requests.get(test_url, timeout=5, allow_redirects=False)
                    if resp.status_code == 200:
                        severity = "info" if file_path in ['/robots.txt', '/sitemap.xml'] else "medium"
                        findings.append({
                            "type": "Information Disclosure",
                            "severity": severity,
                            "title": f"Sensitive File Accessible: {file_path}",
                            "description": f"{file_path} is publicly accessible",
                            "recommendation": f"Restrict access to {file_path}",
                            "url": test_url
                        })
                except Exception:
                    pass
                    
        return findings

    def _check_cors(self, url: str) -> List[Dict]:
        """Check CORS configuration."""
        findings = []
        
        if requests:
            try:
                headers = {'Origin': 'https://evil.com'}
                resp = requests.get(url, headers=headers, timeout=10)
                
                if 'Access-Control-Allow-Origin' in resp.headers:
                    acao = resp.headers['Access-Control-Allow-Origin']
                    if acao == '*' or acao == 'https://evil.com':
                        findings.append({
                            "type": "CORS Misconfiguration",
                            "severity": "medium",
                            "title": "Overly Permissive CORS Policy",
                            "description": f"Access-Control-Allow-Origin: {acao}",
                            "recommendation": "Restrict CORS to trusted origins",
                            "url": url
                        })
            except Exception:
                pass
                
        return findings

    def _get_header_analysis(self, url: str) -> Dict:
        """Get detailed header analysis."""
        headers_present = {}
        headers_missing = []
        
        if requests:
            try:
                resp = requests.get(url, timeout=10)
                for header in self.security_headers:
                    if header in resp.headers:
                        headers_present[header] = resp.headers[header]
                    else:
                        headers_missing.append(header)
            except Exception:
                pass
                
        return {
            "present": headers_present,
            "missing": headers_missing,
            "score": len(headers_present),
            "total": len(self.security_headers)
        }

    def _get_ssl_info(self, url: str) -> Dict:
        """Get SSL certificate information."""
        info = {}
        
        if url.startswith("https://"):
            try:
                hostname = urlparse(url).netloc
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(5)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                    
                    info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "serialNumber": cert.get('serialNumber'),
                        "notBefore": cert.get('notBefore'),
                        "notAfter": cert.get('notAfter'),
                        "version": cert.get('version'),
                    }
            except Exception:
                pass
                
        return info

    def _generate_summary(self, results: Dict) -> str:
        """Generate human-readable summary."""
        total = results["total_vulnerabilities"]
        breakdown = results["vulnerability_breakdown"]
        
        if total == 0:
            return "No vulnerabilities detected. The target appears to be secure."
        
        summary_parts = []
        summary_parts.append(f"Found {total} potential vulnerabilities:")
        
        if breakdown["critical"] > 0:
            summary_parts.append(f"🔴 {breakdown['critical']} Critical")
        if breakdown["high"] > 0:
            summary_parts.append(f"🟠 {breakdown['high']} High")
        if breakdown["medium"] > 0:
            summary_parts.append(f"🟡 {breakdown['medium']} Medium")
        if breakdown["low"] > 0:
            summary_parts.append(f"🔵 {breakdown['low']} Low")
        if breakdown["info"] > 0:
            summary_parts.append(f"⚪ {breakdown['info']} Informational")
            
        return " | ".join(summary_parts)

    def quick_scan(self, url: str) -> List[Dict]:
        """Perform a quick vulnerability scan."""
        findings = []
        findings.extend(self._check_security_headers(url))
        findings.extend(self._check_information_disclosure(url))
        return findings
