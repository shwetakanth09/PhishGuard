"""
CyberShield Web Dashboard
=========================

Flask-based web interface for phishing detection
and vulnerability scanning.
"""

from flask import Flask, render_template, request, jsonify
import json
from datetime import datetime
from .phishing import PhishingDetector
from .vuln_scanner import VulnerabilityScanner

app = Flask(__name__)
app.secret_key = "cybershield-secret-key-change-in-production"

detector = PhishingDetector()
scanner = VulnerabilityScanner()


@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/scan/phishing", methods=["POST"])
def scan_phishing():
    """Scan URL for phishing indicators."""
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = detector.analyze_url(url)
    return jsonify(results)


@app.route("/scan/vulnerability", methods=["POST"])
def scan_vulnerability():
    """Scan URL for vulnerabilities."""
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    results = scanner.scan_target(url)
    return jsonify(results)


@app.route("/scan/full", methods=["POST"])
def scan_full():
    """Perform full security scan (phishing + vulnerability)."""
    data = request.get_json()
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    phishing_results = detector.analyze_url(url)
    vuln_results = scanner.scan_target(url)

    combined = {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "phishing": phishing_results,
        "vulnerability": vuln_results,
        "overall_risk": max(phishing_results["risk_score"], vuln_results["total_vulnerabilities"] * 10),
    }

    return jsonify(combined)


@app.route("/api/stats")
def get_stats():
    """Get scan statistics."""
    return jsonify({
        "status": "operational",
        "modules": ["Phishing Detection", "Vulnerability Scanner"],
        "version": "1.0.0",
        "last_scan": datetime.now().isoformat()
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
