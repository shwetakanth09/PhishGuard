"""
CyberShield - AI-Powered Cybersecurity Toolkit
===============================================

A comprehensive security tool combining phishing detection
and vulnerability scanning capabilities.

Supports: Linux (Kali), macOS, Windows

Author: Aditya Sharma
GitHub: https://github.com/aditya226-sharma
"""

__version__ = "1.0.0"
__author__ = "Aditya Sharma"

from .phishing import PhishingDetector
from .vuln_scanner import VulnerabilityScanner
from .platform import PlatformDetector, get_platform

__all__ = [
    "PhishingDetector",
    "VulnerabilityScanner", 
    "PlatformDetector",
    "get_platform",
]
