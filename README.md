<div align="center">

# 🛡️ CyberShield

### AI-Powered Cybersecurity Toolkit

![Version](https://img.shields.io/badge/Version-1.0.0-00D4FF?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00FF88?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production-brightgreen?style=for-the-badge)

**A comprehensive security toolkit combining phishing detection and vulnerability scanning capabilities.**

![Linux](https://img.shields.io/badge/Linux-Kali-557C94?style=for-the-badge&logo=linux&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D4?style=for-the-badge&logo=windows&logoColor=white)

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/aditya226-sharma/cybershield)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/aditya-sharma90)
[![Portfolio](https://img.shields.io/badge/Portfolio-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://adii-sharma.vercel.app/)

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Platform Support](#-platform-support)
- [Installation](#-installation)
- [Usage](#-usage)
- [Web Dashboard](#-web-dashboard)
- [API Reference](#-api-reference)
- [Architecture](#-architecture)
- [Examples](#-examples)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

### 🎣 Phishing Detection
- **URL Structure Analysis** - Detects suspicious patterns in URLs
- **Domain Reputation Check** - Identifies risky TLDs and domain characteristics
- **SSL Certificate Validation** - Verifies HTTPS implementation
- **Keyword Detection** - Flags phishing-related keywords
- **Redirect Detection** - Identifies suspicious redirects
- **Homograph Attack Detection** - Detects Unicode character attacks
- **Heuristic Scoring** - AI-powered risk assessment

### 🔍 Vulnerability Scanner
- **XSS Detection** - Tests for Cross-Site Scripting vulnerabilities
- **SQL Injection Testing** - Identifies SQL injection points
- **Security Headers Audit** - Validates security header implementation
- **SSL/TLS Analysis** - Checks certificate validity and configuration
- **Information Disclosure** - Detects exposed sensitive data
- **CORS Misconfiguration** - Identifies cross-origin issues
- **Sensitive File Detection** - Checks for exposed configuration files

### 🖥️ Web Dashboard
- **Modern UI** - Sleek dark mode interface
- **Real-time Scanning** - Instant results with animated indicators
- **Visual Reports** - Charts and graphs for easy understanding
- **Export Results** - Download scan reports in JSON format

### 💻 CLI Interface
- **Rich Terminal Output** - Beautiful console formatting
- **Multiple Scan Modes** - Full, phishing-only, vulnerability-only
- **Batch Processing** - Scan multiple URLs at once
- **Cross-Platform** - Works on Linux, macOS, Windows

---

## 🖥️ Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux (Kali)** | ✅ Full Support | Recommended for security professionals |
| **Linux (Ubuntu/Debian)** | ✅ Full Support | Tested on Ubuntu 20.04+ |
| **Linux (CentOS/RHEL)** | ✅ Full Support | Uses yum for dependencies |
| **Linux (Arch)** | ✅ Full Support | Uses pacman |
| **macOS** | ✅ Full Support | Requires Xcode Command Line Tools |
| **Windows 10/11** | ✅ Full Support | PowerShell or CMD |
| **Windows Server** | ✅ Full Support | Tested on Server 2019+ |

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

---

### 🐧 Linux (Kali/Ubuntu/Debian)

```bash
# Quick Install (One-liner)
curl -sSL https://raw.githubusercontent.com/aditya226-sharma/cybershield/main/install.sh | bash

# Or Manual Install
git clone https://github.com/aditya226-sharma/cybershield.git
cd cybershield
chmod +x install.sh
./install.sh
```

**For Kali Linux (as root):**
```bash
sudo apt update
sudo apt install python3-pip python3-venv -y
pip3 install -r requirements.txt
pip3 install -e .
```

---

### 🍎 macOS

```bash
# Install Python (if not installed)
brew install python

# Clone and install
git clone https://github.com/aditya226-sharma/cybershield.git
cd cybershield
pip3 install -r requirements.txt
pip3 install -e .
```

**Or using the install script:**
```bash
chmod +x install.sh
./install.sh
```

---

### 🪟 Windows

**Option 1: Using install.bat (Recommended)**
```cmd
git clone https://github.com/aditya226-sharma/cybershield.git
cd cybershield
install.bat
```

**Option 2: Using PowerShell**
```powershell
# Clone repository
git clone https://github.com/aditya226-sharma/cybershield.git
cd cybershield

# Install dependencies
python -m pip install -r requirements.txt

# Install package
python -m pip install -e .
```

**Option 3: Using Command Prompt**
```cmd
git clone https://github.com/aditya226-sharma/cybershield.git
cd cybershield
python -m pip install -r requirements.txt
python -m pip install -e .
```

---

### 🐳 Docker (All Platforms)

```bash
# Build image
docker build -t cybershield .

# Run container
docker run -it cybershield full https://example.com
```

---

## 💡 Usage

### Command Line Interface

```bash
# Full security scan
cybershield full https://example.com

# Phishing detection only
cybershield phishing https://example.com

# Vulnerability scan only
cybershield vuln https://example.com

# Start web dashboard
cybershield serve --port 5000

# Check system compatibility
cybershield check
```

### Python API

```python
from cybershield import PhishingDetector, VulnerabilityScanner, get_platform

# Check platform
platform = get_platform()
platform.print_info()

# Phishing Detection
detector = PhishingDetector()
result = detector.analyze_url("https://example.com")

print(f"Risk Score: {result['risk_score']}/100")
print(f"Risk Level: {result['risk_level']}")
print(f"Is Phishing: {result['is_phishing']}")

# Vulnerability Scanning
scanner = VulnerabilityScanner()
results = scanner.scan_target("https://example.com")

print(f"Vulnerabilities Found: {results['total_vulnerabilities']}")
for finding in results['findings']:
    print(f"  - {finding['title']}: {finding['severity']}")
```

### Batch Scanning

```python
from cybershield import PhishingDetector

detector = PhishingDetector()

urls = [
    "https://google.com",
    "https://github.com",
    "https://example.com"
]

results = detector.batch_scan(urls)
for result in results:
    print(f"{result['url']}: {result['risk_level']}")
```

---

## 🖥️ Web Dashboard

Start the dashboard with:

```bash
cybershield serve
```

Then open your browser and navigate to `http://localhost:5000`

### Features:
- 🎯 **Target Input** - Enter URL to scan
- 📊 **Risk Meter** - Visual risk indicator
- 🔍 **Detailed Findings** - Complete vulnerability list
- 📈 **Statistics** - Scan history and trends
- 🌙 **Dark Mode** - Easy on the eyes

---

## 📡 API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main dashboard |
| `POST` | `/scan/phishing` | Phishing detection scan |
| `POST` | `/scan/vulnerability` | Vulnerability scan |
| `POST` | `/scan/full` | Full security scan |
| `GET` | `/api/stats` | Get scan statistics |

### Example Request

```bash
curl -X POST http://localhost:5000/scan/full \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 🏗️ Architecture

```
cybershield/
├── cybershield/
│   ├── __init__.py          # Package initialization
│   ├── __main__.py          # CLI entry point
│   ├── phishing.py          # Phishing detection module
│   ├── vuln_scanner.py      # Vulnerability scanner module
│   ├── dashboard.py         # Flask web application
│   └── platform.py          # Cross-platform utilities
├── templates/
│   └── index.html           # Dashboard HTML template
├── static/
│   ├── css/style.css        # Dashboard styling
│   └── js/main.js           # Dashboard JavaScript
├── tests/
│   └── test_modules.py      # Unit tests
├── install.sh               # Linux/macOS installer
├── install.bat              # Windows installer
├── setup.py                 # Package setup
├── requirements.txt         # Dependencies
└── README.md                # Documentation
```

---

## 📸 Examples

### Sample Phishing Detection Output

```
🛡️ Phishing Analysis

URL: https://paypa1-secure.login.com
Risk Score: 85/100
Risk Level: 🔴 CRITICAL
Phishing: 🔴 Yes

Warnings:
  ⚠️ Suspicious keywords found: login, secure, verify
  ⚠️ Suspicious TLD: .com
  ⚠️ Domain uses IP address instead of name
```

### Sample Vulnerability Scan Output

```
🔍 Vulnerability Scan Results

┌─────────────────────┬───────┐
│ Metric              │ Count │
├─────────────────────┼───────┤
│ Total Vulnerabilities│   12  │
│ Critical            │    2  │
│ High                │    4  │
│ Medium              │    5  │
│ Low                 │    1  │
└─────────────────────┴───────┘

Detailed Findings:
  1. Missing Content-Security-Policy Header
  2. Missing X-Frame-Options Header
  3. Server Header Information Disclosure
```

### System Check Output

```
==================================================
SYSTEM CHECK
==================================================
Platform: Linux
Python: 3.11.0
Architecture: x86_64
[OK] requests
[OK] beautifulsoup4
[OK] rich
[OK] tldextract
[OK] python-whois
==================================================

All dependencies satisfied!
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Aditya Sharma**

- 🌐 Portfolio: [adii-sharma.vercel.app](https://adii-sharma.vercel.app/)
- 💼 LinkedIn: [aditya-sharma90](https://linkedin.com/in/aditya-sharma90)
- 🐙 GitHub: [@aditya226-sharma](https://github.com/aditya226-sharma)
- 📧 Email: adityaiit687@gmail.com

---

## 🙏 Acknowledgments

- Built with ❤️ by Aditya Sharma
- Part of the cybersecurity learning journey
- Designed for educational and professional use

---

<div align="center">

**If you found this tool helpful, please give it a ⭐ on GitHub!**

![Footer](https://img.shields.io/badge/Made_With-❤️_By_Aditya_Sharma-00D4FF?style=for-the-badge)

</div>
