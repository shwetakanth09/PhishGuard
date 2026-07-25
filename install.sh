#!/bin/bash

# CyberShield Installer for Linux/Kali
# ====================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "   CyberShield - Security Toolkit Installer"
    echo "============================================"
    echo -e "${NC}"
}

check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON=python3
    elif command -v python &> /dev/null; then
        PYTHON=python
    else
        echo -e "${RED}Python not found! Please install Python 3.8+${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Using: $($PYTHON --version)${NC}"
}

install_pip() {
    echo -e "${YELLOW}Installing pip packages...${NC}"
    $PYTHON -m pip install --upgrade pip
    $PYTHON -m pip install -r requirements.txt
}

install_system_deps() {
    echo -e "${YELLOW}Checking system dependencies...${NC}"
    
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu/Kali
        sudo apt-get update
        sudo apt-get install -y python3-pip python3-venv
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        sudo yum install -y python3-pip
    elif [ -f /etc/arch-release ]; then
        # Arch
        sudo pacman -S python-pip
    fi
}

setup_virtualenv() {
    echo -e "${YELLOW}Setting up virtual environment...${NC}"
    
    if [ ! -d "venv" ]; then
        $PYTHON -m venv venv
    fi
    
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
}

install_package() {
    echo -e "${YELLOW}Installing CyberShield...${NC}"
    $PYTHON -m pip install -e .
}

main() {
    print_banner
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}Running as root${NC}"
    else
        echo -e "${YELLOW}Not running as root (some features may require sudo)${NC}"
    fi
    
    check_python
    install_system_deps
    install_pip
    install_package
    
    echo ""
    echo -e "${GREEN}============================================"
    echo "   Installation Complete!"
    echo "============================================"
    echo ""
    echo -e "${CYAN}Usage:${NC}"
    echo "  cybershield full https://example.com"
    echo "  cybershield phishing https://example.com"
    echo "  cybershield vuln https://example.com"
    echo "  cybershield serve"
    echo "  cybershield check"
    echo ""
    echo -e "${CYAN}Web Dashboard:${NC}"
    echo "  cybershield serve --port 5000"
    echo "  Then open: http://localhost:5000"
    echo ""
}

main "$@"
