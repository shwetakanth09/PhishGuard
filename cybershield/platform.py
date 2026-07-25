"""
Cross-Platform Compatibility Module
====================================

Provides platform detection and utilities for
Linux (Kali), macOS, and Windows.
"""

import sys
import os
import platform
import subprocess
from pathlib import Path


class PlatformDetector:
    """Detect and configure for the current platform."""

    KALI = "kali"
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"

    def __init__(self):
        self.system = platform.system().lower()
        self.distribution = self._get_distribution()
        self.platform_name = self._detect_platform()
        self.is_root = self._check_root()
        self.python_version = sys.version_info

    def _get_distribution(self):
        """Get Linux distribution if applicable."""
        if self.system == "linux":
            try:
                import distro
                return distro.id().lower()
            except ImportError:
                pass
            
            try:
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("ID="):
                            return line.split("=")[1].strip().lower()
            except FileNotFoundError:
                pass
                
        return None

    def _detect_platform(self):
        """Detect the specific platform."""
        if self.system == "windows":
            return self.WINDOWS
        elif self.system == "darwin":
            return self.MACOS
        elif self.system == "linux":
            if self.distribution and "kali" in self.distribution:
                return self.KALI
            return self.LINUX
        return self.UNKNOWN

    def _check_root(self):
        """Check if running with root/admin privileges."""
        if self.system == "windows":
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0

    def get_install_command(self, package):
        """Get platform-specific install command for a package."""
        if self.platform_name in [self.KALI, self.LINUX]:
            return f"sudo apt-get install -y {package}"
        elif self.platform_name == self.MACOS:
            return f"brew install {package}"
        elif self.platform_name == self.WINDOWS:
            return f"choco install {package} -y"
        return None

    def print_info(self):
        """Print platform information."""
        print(f"\n{'='*50}")
        print(f"Platform Information:")
        print(f"{'='*50}")
        print(f"System: {self.system.title()}")
        print(f"Platform: {self.platform_name.upper()}")
        if self.distribution:
            print(f"Distribution: {self.distribution.title()}")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Architecture: {platform.machine()}")
        print(f"Root Access: {'Yes' if self.is_root else 'No'}")
        print(f"{'='*50}\n")


class NetworkHelper:
    """Platform-agnostic network utilities."""

    @staticmethod
    def check_internet():
        """Check internet connectivity."""
        import socket
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=3)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    @staticmethod
    def get_host_ip():
        """Get the host machine's IP address."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def resolve_domain(domain):
        """Resolve domain to IP address."""
        import socket
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None


class ColorSupport:
    """Handle terminal color support across platforms."""

    def __init__(self):
        self.supported = self._check_support()

    def _check_support(self):
        """Check if terminal supports colors."""
        if os.getenv("NO_COLOR"):
            return False
        if self._is_windows():
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except Exception:
                return False
        return True

    def _is_windows(self):
        return platform.system().lower() == "windows"

    def colorize(self, text, color):
        """Apply color to text if supported."""
        if not self.supported:
            return text
            
        colors = {
            "red": "\033[91m",
            "green": "\033[92m",
            "yellow": "\033[93m",
            "blue": "\033[94m",
            "magenta": "\033[95m",
            "cyan": "\033[96m",
            "white": "\033[97m",
            "reset": "\033[0m"
        }
        
        return f"{colors.get(color, '')}{text}{colors['reset']}"


def get_platform():
    """Get platform detector instance."""
    return PlatformDetector()


def check_dependencies():
    """Check if all required dependencies are installed."""
    required = [
        "flask",
        "requests",
        "bs4",
        "rich",
        "tldextract"
    ]
    
    missing = []
    for package in required:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing.append(package)
    
    return missing


def install_missing_deps(missing):
    """Attempt to install missing dependencies."""
    import pip
    
    for package in missing:
        try:
            pip.main(["install", package])
        except Exception as e:
            print(f"Failed to install {package}: {e}")
            return False
    
    return True
