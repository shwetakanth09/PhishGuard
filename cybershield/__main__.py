"""
CyberShield CLI
===============

Cross-platform command-line interface for phishing detection
and vulnerability scanning.
"""

import sys
import argparse
import platform
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from .phishing import PhishingDetector
from .vuln_scanner import VulnerabilityScanner


class Colors:
    """Cross-platform color support."""
    
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    
    @classmethod
    def disable(cls):
        """Disable colors."""
        cls.RED = cls.GREEN = cls.YELLOW = ""
        cls.BLUE = cls.MAGENTA = cls.CYAN = cls.WHITE = cls.RESET = cls.BOLD = ""


def check_terminal_support():
    """Check terminal color support across platforms."""
    system = platform.system().lower()
    
    if system == "windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    else:
        return sys.stdout.isatty()


if HAS_RICH:
    console = Console()
else:
    if not check_terminal_support():
        Colors.disable()


def print_colored(text, color="white"):
    """Print colored text (fallback for no rich)."""
    if HAS_RICH:
        console.print(text, style=color)
    else:
        print(f"{getattr(Colors, color.upper(), '')}{text}{Colors.RESET}")


def scan_phishing(url: str):
    """Scan URL for phishing indicators."""
    detector = PhishingDetector()
    
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Analyzing URL...", total=None)
            results = detector.analyze_url(url)
            progress.update(task, completed=True)

        console.print("\n")
        
        risk_color = {
            "SAFE": "green",
            "LOW": "yellow",
            "MEDIUM": "dark_orange",
            "HIGH": "red",
            "CRITICAL": "bold red"
        }.get(results["risk_level"], "white")
        
        panel_content = f"""
[bold]URL:[/bold] {results['url']}
[bold]Risk Score:[/bold] [{risk_color}]{results['risk_score']}/100[/{risk_color}]
[bold]Risk Level:[/bold] [{risk_color}]{results['risk_level']}[/{risk_color}]
[bold]Phishing:[/bold] {'Yes' if results['is_phishing'] else 'No'}
"""
        
        if results["warnings"]:
            panel_content += "\n[bold yellow]Warnings:[/bold yellow]\n"
            for warning in results["warnings"]:
                panel_content += f"  ! {warning}\n"
                
        console.print(Panel(panel_content, title="Phishing Analysis", border_style="cyan"))
    else:
        print("\n" + "="*50)
        print("PHISHING ANALYSIS")
        print("="*50)
        print(f"URL: {results['url']}")
        print(f"Risk Score: {results['risk_score']}/100")
        print(f"Risk Level: {results['risk_level']}")
        print(f"Phishing: {'Yes' if results['is_phishing'] else 'No'}")
        if results["warnings"]:
            print("\nWarnings:")
            for warning in results["warnings"]:
                print(f"  - {warning}")
        print("="*50 + "\n")


def scan_vulnerability(url: str):
    """Scan URL for vulnerabilities."""
    scanner = VulnerabilityScanner()
    
    if HAS_RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=None)
            results = scanner.scan_target(url)
            progress.update(task, completed=True)

        console.print("\n")
        
        breakdown = results["vulnerability_breakdown"]
        
        table = Table(title="Vulnerability Scan Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")
        
        table.add_row("Total Vulnerabilities", str(results["total_vulnerabilities"]))
        table.add_row("Critical", f"[bold red]{breakdown['critical']}[/bold red]")
        table.add_row("High", f"[red]{breakdown['high']}[/red]")
        table.add_row("Medium", f"[yellow]{breakdown['medium']}[/yellow]")
        table.add_row("Low", f"[blue]{breakdown['low']}[/blue]")
        table.add_row("Informational", f"[white]{breakdown['info']}[/white]")
        
        console.print(table)
        
        if results["findings"]:
            console.print("\n[bold]Detailed Findings:[/bold]\n")
            for i, finding in enumerate(results["findings"][:10], 1):
                severity_color = {
                    "critical": "bold red",
                    "high": "red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "white"
                }.get(finding["severity"], "white")
                
                console.print(f"  {i}. [{severity_color}]{finding['title']}[/{severity_color}]")
                console.print(f"     {finding['description']}\n")
    else:
        print("\n" + "="*50)
        print("VULNERABILITY SCAN RESULTS")
        print("="*50)
        breakdown = results["vulnerability_breakdown"]
        print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
        print(f"Critical: {breakdown['critical']}")
        print(f"High: {breakdown['high']}")
        print(f"Medium: {breakdown['medium']}")
        print(f"Low: {breakdown['low']}")
        print("-"*50)
        if results["findings"]:
            print("Detailed Findings:")
            for i, finding in enumerate(results["findings"][:10], 1):
                print(f"  {i}. [{finding['severity'].upper()}] {finding['title']}")
                print(f"     {finding['description']}\n")
        print("="*50 + "\n")


def scan_full(url: str):
    """Perform full security scan."""
    if HAS_RICH:
        console.print(f"\n[bold cyan]Starting Full Security Scan for: {url}[/bold cyan]\n")
    else:
        print(f"\nStarting Full Security Scan for: {url}\n")
    
    if HAS_RICH:
        console.print("[bold]Phase 1: Phishing Detection[/bold]")
    else:
        print("Phase 1: Phishing Detection")
    scan_phishing(url)
    
    if HAS_RICH:
        console.print("[bold]Phase 2: Vulnerability Scanning[/bold]")
    else:
        print("Phase 2: Vulnerability Scanning")
    scan_vulnerability(url)
    
    if HAS_RICH:
        console.print("[bold green]Scan Complete![/bold green]")
    else:
        print("Scan Complete!")


def check_system():
    """Check system compatibility."""
    system = platform.system()
    
    print("\n" + "="*50)
    print("SYSTEM CHECK")
    print("="*50)
    print(f"Platform: {system}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Architecture: {platform.machine()}")
    
    # Check dependencies
    missing = []
    deps = {
        "requests": "requests",
        "bs4": "beautifulsoup4",
        "rich": "rich",
        "tldextract": "tldextract",
        "whois": "python-whois"
    }
    
    for module, package in deps.items():
        try:
            __import__(module)
            print(f"[OK] {package}")
        except ImportError:
            missing.append(package)
            print(f"[MISSING] {package}")
    
    print("="*50)
    
    if missing:
        print(f"\nMissing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        return False
    
    print("\nAll dependencies satisfied!")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="CyberShield - AI-Powered Cybersecurity Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cybershield phishing https://example.com
  cybershield vuln https://example.com
  cybershield full https://example.com
  cybershield serve
  cybershield check
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    phishing_parser = subparsers.add_parser("phishing", help="Scan for phishing indicators")
    phishing_parser.add_argument("url", help="URL to scan")
    
    vuln_parser = subparsers.add_parser("vuln", help="Scan for vulnerabilities")
    vuln_parser.add_argument("url", help="URL to scan")
    
    full_parser = subparsers.add_parser("full", help="Full security scan")
    full_parser.add_argument("url", help="URL to scan")
    
    serve_parser = subparsers.add_parser("serve", help="Start web dashboard")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port number")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host address")
    
    check_parser = subparsers.add_parser("check", help="Check system compatibility")
    
    args = parser.parse_args()
    
    if args.command == "phishing":
        scan_phishing(args.url)
    elif args.command == "vuln":
        scan_vulnerability(args.url)
    elif args.command == "full":
        scan_full(args.url)
    elif args.command == "serve":
        try:
            from .dashboard import app
            if HAS_RICH:
                console.print(f"\n[bold green]Starting CyberShield Dashboard on http://{args.host}:{args.port}[/bold green]\n")
            else:
                print(f"\nStarting CyberShield Dashboard on http://{args.host}:{args.port}\n")
            app.run(debug=True, host=args.host, port=args.port)
        except ImportError as e:
            if HAS_RICH:
                console.print(f"[red]Error: {e}[/red]")
            else:
                print(f"Error: {e}")
    elif args.command == "check":
        check_system()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
