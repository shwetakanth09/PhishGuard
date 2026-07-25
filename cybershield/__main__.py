"""
CyberShield CLI
===============

Command-line interface for phishing detection
and vulnerability scanning.
"""

import sys
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .phishing import PhishingDetector
from .vuln_scanner import VulnerabilityScanner

console = Console()


def scan_phishing(url: str):
    """Scan URL for phishing indicators."""
    detector = PhishingDetector()
    
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
[bold]Phishing:[/bold] {'🔴 Yes' if results['is_phishing'] else '🟢 No'}
"""
    
    if results["warnings"]:
        panel_content += "\n[bold yellow]Warnings:[/bold yellow]\n"
        for warning in results["warnings"]:
            panel_content += f"  ⚠️ {warning}\n"
            
    console.print(Panel(panel_content, title="🛡️ Phishing Analysis", border_style="cyan"))


def scan_vulnerability(url: str):
    """Scan URL for vulnerabilities."""
    scanner = VulnerabilityScanner()
    
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
    
    table = Table(title="🔍 Vulnerability Scan Results")
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


def scan_full(url: str):
    """Perform full security scan."""
    console.print(f"\n[bold cyan]🚀 Starting Full Security Scan for: {url}[/bold cyan]\n")
    
    console.print("[bold]Phase 1: Phishing Detection[/bold]")
    scan_phishing(url)
    
    console.print("\n[bold]Phase 2: Vulnerability Scanning[/bold]")
    scan_vulnerability(url)
    
    console.print("\n[bold green]✅ Scan Complete![/bold green]")


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
    
    args = parser.parse_args()
    
    if args.command == "phishing":
        scan_phishing(args.url)
    elif args.command == "vuln":
        scan_vulnerability(args.url)
    elif args.command == "full":
        scan_full(args.url)
    elif args.command == "serve":
        from .dashboard import app
        console.print(f"\n[bold green]🚀 Starting CyberShield Dashboard on http://{args.host}:{args.port}[/bold green]\n")
        app.run(debug=True, host=args.host, port=args.port)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
