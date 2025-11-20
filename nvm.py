import argparse
import sys
import time
from rich.console import Console
from rich.panel import Panel
from dotenv import load_dotenv
from core import scanner
from core import identifier
from core import cve_lookup
from core import analyzer
from reports import generate_json
from reports import generate_html

load_dotenv()

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

console = Console()

def print_banner():
    banner = """
    ███╗   ██╗██╗   ██╗███╗   ███╗
    ████╗  ██║██║   ██║████╗ ████║
    ██╔██╗ ██║██║   ██║██╔████╔██║
    ██║╚██╗██║╚██╗ ██╔╝██║╚██╔╝██║
    ██║ ╚████║ ╚████╔╝ ██║ ╚═╝ ██║
    ╚═╝  ╚═══╝  ╚═══╝  ╚═╝     ╚═╝
    [bold cyan]Network Vulnerability Manager v1.0[/]
    """
    console.print(banner, style="bold blue")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="NVM - Smart Network Vulnerability Scanner")
    
    parser.add_argument("-t", "--target", required=True, help="Target IP")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range")
    parser.add_argument("--html", action="store_true", help="Generate HTML")
    parser.add_argument("--json", action="store_true", help="Generate JSON")
    parser.add_argument("--threads", type=int, default=50, help="Threads")

    args = parser.parse_args()

    start_time = time.time()
    console.print(f"[+] Target: [bold green]{args.target}[/]")
    console.print(f"[+] Ports:  [bold green]{args.ports}[/]")
    console.print(f"[+] Threads: [bold green]{args.threads}[/]")
    console.print("-" * 40)

    # --- PHASE 1: SCANNING ---
    with console.status(f"[bold green]Scanning {args.target} with {args.threads} threads...[/]"):
        scan_results = scanner.run_scan(args.target, args.ports, args.threads)
    
    console.print(f"[green]✔ Scan Complete[/]. Found [bold]{len(scan_results)}[/] open ports.")

    if not scan_results:
        console.print("[yellow]No open ports found. Exiting.[/]")
        return
        
    # --- PHASE 2: IDENTIFICATION ---
    console.print("[bold blue][*] Identifying Services & CPEs...[/]")
    cpe_results = identifier.identify_cpes(scan_results)

    valid_cpe_count = sum(1 for data in cpe_results.values() if data['cpe'])
    console.print(f"[bold blue]✔ CPE Mapping Complete. Found {valid_cpe_count} valid CPE strings.[/]")

    if not valid_cpe_count:
        console.print("[yellow]No identifiable services found. Exiting.[/]")
        return
        
    # --- PHASE 3: VULN LOOKUP ---
    console.print("[bold yellow][*] Checking NVD for Vulnerabilities...[/]")
    
    with console.status("[bold yellow]Fetching CVEs from NVD API...[/]"):
        all_vulnerabilities = cve_lookup.fetch_cves(cpe_results)
    
    total_cves = sum(len(v) for v in all_vulnerabilities.values())
    console.print(f"[bold yellow]✔ NVD Lookup Complete. Found {total_cves} total CVEs.[/]")

    # --- PHASE 4: RISK ANALYSIS ---
    console.print("[bold red][*] Analyzing Risk Profile...[/]")
    
    overall_risk, final_results = analyzer.analyze_vulnerabilities(cpe_results, all_vulnerabilities)

    # 5. PRINT FINAL SUMMARY
    risk_color = "white"
    if overall_risk == "LOW": risk_color = "green"
    if overall_risk == "MEDIUM": risk_color = "yellow"
    if overall_risk in ["HIGH", "CRITICAL"]: risk_color = "red"

    console.print(f"\nOverall Risk: [{risk_color} bold]{overall_risk}[/]\n")
    
    console.print("Port    Service/Version           Risk     CVE Count")
    console.print("-" * 60)
    for port, info in final_results.items():
        risk_color = "white"
        if info['risk'] == "LOW": risk_color = "green"
        if info['risk'] == "MEDIUM": risk_color = "yellow"
        if info['risk'] in ["HIGH", "CRITICAL"]: risk_color = "red"
        
        console.print(
            f"{port:<7} {info['service']:<17} {str(info['version'])[:15]:<15} [{risk_color}]{info['risk']}[/]{' ' * (10 - len(info['risk']))} {len(info['vulnerabilities']):<5}"
        )
    console.print("-" * 60)

    # --- PHASE 5: REPORTING ---
    if args.json:
        console.print("[bold cyan][*] Generating JSON Report...[/]")
        json_file = generate_json.create_json_report(overall_risk, final_results, args.target)
        console.print(f"✔ JSON Report saved: [green]{json_file}[/]")

    if args.html:
        console.print("[bold cyan][*] Generating HTML Report...[/]")
        html_file = generate_html.create_html_report(overall_risk, final_results, args.target)
        console.print(f"✔ HTML Report saved: [green]{html_file}[/]")


    elapsed = time.time() - start_time
    console.print(Panel(f"Scan finished in {elapsed:.2f}s", title="Done", style="green"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]![/] Scan Aborted by user.")
        sys.exit(1)