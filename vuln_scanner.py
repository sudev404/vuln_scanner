#!/usr/bin/env python3
"""
VulnScanner - Vulnerability Assessment Tool
Usage: python vuln_scanner.py -t <target> [options]
"""

import argparse
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.port_scanner import run_port_scan
from modules.cve_lookup import run_cve_lookup
from modules.sqli_tester import run_sqli_test
from modules.xss_tester import run_xss_test
from modules.ssl_checker import run_ssl_check
try:
    from modules.report_generator import generate_pdf_report, generate_html_report
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False
    print("[!] reportlab not installed — PDF report disabled, HTML only.")

BANNER = """
\033[92m
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
\033[0m
\033[92m[+]\033[0m  Target Reconnaissance  \033[92m[+]\033[0m  CVE Lookup  \033[92m[+]\033[0m  Exploit Detection  \033[92m[+]\033[0m  Report Generation
\033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
\033[91m[!] For Authorized Penetration Testing Only  |  Unauthorized use is illegal\033[0m
\033[90m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m
\033[96m                                      by Sudev\033[0m
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScanner - Comprehensive Vulnerability Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target hostname or IP (e.g., example.com or 192.168.1.1)")
    parser.add_argument("-u", "--url",
                        help="Target URL for web tests (e.g., http://example.com/page?id=1)")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range to scan (default: 1-1024, e.g., 1-65535)")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-cve", action="store_true", help="Skip CVE lookup")
    parser.add_argument("--skip-sqli", action="store_true", help="Skip SQLi testing")
    parser.add_argument("--skip-xss", action="store_true", help="Skip XSS testing")
    parser.add_argument("--skip-ssl", action="store_true", help="Skip SSL/TLS check")
    parser.add_argument("-o", "--output", default="vuln_report",
                        help="Output filename (without extension, default: vuln_report)")
    parser.add_argument("--threads", type=int, default=100,
                        help="Threads for port scanning (default: 100)")
    return parser.parse_args()


def parse_port_range(port_str):
    try:
        parts = port_str.split("-")
        return int(parts[0]), int(parts[1])
    except Exception:
        return 1, 1024


def main():
    print(BANNER)
    args = parse_args()

    target = args.target.strip()
    url = args.url or f"http://{target}"
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    port_range = parse_port_range(args.ports)

    print(f"[*] Target     : {target}")
    print(f"[*] URL        : {url}")
    print(f"[*] Port Range : {port_range[0]}-{port_range[1]}")
    print(f"[*] Scan Time  : {scan_time}")
    print("=" * 60)

    scan_data = {
        "target": target,
        "scan_time": scan_time,
        "ports": [],
        "cves": {},
        "sqli": [],
        "xss": [],
        "ssl": {},
    }

    # ── Phase 1: Port Scan ────────────────────────────────────────────────────
    if not args.skip_ports:
        scan_data["ports"] = run_port_scan(target, port_range, threads=args.threads)

    # ── Phase 2: CVE Lookup ───────────────────────────────────────────────────
    if not args.skip_cve and scan_data["ports"]:
        scan_data["cves"] = run_cve_lookup(scan_data["ports"])
    elif not args.skip_cve:
        print("\n[!] Skipping CVE lookup — no open ports discovered.")

    # ── Phase 3: SQL Injection ────────────────────────────────────────────────
    if not args.skip_sqli:
        scan_data["sqli"] = run_sqli_test(url)

    # ── Phase 4: XSS ─────────────────────────────────────────────────────────
    if not args.skip_xss:
        scan_data["xss"] = run_xss_test(url)

    # ── Phase 5: SSL/TLS ──────────────────────────────────────────────────────
    if not args.skip_ssl:
        scan_data["ssl"] = run_ssl_check(target)

    # ── Report Generation ─────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("[*] Generating reports...")

    pdf_path = f"{args.output}.pdf"
    html_path = f"{args.output}.html"

if PDF_SUPPORT:
    generate_pdf_report(scan_data, pdf_path)
else:
    print("[!] Skipping PDF — reportlab not available.")
generate_html_report(scan_data, html_path)
    

    print(f"\n{'='*60}")
    print(f"[✓] Scan complete!")
    print(f"[✓] PDF Report  : {pdf_path}")
    print(f"[✓] HTML Report : {html_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
