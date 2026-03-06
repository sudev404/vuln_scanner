
# VulnScanner 🔍
A comprehensive vulnerability assessment tool built in Python for authorized security testing.

## Features
| Module | Description |
|---|---|
| Port Scanner | Multi-threaded TCP port scan with service detection & risk flagging |
| CVE Lookup | Queries NVD API for real CVEs matching discovered services |
| SQLi Tester | Tests URL parameters and form inputs for SQL injection |
| XSS Tester | Tests for Reflected XSS and checks security headers |
| SSL/TLS Checker | Validates certificates, protocols, cipher suites & HSTS |
| Report Generator | Generates professional PDF & HTML reports |

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Full scan (all modules)
python vuln_scanner.py -t example.com -u "http://example.com/page?id=1"

# Custom port range
python vuln_scanner.py -t example.com --ports 1-65535

# Skip specific modules
python vuln_scanner.py -t example.com --skip-cve --skip-sqli

# Custom output filename
python vuln_scanner.py -t example.com -o my_report

# Faster scan with more threads
python vuln_scanner.py -t example.com --threads 200
```

## Output
- `<output>.pdf` — Styled PDF vulnerability report
- `<output>.html` — Interactive HTML vulnerability report

## Project Structure
```
vuln_scanner/
├── vuln_scanner.py          # Main CLI entry point
├── requirements.txt
├── README.md
└── modules/
    ├── port_scanner.py      # TCP port scanning
    ├── cve_lookup.py        # NVD CVE API lookup
    ├── sqli_tester.py       # SQL injection testing
    ├── xss_tester.py        # XSS testing + header checks
    ├── ssl_checker.py       # SSL/TLS certificate analysis
    └── report_generator.py  # PDF & HTML report generation
```

## ⚠️ Legal Disclaimer
This tool is intended for **authorized penetration testing only**.
Do NOT use against systems you do not have explicit permission to test.
