# VulnScanner 🔍
> A comprehensive Python-based Vulnerability Assessment Tool for authorized penetration testing.
> 
> **by Sudev**

---

## 🚀 Features

| Module | Description |
|---|---|
| 🔌 Port Scanner | Multi-threaded TCP port scan with service detection and risk flagging |
| 🛡️ CVE Lookup | Queries NVD API for real CVEs matching discovered services |
| 💉 SQLi Tester | Tests URL parameters and form inputs for SQL injection |
| ⚡ XSS Tester | Tests for Reflected XSS and checks security headers |
| 🔒 SSL/TLS Checker | Validates certificates, protocols, cipher suites and HSTS |
| 📊 Report Generator | Generates professional PDF and HTML reports |

---

## 🖥️ Requirements

- Python 3.7 or higher
- pip (Python package manager)

---

## 📦 Installation

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/sudev404/vuln_scanner.git
cd vuln_scanner
```

**Step 2 — Install dependencies:**
```bash
pip install requests reportlab
```
Or using the requirements file:
```bash
pip install -r requirements.txt
```

**Step 3 — Verify installation:**
```bash
python -c "import requests, reportlab; print('All dependencies installed!')"
```

---

## ▶️ Usage

**Basic scan:**
```bash
python vuln_scanner.py -t target.com -u "http://target.com/page?id=1"
```

**Full scan with all options:**
```bash
python vuln_scanner.py -t target.com -u "http://target.com" --ports 1-65535 --threads 200 -o my_report
```

---

## ⚙️ Options

| Option | Description | Default |
|---|---|---|
| `-t` | Target hostname or IP | Required |
| `-u` | Target URL for web tests | `http://<target>` |
| `--ports` | Port range to scan | `1-1024` |
| `--threads` | Number of scan threads | `100` |
| `-o` | Output report filename | `vuln_report` |
| `--skip-ports` | Skip port scanning | - |
| `--skip-cve` | Skip CVE lookup | - |
| `--skip-sqli` | Skip SQL injection test | - |
| `--skip-xss` | Skip XSS test | - |
| `--skip-ssl` | Skip SSL/TLS check | - |

---

## 🎯 Safe Practice Targets

> Use these legal, intentionally vulnerable sites to test the tool:

| Target | Best For |
|---|---|
| `testphp.vulnweb.com` | SQLi + XSS testing |
| `scanme.nmap.org` | Port scanning only |

**Example:**
```bash
python vuln_scanner.py -t testphp.vulnweb.com -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

---

## 📊 Output Reports

After every scan, two report files are generated:
```
vuln_scanner/
├── vuln_report.pdf    ← open with any PDF viewer
└── vuln_report.html   ← open with any browser (recommended)
```

---

## 🖥️ OS Compatibility

| OS | Command |
|---|---|
| Windows | `python vuln_scanner.py` |
| Linux / Kali | `python3 vuln_scanner.py` |
| macOS | `python3 vuln_scanner.py` |
| Android (Termux) | `python3 vuln_scanner.py` |

---

## 📁 Project Structure

```
vuln_scanner/
├── vuln_scanner.py          ← Main CLI entry point
├── requirements.txt         ← Dependencies
├── README.md
└── modules/
    ├── __init__.py
    ├── port_scanner.py      ← TCP port scanning
    ├── cve_lookup.py        ← NVD CVE API lookup
    ├── sqli_tester.py       ← SQL injection testing
    ├── xss_tester.py        ← XSS testing + header checks
    ├── ssl_checker.py       ← SSL/TLS certificate analysis
    └── report_generator.py  ← PDF & HTML report generation
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized penetration testing only**.  
Do **NOT** use against systems you do not have explicit written permission to test.  
Unauthorized use is **illegal** and unethical.

---

## 👤 Author

**Sudev** — [github.com/sudev404](https://github.com/sudev404)
