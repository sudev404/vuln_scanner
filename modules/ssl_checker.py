import ssl
import socket
import datetime
import requests

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5"
]

DEPRECATED_PROTOCOLS = {
    "SSLv2": ssl.PROTOCOL_TLS_CLIENT,
    "SSLv3": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.0": ssl.PROTOCOL_TLS_CLIENT,
    "TLSv1.1": ssl.PROTOCOL_TLS_CLIENT,
}

PROTOCOL_MAP = {
    "TLSv1": "TLS 1.0",
    "TLSv1.1": "TLS 1.1",
    "TLSv1.2": "TLS 1.2",
    "TLSv1.3": "TLS 1.3",
    "SSLv3": "SSL 3.0",
    "SSLv2": "SSL 2.0",
}


def get_certificate_info(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                not_after = datetime.datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
                not_before = datetime.datetime.strptime(
                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                )
                days_remaining = (not_after - datetime.datetime.utcnow()).days

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for _, v in cert.get("subjectAltName", [])]

                return {
                    "valid": True,
                    "subject_cn": subject.get("commonName", "N/A"),
                    "issuer": issuer.get("organizationName", "N/A"),
                    "not_before": not_before.strftime("%Y-%m-%d"),
                    "not_after": not_after.strftime("%Y-%m-%d"),
                    "days_remaining": days_remaining,
                    "san": san[:5],
                    "cipher": cipher[0] if cipher else "N/A",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "protocol": protocol,
                    "hostname": hostname,
                    "port": port,
                }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Certificate verification failed: {e}", "hostname": hostname}
    except Exception as e:
        return {"valid": False, "error": str(e), "hostname": hostname}


def check_hsts(url):
    try:
        resp = requests.get(url, timeout=10)
        hsts = resp.headers.get("Strict-Transport-Security", None)
        return hsts
    except Exception:
        return None


def analyze_cert_issues(cert_info):
    issues = []
    if not cert_info.get("valid"):
        issues.append({
            "issue": "Invalid/Untrusted Certificate",
            "detail": cert_info.get("error", "Unknown error"),
            "severity": "CRITICAL"
        })
        return issues

    days = cert_info.get("days_remaining", 999)
    if days < 0:
        issues.append({"issue": "Certificate EXPIRED", "detail": f"Expired {abs(days)} days ago", "severity": "CRITICAL"})
    elif days < 14:
        issues.append({"issue": "Certificate Expiring Very Soon", "detail": f"Expires in {days} days", "severity": "HIGH"})
    elif days < 30:
        issues.append({"issue": "Certificate Expiring Soon", "detail": f"Expires in {days} days", "severity": "MEDIUM"})

    protocol = cert_info.get("protocol", "")
    if "TLSv1" == protocol or "TLSv1.1" == protocol or "SSL" in protocol:
        issues.append({
            "issue": f"Deprecated Protocol: {protocol}",
            "detail": "TLS 1.0/1.1 and SSL are deprecated and vulnerable",
            "severity": "HIGH"
        })

    cipher = cert_info.get("cipher", "")
    for weak in WEAK_CIPHERS:
        if weak.upper() in cipher.upper():
            issues.append({
                "issue": f"Weak Cipher Suite: {cipher}",
                "detail": f"Contains weak algorithm: {weak}",
                "severity": "HIGH"
            })

    bits = cert_info.get("cipher_bits", 256)
    if bits and bits < 128:
        issues.append({
            "issue": "Weak Key Length",
            "detail": f"Only {bits}-bit encryption in use",
            "severity": "HIGH"
        })

    return issues


def run_ssl_check(target):
    print(f"\n[*] Starting SSL/TLS check on {target}...")
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]

    cert_info = get_certificate_info(hostname)
    issues = analyze_cert_issues(cert_info)
    hsts = check_hsts(f"https://{hostname}")

    if not hsts:
        issues.append({
            "issue": "Missing HSTS Header",
            "detail": "Strict-Transport-Security not set; susceptible to downgrade attacks",
            "severity": "MEDIUM"
        })
    else:
        print(f"  [+] HSTS enabled: {hsts}")

    if cert_info.get("valid"):
        print(f"  [+] Certificate valid for: {cert_info['subject_cn']}")
        print(f"  [+] Issuer: {cert_info['issuer']}")
        print(f"  [+] Protocol: {cert_info['protocol']} | Cipher: {cert_info['cipher']}")
        print(f"  [+] Expires: {cert_info['not_after']} ({cert_info['days_remaining']} days remaining)")
    else:
        print(f"  [!] Certificate issue: {cert_info.get('error')}")

    for issue in issues:
        print(f"  [{issue['severity']}] {issue['issue']}: {issue['detail']}")

    if not issues:
        print(f"  [+] No SSL/TLS issues found.")

    return {"cert_info": cert_info, "issues": issues, "hsts": hsts}