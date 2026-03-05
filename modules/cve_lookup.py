import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SERVICE_KEYWORDS = {
    "FTP":        ["vsftpd", "proftpd", "filezilla server"],
    "SSH":        ["openssh"],
    "HTTP":       ["apache", "nginx", "iis"],
    "HTTPS":      ["apache", "nginx", "iis", "openssl"],
    "SMB":        ["samba", "windows smb"],
    "MySQL":      ["mysql"],
    "PostgreSQL": ["postgresql"],
    "Redis":      ["redis"],
    "MongoDB":    ["mongodb"],
    "RDP":        ["remote desktop", "rdp"],
    "Telnet":     ["telnet"],
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "N/A": 5}


def lookup_cves_for_keyword(keyword, max_results=5):
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0,
        }
        resp = requests.get(NVD_API, params=params, timeout=10)
        if resp.status_code != 200:
            return []

        data = resp.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")
            metrics = cve.get("metrics", {})

            severity = "N/A"
            score = "N/A"
            if "cvssMetricV31" in metrics:
                m = metrics["cvssMetricV31"][0]["cvssData"]
                severity = m.get("baseSeverity", "N/A")
                score = m.get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics:
                m = metrics["cvssMetricV2"][0]
                severity = m.get("baseSeverity", "N/A")
                score = m.get("cvssData", {}).get("baseScore", "N/A")

            cves.append({
                "id": cve_id,
                "description": desc[:250] + "..." if len(desc) > 250 else desc,
                "severity": severity,
                "score": score,
            })

        cves.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"].upper(), 5))
        return cves

    except Exception as e:
        return [{"id": "ERROR", "description": str(e), "severity": "N/A", "score": "N/A"}]


def run_cve_lookup(open_ports):
    print(f"\n[*] Starting CVE lookup for discovered services...")
    results = {}
    seen_keywords = set()

    for port_info in open_ports:
        service = port_info.get("service", "Unknown")
        keywords = SERVICE_KEYWORDS.get(service, [service.lower()])

        for keyword in keywords[:1]:  # Use first keyword per service
            if keyword in seen_keywords:
                continue
            seen_keywords.add(keyword)

            print(f"  [*] Looking up CVEs for: {keyword} ({service} on port {port_info['port']})")
            cves = lookup_cves_for_keyword(keyword)
            if cves:
                results[f"{service} (Port {port_info['port']})"] = cves
                for c in cves[:3]:
                    print(f"    [{c['severity']}] {c['id']} - Score: {c['score']}")
            else:
                print(f"    [-] No CVEs found for {keyword}")

    print(f"[*] CVE lookup complete. Found CVEs for {len(results)} service(s).")
    return results