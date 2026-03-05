import os
from datetime import datetime
from html import escape
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

SEVERITY_COLORS = {
    "CRITICAL": "#cc0000",
    "HIGH":     "#e85d04",
    "MEDIUM":   "#f48c06",
    "LOW":      "#90be6d",
    "N/A":      "#6c757d",
    "INFO":     "#0077b6",
}

SEVERITY_BG = {
    "CRITICAL": colors.HexColor("#fff0f0"),
    "HIGH":     colors.HexColor("#fff4ee"),
    "MEDIUM":   colors.HexColor("#fffbee"),
    "LOW":      colors.HexColor("#f0fff4"),
    "N/A":      colors.HexColor("#f8f9fa"),
}


def severity_color(sev):
    return colors.HexColor(SEVERITY_COLORS.get(str(sev).upper(), "#6c757d"))


def count_severity(findings_list):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings_list:
        sev = str(f.get("severity", "")).upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def generate_pdf_report(scan_data, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    style_title = ParagraphStyle("ReportTitle", parent=styles["Title"],
                                  fontSize=26, spaceAfter=6, textColor=colors.HexColor("#1a1a2e"), alignment=TA_LEFT)
    style_subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"],
                                     fontSize=11, textColor=colors.HexColor("#6c757d"), spaceAfter=20)
    style_h1 = ParagraphStyle("H1", parent=styles["Heading1"],
                                fontSize=16, textColor=colors.HexColor("#1a1a2e"),
                                spaceBefore=18, spaceAfter=8,
                                borderPad=4)
    style_h2 = ParagraphStyle("H2", parent=styles["Heading2"],
                                fontSize=12, textColor=colors.HexColor("#16213e"),
                                spaceBefore=12, spaceAfter=6)
    style_body = ParagraphStyle("Body", parent=styles["Normal"],
                                  fontSize=9.5, leading=14, spaceAfter=6)
    style_code = ParagraphStyle("Code", parent=styles["Code"],
                                  fontSize=8.5, backColor=colors.HexColor("#f4f4f4"),
                                  leading=12, leftIndent=10)
    style_small = ParagraphStyle("Small", parent=styles["Normal"],
                                   fontSize=8, textColor=colors.HexColor("#6c757d"))

    target = scan_data.get("target", "Unknown")
    scan_time = scan_data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    story = []

    # ── Cover Header ──────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=4, color=colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Vulnerability Assessment Report", style_title))
    story.append(Paragraph(f"Target: <b>{target}</b> &nbsp;|&nbsp; Scan Date: {scan_time}", style_subtitle))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))
    story.append(Spacer(1, 14))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", style_h1))

    sqli = scan_data.get("sqli", [])
    xss = scan_data.get("xss", [])
    ssl = scan_data.get("ssl", {})
    ports = scan_data.get("ports", [])
    cves = scan_data.get("cves", {})

    all_vulns = sqli + xss + ssl.get("issues", [])
    counts = count_severity(all_vulns)
    total_open = len(ports)
    risky_ports = [p for p in ports if p.get("risk")]

    summary_data = [
        ["Metric", "Value"],
        ["Open Ports Discovered", str(total_open)],
        ["Risky Ports", str(len(risky_ports))],
        ["Services with CVEs", str(len(cves))],
        ["SQLi Findings", str(len(sqli))],
        ["XSS Findings", str(len(xss))],
        ["SSL/TLS Issues", str(len(ssl.get("issues", [])))],
        ["CRITICAL Issues", str(counts["CRITICAL"])],
        ["HIGH Issues", str(counts["HIGH"])],
        ["MEDIUM Issues", str(counts["MEDIUM"])],
    ]

    t = Table(summary_data, colWidths=[3.5 * inch, 2.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 10),
        ("FONTSIZE", (0, 1), (-1, -1), 9.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # ── Port Scan Results ─────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("1. Port Scan Results", style_h1))
    if ports:
        port_data = [["Port", "Service", "State", "Risk"]]
        for p in ports:
            risk_label = "⚠ Risky" if p.get("risk") else "OK"
            risk_color = colors.HexColor("#e85d04") if p.get("risk") else colors.HexColor("#2d6a4f")
            port_data.append([str(p["port"]), p["service"], p["state"], risk_label])
        pt = Table(port_data, colWidths=[1 * inch, 2 * inch, 1.2 * inch, 2.3 * inch])
        pt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f0f4ff")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(pt)

        for p in ports:
            if p.get("risk"):
                story.append(Spacer(1, 6))
                story.append(Paragraph(
                    f"<b>Port {p['port']} ({p['service']}):</b> {p['risk']}",
                    ParagraphStyle("warn", parent=style_body, textColor=colors.HexColor("#e85d04"))
                ))
    else:
        story.append(Paragraph("No open ports discovered.", style_body))

    # ── CVE Results ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(Paragraph("2. CVE Vulnerability Lookup", style_h1))
    if cves:
        for service_label, cve_list in cves.items():
            story.append(Paragraph(f"Service: {service_label}", style_h2))
            cve_data = [["CVE ID", "Severity", "Score", "Description"]]
            for c in cve_list[:5]:
                cve_data.append([c["id"], c["severity"], str(c["score"]), c["description"][:120] + "..."])
            ct = Table(cve_data, colWidths=[1.4 * inch, 0.8 * inch, 0.6 * inch, 3.7 * inch])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#343a40")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e6")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("WORDWRAP", (3, 1), (3, -1), True),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(ct)
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("No CVE data retrieved (no open ports or API unavailable).", style_body))

    # ── SQLi Results ──────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("3. SQL Injection Testing", style_h1))
    if sqli:
        for f in sqli:
            sev = f.get("severity", "HIGH")
            sc = severity_color(sev)
            story.append(Paragraph(
                f'<font color="{SEVERITY_COLORS.get(sev, "#000")}">[{sev}]</font> '
                f'<b>{escape(f["type"])}</b> — Parameter: <i>{escape(f["parameter"])}</i>',
                style_body
            ))
            story.append(Paragraph(f"Payload: <code>{escape(f['payload'])}</code>", style_code))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No SQL injection vulnerabilities detected.", style_body))

    # ── XSS Results ───────────────────────────────────────────────────────────
    story.append(Spacer(1, 16))
    story.append(Paragraph("4. Cross-Site Scripting (XSS) Testing", style_h1))
    if xss:
        for f in xss:
            sev = f.get("severity", "HIGH")
            story.append(Paragraph(
                f'<font color="{SEVERITY_COLORS.get(sev, "#000")}">[{sev}]</font> '
                f'<b>{escape(f.get("type", "XSS"))}</b> — {escape(f.get("description", ""))}',
                style_body
            ))
            if f.get("parameter"):
                story.append(Paragraph(f"Parameter: <i>{escape(f['parameter'])}</i>", style_small))
            if f.get("payload"):
                story.append(Paragraph(f"Payload: <code>{escape(f['payload'])}</code>", style_code))
            story.append(Spacer(1, 6))
    else:
        story.append(Paragraph("No XSS vulnerabilities detected.", style_body))

    # ── SSL/TLS Results ───────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("5. SSL/TLS Configuration", style_h1))
    cert = ssl.get("cert_info", {})
    if cert.get("valid"):
        ssl_data = [
            ["Property", "Value"],
            ["Common Name", cert.get("subject_cn", "N/A")],
            ["Issuer", cert.get("issuer", "N/A")],
            ["Valid From", cert.get("not_before", "N/A")],
            ["Valid Until", cert.get("not_after", "N/A")],
            ["Days Remaining", str(cert.get("days_remaining", "N/A"))],
            ["Protocol", cert.get("protocol", "N/A")],
            ["Cipher Suite", cert.get("cipher", "N/A")],
            ["HSTS", ssl.get("hsts") or "Not Set"],
        ]
        st = Table(ssl_data, colWidths=[2.5 * inch, 4 * inch])
        st.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d6efd")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#e8f4fd")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dee2e6")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(st)

    ssl_issues = ssl.get("issues", [])
    if ssl_issues:
        story.append(Spacer(1, 10))
        story.append(Paragraph("SSL/TLS Issues Found:", style_h2))
        for issue in ssl_issues:
            sev = issue.get("severity", "MEDIUM")
            story.append(Paragraph(
                f'<font color="{SEVERITY_COLORS.get(sev, "#000")}">[{sev}]</font> '
                f'<b>{issue["issue"]}</b>: {issue["detail"]}',
                style_body
            ))
    else:
        story.append(Spacer(1, 8))
        story.append(Paragraph("No SSL/TLS issues detected.", style_body))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dee2e6")))
    story.append(Paragraph(
        f"<i>Report generated on {scan_time}. This assessment is for authorized use only.</i>",
        ParagraphStyle("footer", parent=style_small, alignment=TA_CENTER, spaceBefore=6)
    ))

    doc.build(story)
    print(f"[+] PDF report saved: {output_path}")


def generate_html_report(scan_data, output_path):
    target = scan_data.get("target", "Unknown")
    scan_time = scan_data.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    ports = scan_data.get("ports", [])
    cves = scan_data.get("cves", {})
    sqli = scan_data.get("sqli", [])
    xss = scan_data.get("xss", [])
    ssl = scan_data.get("ssl", {})

    all_vulns = sqli + xss + ssl.get("issues", [])
    counts = count_severity(all_vulns)

    def sev_badge(sev):
        colors_map = {
            "CRITICAL": "#cc0000", "HIGH": "#e85d04",
            "MEDIUM": "#f48c06", "LOW": "#52b788", "N/A": "#6c757d"
        }
        bg = colors_map.get(str(sev).upper(), "#6c757d")
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:700">{sev}</span>'

    def port_rows(ports):
        rows = ""
        for p in ports:
            risk = f'<span style="color:#e85d04">⚠ {p["risk"][:60]}...</span>' if p.get("risk") else '<span style="color:#2d6a4f">✓ OK</span>'
            rows += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td><span style='color:green'>OPEN</span></td><td>{risk}</td></tr>"
        return rows or "<tr><td colspan='4'>No open ports found</td></tr>"

    def cve_section(cves):
        if not cves:
            return "<p>No CVE data retrieved.</p>"
        html = ""
        for service, cve_list in cves.items():
            html += f"<h3 style='color:#16213e'>{service}</h3><table>"
            html += "<tr><th>CVE ID</th><th>Severity</th><th>Score</th><th>Description</th></tr>"
            for c in cve_list[:5]:
                html += f"<tr><td><code>{c['id']}</code></td><td>{sev_badge(c['severity'])}</td><td>{c['score']}</td><td>{c['description'][:200]}...</td></tr>"
            html += "</table>"
        return html

    def vuln_list(findings, label_key="type"):
        if not findings:
            return "<p style='color:green'>✓ No vulnerabilities found.</p>"
        html = ""
        for f in findings:
            sev = f.get("severity", "HIGH")
            html += f"""
            <div style='border-left:4px solid {SEVERITY_COLORS.get(sev,"#999")};padding:10px;margin:8px 0;background:#fafafa;border-radius:0 6px 6px 0'>
                {sev_badge(sev)} <strong>{f.get(label_key, 'Finding')}</strong>
                {f'<br><small>Parameter: <code>{f.get("parameter","")}</code></small>' if f.get("parameter") else ""}
                {f'<br><small>Payload: <code>{f.get("payload","")}</code></small>' if f.get("payload") else ""}
                {f'<br><small>{f.get("detail","")}</small>' if f.get("detail") else ""}
                {f'<br><small>{f.get("description","")}</small>' if f.get("description") else ""}
            </div>"""
        return html

    cert = ssl.get("cert_info", {})
    cert_table = ""
    if cert.get("valid"):
        cert_table = f"""
        <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Common Name</td><td>{cert.get('subject_cn','N/A')}</td></tr>
        <tr><td>Issuer</td><td>{cert.get('issuer','N/A')}</td></tr>
        <tr><td>Valid From</td><td>{cert.get('not_before','N/A')}</td></tr>
        <tr><td>Valid Until</td><td>{cert.get('not_after','N/A')}</td></tr>
        <tr><td>Days Remaining</td><td>{cert.get('days_remaining','N/A')}</td></tr>
        <tr><td>Protocol</td><td>{cert.get('protocol','N/A')}</td></tr>
        <tr><td>Cipher</td><td>{cert.get('cipher','N/A')}</td></tr>
        <tr><td>HSTS</td><td>{ssl.get('hsts') or 'Not Set'}</td></tr>
        </table>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report - {target}</title>
<style>
  :root {{
    --primary: #1a1a2e; --accent: #0d6efd; --danger: #cc0000;
    --warning: #e85d04; --success: #2d6a4f; --light: #f8f9fa;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', sans-serif; background: #f0f2f5; color: #212529; }}
  header {{ background: var(--primary); color: #fff; padding: 2rem; }}
  header h1 {{ font-size: 1.8rem; margin-bottom: 0.4rem; }}
  header p {{ color: #adb5bd; font-size: 0.9rem; }}
  .container {{ max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #fff; border-radius: 10px; padding: 1.2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .card h3 {{ font-size: 0.8rem; color: #6c757d; text-transform: uppercase; letter-spacing: 0.5px; }}
  .card .val {{ font-size: 2rem; font-weight: 700; margin-top: 0.3rem; }}
  .section {{ background: #fff; border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .section h2 {{ font-size: 1.2rem; color: var(--primary); border-bottom: 2px solid #e9ecef; padding-bottom: 0.6rem; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  th {{ background: var(--primary); color: #fff; padding: 0.6rem 0.8rem; text-align: left; }}
  td {{ padding: 0.55rem 0.8rem; border-bottom: 1px solid #e9ecef; }}
  tr:nth-child(even) td {{ background: var(--light); }}
  code {{ background: #f1f3f5; padding: 2px 6px; border-radius: 4px; font-size: 0.82rem; }}
  footer {{ text-align: center; color: #adb5bd; font-size: 0.8rem; padding: 2rem; }}
</style>
</head>
<body>
<header>
  <h1>🔍 Vulnerability Assessment Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; Scan Date: {scan_time}</p>
</header>
<div class="container">
  <div class="summary-grid">
    <div class="card"><h3>Open Ports</h3><div class="val" style="color:var(--accent)">{len(ports)}</div></div>
    <div class="card"><h3>CVE Services</h3><div class="val" style="color:#6610f2">{len(cves)}</div></div>
    <div class="card"><h3>SQLi Findings</h3><div class="val" style="color:var(--warning)">{len(sqli)}</div></div>
    <div class="card"><h3>XSS Findings</h3><div class="val" style="color:var(--warning)">{len(xss)}</div></div>
    <div class="card"><h3>Critical</h3><div class="val" style="color:var(--danger)">{counts['CRITICAL']}</div></div>
    <div class="card"><h3>High</h3><div class="val" style="color:var(--warning)">{counts['HIGH']}</div></div>
  </div>

  <div class="section">
    <h2>1. Port Scan Results</h2>
    <table><tr><th>Port</th><th>Service</th><th>State</th><th>Risk</th></tr>
    {port_rows(ports)}</table>
  </div>

  <div class="section">
    <h2>2. CVE Vulnerability Lookup</h2>
    {cve_section(cves)}
  </div>

  <div class="section">
    <h2>3. SQL Injection Testing</h2>
    {vuln_list(sqli)}
  </div>

  <div class="section">
    <h2>4. Cross-Site Scripting (XSS)</h2>
    {vuln_list(xss)}
  </div>

  <div class="section">
    <h2>5. SSL/TLS Configuration</h2>
    {cert_table}
    <div style="margin-top:1rem">{vuln_list(ssl.get('issues', []), label_key='issue')}</div>
  </div>
</div>
<footer>Report generated on {scan_time}. This assessment is for authorized use only.</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
     f.write(html)
    print(f"[+] HTML report saved: {output_path}")