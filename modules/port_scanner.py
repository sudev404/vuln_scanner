import socket
import concurrent.futures
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

RISKY_PORTS = {
    21: "FTP - Often allows anonymous login; transmits data in cleartext",
    23: "Telnet - Unencrypted remote access; highly vulnerable",
    445: "SMB - Exploited by EternalBlue/WannaCry ransomware",
    3389: "RDP - Common brute-force target; vulnerable to BlueKeep",
    6379: "Redis - Often exposed without authentication",
    27017: "MongoDB - Often exposed without authentication",
}


def scan_port(host, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                try:
                    banner = ""
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()[:100]
                except Exception:
                    banner = ""
                return {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "risk": RISKY_PORTS.get(port, None)
                }
    except Exception:
        pass
    return None


def run_port_scan(target, port_range=(1, 1024), threads=100):
    print(f"[*] Starting port scan on {target} (ports {port_range[0]}-{port_range[1]})...")
    start_time = datetime.now()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(port_range[0], port_range[1] + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                risk_tag = " ⚠️  RISKY" if result["risk"] else ""
                print(f"  [+] Port {result['port']}/tcp  OPEN  ({result['service']}){risk_tag}")

    duration = (datetime.now() - start_time).total_seconds()
    open_ports.sort(key=lambda x: x["port"])
    print(f"[*] Port scan complete. {len(open_ports)} open port(s) found in {duration:.2f}s")
    return open_ports