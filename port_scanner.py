import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

TARGET = input("Enter target IP: ")
PORTS = range(1, 1025)
TIMEOUT = 1

results = []

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NETBIOS",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP-ALT"
}

def get_risk(port):
    if port in [23, 445, 139]:
        return "HIGH"
    elif port in [21, 3306, 8080, 25]:
        return "MEDIUM"
    else:
        return "LOW"


def scan_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)

        result = sock.connect_ex((TARGET, port))

        if result == 0:
            service = SERVICE_MAP.get(port, "UNKNOWN")
            risk = get_risk(port)

            banner = "No banner"

            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
                if data:
                    banner = data.decode(errors="ignore").strip()
            except:
                pass

            print(f"[+] {port} OPEN | {service} | {risk}")

            results.append({
                "port": port,
                "service": service,
                "risk": risk,
                "banner": banner
            })

        sock.close()

    except:
        pass


def save_report():
    report = {
        "target": TARGET,
        "scan_time": str(datetime.now()),
        "total_ports_scanned": len(PORTS),
        "open_ports": len(results),
        "results": results
    }

    filename = f"scan_report_{TARGET.replace('.', '_')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved: {filename}")


def summary():
    print("\n========== SCAN SUMMARY ==========")
    print(f"Target: {TARGET}")
    print(f"Open Ports Found: {len(results)}")

    if results:
        print("\nHigh Risk Ports:")
        for r in results:
            if r["risk"] == "HIGH":
                print(f"- {r['port']} ({r['service']})")

    print("==================================\n")


def run_scanner():
    print(f"\n[+] Starting Advanced Scan on {TARGET}\n")

    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(scan_port, PORTS)


if __name__ == "__main__":
    run_scanner()
    summary()
    save_report()
