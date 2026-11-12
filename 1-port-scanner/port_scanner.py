"""
Simple Multithreaded Port Scanner
Usage: python port_scanner.py <host> [-s START] [-e END] [-t THREADS]
ONLY scan machines you own or have permission to test (e.g. 127.0.0.1, scanme.nmap.org).
"""
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
}

def scan_port(host, port, timeout=0.5):
    """Try to connect to one port. Returns (port, banner) if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:   # 0 means connection succeeded
                banner = ""
                try:
                    s.sendall(b"\r\n")
                    banner = s.recv(100).decode(errors="ignore").strip().split("\n")[0]
                except Exception:
                    pass
                return port, banner
    except Exception:
        pass
    return None

def main():
    p = argparse.ArgumentParser(description="Simple multithreaded port scanner")
    p.add_argument("host")
    p.add_argument("-s", "--start", type=int, default=1)
    p.add_argument("-e", "--end", type=int, default=1024)
    p.add_argument("-t", "--threads", type=int, default=100)
    a = p.parse_args()

    try:
        ip = socket.gethostbyname(a.host)
    except socket.gaierror:
        print("Could not resolve host."); return

    print(f"Scanning {a.host} ({ip}) ports {a.start}-{a.end}")
    print(f"Started: {datetime.now():%Y-%m-%d %H:%M:%S}\n")

    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        results = ex.map(lambda port: scan_port(ip, port), range(a.start, a.end + 1))
        open_ports = sorted(r for r in results if r)

    print(f"{'PORT':<8}{'SERVICE':<12}BANNER")
    print("-" * 50)
    for port, banner in open_ports:
        print(f"{port:<8}{COMMON_SERVICES.get(port, 'unknown'):<12}{banner}")
    print(f"\nDone. {len(open_ports)} open port(s) found.")

if __name__ == "__main__":
    main()
