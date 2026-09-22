#!/usr/bin/env python3
"""
Send a short attack sequence to TRACELOG as syslog: a scan, a web scanner probe, a path
traversal attempt, an SQL injection probe (lines in the format Suricata writes to syslog)
and a failed SSH login. Use it to watch events arrive live in the dashboard.

    python scripts/send_sample_attack.py                       # UDP syslog to 127.0.0.1:5514 (python run_app.py)
    python scripts/send_sample_attack.py --port 514            # docker compose publishes syslog on 514
    python scripts/send_sample_attack.py --http http://127.0.0.1:8000/api/ingest/stream

The lines are samples, not captured traffic. For live alerts from a real sensor, use
docker-compose.devices.yml (README, "Live demo with a real sensor").
"""
import argparse
import socket
import sys
import time
import urllib.request
from typing import Any, Dict, List

SAMPLE_EVENTS: List[Dict[str, Any]] = [
    {
        "name": "Nmap Port Reconnaissance Scan",
        "format": "syslog_rfc3164",
        "syslog": "<132>Sep 15 20:30:15 suricata-ids01 suricata[4102]: [1:2001211:3] ET SCAN Nmap Scripting Engine User-Agent Detected [Classification: Attempted Reconnaissance] [Priority: 1] {TCP} 192.168.1.50:54321 -> 10.0.0.5:80",
        "description": "Suricata IDS flagged Nmap port scan targeting web server"
    },
    {
        "name": "Nikto Web Vulnerability Scanner Probe",
        "format": "syslog_rfc3164",
        "syslog": "<132>Sep 15 20:30:18 suricata-ids01 suricata[4102]: [1:2002441:2] ET WEB_SERVER Nikto Web Scanner Attack Signature [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.50:54322 -> 10.0.0.5:80",
        "description": "Suricata IDS detected automated vulnerability scanner HTTP probe"
    },
    {
        "name": "Directory Traversal Exploit Attempt (/etc/passwd)",
        "format": "syslog_rfc3164",
        "syslog": "<131>Sep 15 20:30:22 suricata-ids01 suricata[4102]: [1:2010002:4] ET WEB_SERVER Path Traversal Attempt /etc/passwd Access [Classification: Policy Violation] [Priority: 2] {TCP} 192.168.1.50:54323 -> 10.0.0.5:80",
        "description": "Suricata IDS detected path traversal attempt trying to read system shadow files"
    },
    {
        "name": "SQL Injection Probe (OR 1=1)",
        "format": "syslog_rfc3164",
        "syslog": "<131>Sep 15 20:30:25 suricata-ids01 suricata[4102]: [1:2014889:1] ET WEB_SERVER SQL Injection Attempt 'OR 1=1' in URI Query [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.1.50:54324 -> 10.0.0.5:80",
        "description": "Suricata IDS blocked SQL injection attempt targeting database endpoints"
    },
    {
        "name": "SSH Brute Force Failed Authentication",
        "format": "syslog_rfc3164",
        "syslog": "<134>Sep 15 20:30:30 firewall01 pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.50  user=root",
        "description": "Perimeter host PAM logged SSH brute-force logon failure for root account"
    }
]


def send_udp(line: str, host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(line.encode("utf-8"), (host, port))


def send_http(line: str, url: str, token: str = "") -> int:
    headers = {"Content-Type": "text/plain"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=line.encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return resp.status


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5514)
    ap.add_argument("--http", metavar="URL", help="send to the HTTP stream receiver instead of UDP syslog")
    ap.add_argument("--token", default="", help="receiver token, if tokens are configured")
    ap.add_argument("--delay", type=float, default=0.5, help="seconds between lines")
    args = ap.parse_args()
    target = args.http or f"udp://{args.host}:{args.port}"
    print(f"Sending {len(SAMPLE_EVENTS)} sample lines to {target}")
    for i, evt in enumerate(SAMPLE_EVENTS, 1):
        try:
            if args.http:
                send_http(evt["syslog"], args.http, args.token)
            else:
                send_udp(evt["syslog"], args.host, args.port)
            print(f"  [{i}/{len(SAMPLE_EVENTS)}] sent: {evt['name']}")
        except Exception as exc:
            print(f"  [{i}/{len(SAMPLE_EVENTS)}] FAILED ({exc}): {evt['name']}")
            return 1
        time.sleep(args.delay)
    print("Done. Open the dashboard: Log Explorer, and Correlation & RCA for the sequence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
