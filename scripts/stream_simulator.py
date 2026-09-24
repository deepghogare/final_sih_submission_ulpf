"""
Stream Simulator Script for ULPF.
Generates and sends realistic real-time Syslog (RFC 3164/5424), CEF, and JSON logs
over UDP or TCP sockets to demonstrate live log ingestion during SIH pitch presentations.
"""

import socket
import time
import random
import argparse
from datetime import datetime, timezone

SAMPLE_LOGS = [
    # Syslog RFC 3164 (Cisco ASA / Linux SSH)
    "<34>1 2026-09-23T23:45:00.123Z firewall.corp.local %ASA-6-302013: Built inbound TCP connection 120934 for outside:198.51.100.45/443 to inside:10.0.1.20/54321",
    "<86>Sep 23 23:45:01 auth-server sshd[14022]: Failed password for root from 203.0.113.195 port 42100 ssh2",

    # Syslog RFC 5424
    "<165>1 2026-09-23T23:45:02.004Z host-01.corp.internal app-service 4912 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] User login succeeded for admin",

    # ArcSight CEF
    "CEF:0|PaloAltoNetworks|PAN-OS|10.1.0|TRAFFIC|end|3|src=192.168.1.105 dst=10.0.4.12 spt=51200 dpt=80 proto=tcp act=ALLOW msg=Web browsing traffic",

    # JSON Network Security Log
    '{"timestamp": "2026-09-23T23:45:03Z", "vendor": "Fortinet", "src_ip": "172.16.0.45", "dst_ip": "10.0.0.1", "src_port": 61200, "dst_port": 53, "action": "DENY", "severity": "HIGH", "message": "DNS Sinkhole Block"}',

    # IBM QRadar LEEF 2.0
    "LEEF:2.0|CheckPoint|FW1|6.0|Accept|devTime=2026-09-23T23:45:04Z\tusrName=jdoe\tsrc=10.10.1.50\tdst=10.10.2.100\tproto=TCP\tsrcPort=49300\tdstPort=22",

    # XML Windows Event Log
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><Level>0</Level><TimeCreated SystemTime="2026-09-23T23:45:05.000Z"/></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="WorkstationName">DC-01</Data><Data Name="IpAddress">192.168.10.200</Data></EventData></Event>'
]


def send_udp(host: str, port: int, count: int, delay: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Streaming {count} events over UDP to {host}:{port} (Delay: {delay}s)...")
    for i in range(1, count + 1):
        raw_log = random.choice(SAMPLE_LOGS)
        sock.sendto(raw_log.encode("utf-8"), (host, port))
        if i % 10 == 0 or i == count:
            print(f"  [UDP] Sent {i}/{count} events", end="\r", flush=True)
        time.sleep(delay)
    sock.close()
    print(f"\n[+] UDP streaming complete ({count} events sent).")


def send_tcp(host: str, port: int, count: int, delay: float):
    print(f"[*] Connecting TCP stream socket to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except Exception as e:
        print(f"[!] Failed to connect TCP socket to {host}:{port}: {e}")
        return

    print(f"[*] Streaming {count} events over TCP connection...")
    try:
        for i in range(1, count + 1):
            raw_log = random.choice(SAMPLE_LOGS) + "\n"
            sock.sendall(raw_log.encode("utf-8"))
            if i % 10 == 0 or i == count:
                print(f"  [TCP] Sent {i}/{count} events", end="\r", flush=True)
            time.sleep(delay)
    finally:
        sock.close()
    print(f"\n[+] TCP streaming complete ({count} events sent).")


def main():
    parser = argparse.ArgumentParser(description="ULPF Real-time Log Stream Simulator")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Protocol (udp or tcp)")
    parser.add_argument("--host", default="127.0.0.1", help="Target listener IP")
    parser.add_argument("--port", type=int, default=5140, help="Target listener port")
    parser.add_argument("-n", "--count", type=int, default=100, help="Total events to stream")
    parser.add_argument("-r", "--rate", type=float, default=20.0, help="Events per second rate")

    args = parser.parse_args()
    delay = 1.0 / max(0.1, args.rate)

    if args.protocol == "udp":
        send_udp(args.host, args.port, args.count, delay)
    else:
        send_tcp(args.host, args.port, args.count, delay)


if __name__ == "__main__":
    main()

