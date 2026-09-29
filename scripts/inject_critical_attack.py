import socket
import time

CRITICAL_LOGS = [
    # SSH Brute Force (Triggers multiple failed auth Wazuh rules - Level 10+)
    '<86>Sep 23 23:45:01 auth-server sshd[14022]: Failed password for root from 185.112.55.22 port 42100 ssh2',
    '<86>Sep 23 23:45:02 auth-server sshd[14022]: Failed password for admin from 185.112.55.22 port 42101 ssh2',
    '<86>Sep 23 23:45:03 auth-server sshd[14022]: Failed password for user1 from 185.112.55.22 port 42102 ssh2',
    
    # RDP Brute Force
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">Administrator</Data><Data Name="IpAddress">203.0.113.10</Data></EventData></Event>',
    
    # Critical Network Drop / Block
    '{"timestamp": "2026-09-23T23:45:03Z", "vendor": "Fortinet", "src_ip": "85.122.14.9", "dst_ip": "10.0.0.1", "action": "DENY", "severity": "CRITICAL", "message": "Malware Command and Control Blocked"}'
]

def blast_criticals(host='127.0.0.1', port=5140, count=500):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Initiating CRITICAL ATTACK SIMULATION to {host}:{port}...")
    for i in range(count):
        log = CRITICAL_LOGS[i % len(CRITICAL_LOGS)]
        sock.sendto(log.encode('utf-8'), (host, port))
        time.sleep(0.01) # 100 EPS
    
    print(f"[+] Sent {count} critical attack signatures successfully.")
    print("[-] Check your ULPF Dashboard and Wazuh SIEM to see the Critical alerts spike!")

if __name__ == '__main__':
    blast_criticals()
