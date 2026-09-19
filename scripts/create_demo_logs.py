from pathlib import Path

out_dir = Path("g:/SIH2026/demo_logs_for_upload")
out_dir.mkdir(exist_ok=True)

# 1. CEF Logs
cef_content = """CEF:0|Palo Alto Networks|PAN-OS|10.2.0|TRAFFIC|drop|8|src=198.51.100.23 dst=10.0.0.15 spt=44123 dpt=445 proto=TCP act=drop msg=Exploit SMB attempt detected
CEF:0|Palo Alto Networks|PAN-OS|10.2.0|TRAFFIC|allow|2|src=192.168.1.50 dst=10.0.0.22 spt=51200 dpt=443 proto=TCP act=allow msg=Authorized HTTPS session
CEF:0|Fortinet|FortiGate|7.2.4|IPS|ips-signature|9|src=203.0.113.88 dst=10.0.0.5 spt=59123 dpt=8080 proto=TCP act=deny msg=SQL Injection pattern in HTTP URI
CEF:0|Check Point|SmartDefense|R81.20|Firewall|drop|8|src=185.220.101.5 dst=10.0.0.1 spt=38291 dpt=22 proto=TCP act=deny msg=SSH Brute-force blocked
CEF:0|Cisco|Firepower|7.1.0|CONNECTION|allow|2|src=10.100.5.12 dst=8.8.8.8 spt=61245 dpt=53 proto=UDP act=allow msg=DNS query outbound
CEF:0|Palo Alto Networks|PAN-OS|10.2.0|THREAT|alert|9|src=198.51.100.77 dst=10.0.0.100 spt=49152 dpt=3389 proto=TCP act=alert msg=RDP Credential stuffing attempt
CEF:0|Fortinet|FortiGate|7.2.4|IPS|ips-signature|10|src=198.51.100.99 dst=10.0.0.80 spt=53210 dpt=443 proto=TCP act=deny msg=Zero-Day WebShell upload attempt detected
CEF:0|Palo Alto Networks|PAN-OS|10.2.0|THREAT|drop|8|src=10.0.0.150 dst=203.0.113.200 spt=62111 dpt=53 proto=UDP act=drop msg=DNS Tunneling Command and Control beacon
"""
(out_dir / "01_firewall_and_exploit_alerts.cef").write_text(cef_content.strip() + "\n", encoding="utf-8")

# 2. Syslog
syslog_content = """date=2026-09-06 time=04:30:00 devname="FGT-HQ-DC1" devid="FGT60D12345" type="traffic" subtype="forward" level="warning" action="deny" srcip=198.51.100.89 dstip=10.0.0.12 srcport=54123 dstport=445 proto=6 msg="Policy violation: unauthorized SMB scan"
date=2026-09-06 time=04:30:01 devname="FGT-HQ-DC1" devid="FGT60D12345" type="traffic" subtype="forward" level="notice" action="allow" srcip=192.168.1.100 dstip=10.0.0.25 srcport=52341 dstport=443 proto=6 msg="Normal HTTPS web session"
<134>1 2026-09-06T04:30:02Z fw01.corp Cisco - - - %ASA-4-106023: Deny tcp src outside:203.0.113.44/41200 dst inside:10.0.0.5/22 by access-group "perimeter_in" action=DENY src=203.0.113.44 dst=10.0.0.5 sport=41200 dport=22 proto=TCP
<134>1 2026-09-06T04:30:03Z fw01.corp Cisco - - - %ASA-6-302013: Built inbound TCP connection for outside:172.16.5.10/50123 to inside:10.0.0.80/80 action=ALLOW src=172.16.5.10 dst=10.0.0.80 sport=50123 dport=80 proto=TCP
Sep  6 04:30:04 auth-server sshd[9842]: Failed password for invalid user root from 185.220.101.9 port 39812 ssh2 action=DENY src=185.220.101.9 dst=10.0.0.2 sport=39812 dport=22
Sep  6 04:30:05 auth-server sshd[9843]: Failed password for invalid user admin from 185.220.101.9 port 39814 ssh2 action=DENY src=185.220.101.9 dst=10.0.0.2 sport=39814 dport=22
Sep  6 04:30:06 auth-server sudo: pam_unix(sudo:auth): authentication failure; logname=operator uid=1001 euid=0 tty=/dev/pts/1 ruser=operator rhost= user=root action=DENY src=10.0.0.50
Sep  6 04:30:07 auth-server sshd[9844]: Accepted publickey for secadmin from 10.0.0.250 port 51234 ssh2 action=ALLOW src=10.0.0.250 dst=10.0.0.2 sport=51234 dport=22
"""
(out_dir / "02_network_auth_and_syslog.log").write_text(syslog_content.strip() + "\n", encoding="utf-8")

# 3. Cloud Audit JSON
cloud_content = """[
  {
    "eventTime": "2026-09-06T04:31:00Z",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "sourceIPAddress": "185.220.101.50",
    "userAgent": "Mozilla/5.0 Kali-Linux",
    "userIdentity": {"type": "Root", "principalId": "112233445566", "arn": "arn:aws:iam::112233445566:root", "accountId": "112233445566"},
    "responseElements": {"ConsoleLogin": "Failure"},
    "action": "DENY",
    "severity": "critical",
    "vendor": "AWS",
    "product": "CloudTrail"
  },
  {
    "eventTime": "2026-09-06T04:31:10Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "PutBucketPolicy",
    "sourceIPAddress": "203.0.113.15",
    "userIdentity": {"type": "IAMUser", "userName": "temp_dev"},
    "requestParameters": {"bucketName": "prod-database-backups", "policy": "PublicReadAllowed"},
    "action": "ALERT",
    "severity": "high",
    "vendor": "AWS",
    "product": "CloudTrail"
  },
  {
    "eventTime": "2026-09-06T04:31:20Z",
    "eventSource": "cloudresourcemanager.googleapis.com",
    "eventName": "SetIamPolicy",
    "sourceIPAddress": "198.51.100.42",
    "userIdentity": {"email": "attacker-service-account@external.iam.gserviceaccount.com"},
    "action": "DENY",
    "severity": "critical",
    "vendor": "GCP",
    "product": "CloudAudit"
  },
  {
    "eventTime": "2026-09-06T04:31:30Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "DescribeInstances",
    "sourceIPAddress": "10.0.0.10",
    "userIdentity": {"type": "IAMUser", "userName": "ops_monitoring"},
    "action": "ALLOW",
    "severity": "info",
    "vendor": "AWS",
    "product": "CloudTrail"
  }
]"""
(out_dir / "03_cloud_infrastructure_audit.json").write_text(cloud_content.strip() + "\n", encoding="utf-8")

# 4. NDJSON Next-Gen UTM Threats
ndjson_content = """{"acme_src": "198.51.100.33", "acme_dst": "10.0.0.1", "acme_sport": 51234, "acme_dport": 80, "acme_disposition": "BLOCK", "acme_threat_level": "critical", "acme_proto": "TCP", "vendor": "AcmeSecurity", "attack_type": "SQL_Injection_Bypass"}
{"acme_src": "198.51.100.44", "acme_dst": "10.0.0.2", "acme_sport": 51235, "acme_dport": 443, "acme_disposition": "ALLOW", "acme_threat_level": "low", "acme_proto": "TCP", "vendor": "AcmeSecurity", "attack_type": "Normal_Traffic"}
{"acme_src": "203.0.113.99", "acme_dst": "10.0.0.99", "acme_sport": 60123, "acme_dport": 3389, "acme_disposition": "DROP", "acme_threat_level": "high", "acme_proto": "TCP", "vendor": "AcmeSecurity", "attack_type": "Remote_Code_Execution"}
{"acme_src": "185.220.101.77", "acme_dst": "10.0.0.80", "acme_sport": 48120, "acme_dport": 8080, "acme_disposition": "BLOCK", "acme_threat_level": "critical", "acme_proto": "TCP", "vendor": "AcmeSecurity", "attack_type": "Log4j_JNDI_Exploit"}
"""
(out_dir / "04_utm_zero_day_threats.ndjson").write_text(ndjson_content.strip() + "\n", encoding="utf-8")

# 5. CSV Network Traffic
csv_content = """timestamp,src_ip,dst_ip,src_port,dst_port,protocol,action,severity,vendor,bytes
2026-09-06T04:32:00Z,198.51.100.12,10.0.0.50,44123,445,TCP,DENY,critical,Fortinet,0
2026-09-06T04:32:01Z,192.168.1.100,10.0.0.20,52100,443,TCP,ALLOW,info,Fortinet,8192
2026-09-06T04:32:02Z,203.0.113.55,10.0.0.50,44124,3389,TCP,DROP,high,CheckPoint,0
2026-09-06T04:32:03Z,185.220.101.88,10.0.0.22,39120,22,TCP,DENY,high,CheckPoint,0
2026-09-06T04:32:04Z,10.0.0.15,8.8.8.8,55231,53,UDP,ALLOW,info,Cisco,128
"""
(out_dir / "05_firewall_traffic_stream.csv").write_text(csv_content.strip() + "\n", encoding="utf-8")

print("Created 5 demo files successfully in demo_logs_for_upload/")
