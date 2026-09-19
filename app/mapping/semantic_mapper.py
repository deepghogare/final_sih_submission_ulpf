"""
Semantic Synonym Dictionary and Field Taxonomy for ULPF.
Defines canonical field categories and known vendor aliases.
"""

from typing import Dict, List, Set

# Universal schema canonical targets mapped to known synonyms
SEMANTIC_ALIASES: Dict[str, List[str]] = {
    "source.ip": [
        "src_ip", "source_ip", "sourceaddress", "srcip", "source_addr",
        "src", "client_ip", "clientip", "c_ip", "orig_ip", "src_ipv4",
        "src_ipv6", "sourceipaddress", "src_host_ip"
    ],
    "source.port": [
        "src_port", "sourceport", "sport", "srcport", "source_port_num",
        "c_port", "client_port", "orig_port", "srcportnumber"
    ],
    "source.hostname": [
        "src_host", "sourcehostname", "srchost", "client_host",
        "src_name", "source_machine_name", "workstation"
    ],
    "source.mac": [
        "src_mac", "sourcemac", "sourcemacaddress", "smac", "client_mac"
    ],
    "destination.ip": [
        "dst_ip", "destination_ip", "destinationaddress", "dstip",
        "dest_ip", "dst", "server_ip", "serverip", "s_ip", "resp_ip",
        "dst_ipv4", "dst_ipv6", "target_ip", "destinationipaddress"
    ],
    "destination.port": [
        "dst_port", "destinationport", "dport", "dstport", "dest_port",
        "s_port", "server_port", "resp_port", "target_port", "dstportnumber"
    ],
    "destination.hostname": [
        "dst_host", "destinationhostname", "dsthost", "server_host",
        "dest_host", "target_host", "dst_name"
    ],
    "network.protocol": [
        "proto", "protocol", "transportprotocol", "net_proto", "trans_proto",
        "service", "app_proto"
    ],
    "network.direction": [
        "direction", "trafficdirection", "dir", "flow_direction"
    ],
    "network.bytes": [
        "bytes", "bytestotal", "bytes_transferred", "bytes_in", "bytes_out",
        "totallength", "sentbytes", "rcvdbytes"
    ],
    "network.packets": [
        "packets", "packetcount", "pkts", "totalpackets", "sentpkts", "rcvdpkts"
    ],
    "event.action": [
        "action", "decision", "act", "disposition", "status",
        "event_action", "filter_result", "verdict"
    ],
    "event.severity": [
        "severity", "priority", "level", "sev", "log_level", "alert_level",
        "syslog_severity"
    ],
    "event.type": [
        "type", "event_type", "eventtype", "activity"
    ],
    "event.category": [
        "category", "classification", "cat", "event_category", "class"
    ],
    "event.timestamp": [
        "timestamp", "eventtime", "time", "date", "logtime",
        "generationtime", "occurred", "datetime"
    ],
    "device.vendor": [
        "vendor", "devvendor", "device_vendor", "devicevendor", "make"
    ],
    "device.product": [
        "product", "devname", "device_product", "deviceproduct", "model"
    ],
    "device.hostname": [
        "device_id", "devhostname", "dev_host", "firewall_name",
        "reporting_device", "host", "dvc"
    ],
    "device.device_type": [
        "device_type", "devicetype", "dev_type"
    ],
    "user.name": [
        "user", "username", "accountuser", "account_name", "user_name",
        "src_user", "dst_user", "usr", "user_id_str"
    ],
    "user.id": [
        "user_id", "accountid", "uid", "sid", "target_user_id"
    ],
    "process.name": [
        "process", "process_name", "app", "application", "proc_name",
        "image_name", "program"
    ],
    "process.id": [
        "pid", "proc_id", "process_id"
    ],
    "threat.name": [
        "threat_name", "signature", "threat", "rule_name", "alert_name"
    ],
    "threat.id": [
        "threat_id", "cve", "signature_id", "rule_id", "sig_id"
    ],
}

# Inverted lookup for O(1) matching: lowercase_alias -> target_field
ALIAS_LOOKUP: Dict[str, str] = {}
for target, aliases in SEMANTIC_ALIASES.items():
    for alias in aliases:
        ALIAS_LOOKUP[alias.lower().replace("_", "").replace("-", "")] = target
