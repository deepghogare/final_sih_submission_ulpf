"""
Network Field Normalization Engine for ULPF.
Standardizes IP addresses, transport ports, protocols, and directions.
"""

import ipaddress
from typing import Optional, Union

PROTOCOL_NUMBER_MAP = {
    "1": "ICMP",
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "41": "IPv6",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSPF",
}


def normalize_ip(raw_ip: Optional[Union[str, int]]) -> Optional[str]:
    """
    Validates and formats an IPv4 or IPv6 address.
    Returns: canonical IP string or None if invalid.
    """
    if raw_ip is None:
        return None
    cleaned = str(raw_ip).strip().strip("[]\"'")
    if not cleaned or cleaned in ("-", "null", "None", "0.0.0.0/0"):
        return None
    # Strip port if attached as ip:port (for IPv4 only)
    if ":" in cleaned and "." in cleaned and cleaned.count(":") == 1:
        cleaned = cleaned.split(":")[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        return str(ip_obj)
    except ValueError:
        return None


def normalize_port(raw_port: Optional[Union[int, str]]) -> Optional[int]:
    """
    Converts and validates port number (1-65535).
    Returns: integer or None if invalid.
    """
    if raw_port is None:
        return None
    try:
        val = int(str(raw_port).strip().strip("\"'"))
        if 1 <= val <= 65535:
            return val
        return None
    except (ValueError, TypeError):
        return None


def normalize_protocol(raw_proto: Optional[Union[str, int]]) -> Optional[str]:
    """
    Normalizes transport protocol names and numbers to uppercase canonical names.
    (e.g. 6 -> 'TCP', 'tcp' -> 'TCP', 'udp' -> 'UDP').
    """
    if raw_proto is None:
        return None
    s = str(raw_proto).strip().strip("\"'")
    if not s or s in ("-", "null"):
        return None

    if s in PROTOCOL_NUMBER_MAP:
        return PROTOCOL_NUMBER_MAP[s]

    upper = s.upper()
    if upper in ("TCP", "UDP", "ICMP", "ICMPV6", "IGMP", "GRE", "ESP", "AH", "OSPF", "HTTP", "HTTPS", "DNS", "SSH", "TLS"):
        return upper
    return upper


def normalize_direction(raw_dir: Optional[str]) -> Optional[str]:
    """
    Normalizes network traffic direction to: inbound, outbound, internal, unknown.
    """
    if not raw_dir:
        return None
    cleaned = str(raw_dir).strip().lower()
    if cleaned in ("in", "inbound", "ingress", "incoming", "0"):
        return "inbound"
    if cleaned in ("out", "outbound", "egress", "outgoing", "1"):
        return "outbound"
    if cleaned in ("int", "internal", "lateral", "inside", "local"):
        return "internal"
    return "unknown"
