"""
Master Normalization Orchestrator for ULPF.
Coordinates semantic normalization across timestamps, network endpoints, actions, and severities.
"""

from typing import Dict, Any, Optional
from app.normalization.timestamp import normalize_timestamp
from app.normalization.network import (
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_direction,
)
from app.normalization.actions import normalize_action
from app.normalization.severity import normalize_severity


class Normalizer:
    """
    Applies standard normalization rules to a mapped event dictionary.
    Guarantees that canonical fields adhere to Universal Schema standards.
    """

    def normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes structured event dictionary (produced by mapping engine)
        and normalizes values in-place.
        """
        # 1. Event details
        event_sec = event_dict.setdefault("event", {})
        if "timestamp" in event_sec:
            event_sec["timestamp"] = normalize_timestamp(event_sec["timestamp"])
        if "action" in event_sec:
            event_sec["action"] = normalize_action(event_sec["action"])
        if "severity" in event_sec:
            event_sec["severity"] = normalize_severity(event_sec["severity"])

        # 2. Source endpoint
        src_sec = event_dict.setdefault("source", {})
        if "ip" in src_sec:
            src_sec["ip"] = normalize_ip(src_sec["ip"])
        if "port" in src_sec:
            src_sec["port"] = normalize_port(src_sec["port"])

        # 3. Destination endpoint
        dst_sec = event_dict.setdefault("destination", {})
        if "ip" in dst_sec:
            dst_sec["ip"] = normalize_ip(dst_sec["ip"])
        if "port" in dst_sec:
            dst_sec["port"] = normalize_port(dst_sec["port"])

        # 4. Network details
        net_sec = event_dict.setdefault("network", {})
        if "protocol" in net_sec:
            net_sec["protocol"] = normalize_protocol(net_sec["protocol"])
        if "direction" in net_sec:
            net_sec["direction"] = normalize_direction(net_sec["direction"])
        for metric in ("bytes", "packets"):
            if metric in net_sec and net_sec[metric] is not None:
                try:
                    net_sec[metric] = int(net_sec[metric])
                except (ValueError, TypeError):
                    net_sec[metric] = None

        return event_dict


default_normalizer = Normalizer()
