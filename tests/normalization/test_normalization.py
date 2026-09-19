"""
Unit Tests for Normalization Engine.
"""

from app.normalization.timestamp import normalize_timestamp
from app.normalization.network import normalize_ip, normalize_port, normalize_protocol
from app.normalization.actions import normalize_action
from app.normalization.severity import normalize_severity


def test_timestamp_normalization():
    # ISO 8601
    assert normalize_timestamp("2026-09-02T17:30:15Z") == "2026-09-02T17:30:15Z"
    # Epoch seconds
    assert normalize_timestamp(1788370215) == "2026-09-02T17:30:15Z"
    # CEF date format
    assert normalize_timestamp("Sep 02 2026 17:30:15") == "2026-09-02T17:30:15Z"


def test_ip_normalization():
    assert normalize_ip("192.168.1.1") == "192.168.1.1"
    assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert normalize_ip("invalid_ip_format") is None
    assert normalize_ip(None) is None


def test_port_normalization():
    assert normalize_port(80) == 80
    assert normalize_port("443") == 443
    assert normalize_port(0) is None
    assert normalize_port(70000) is None
    assert normalize_port("invalid") is None


def test_protocol_normalization():
    assert normalize_protocol(6) == "TCP"
    assert normalize_protocol("17") == "UDP"
    assert normalize_protocol("tcp") == "TCP"
    assert normalize_protocol("icmp") == "ICMP"


def test_action_normalization():
    # Deny variants
    assert normalize_action("DENY") == "deny"
    assert normalize_action("BLOCK") == "deny"
    assert normalize_action("DROP") == "deny"
    assert normalize_action("REJECT") == "deny"

    # Allow variants
    assert normalize_action("ALLOW") == "allow"
    assert normalize_action("PERMIT") == "allow"
    assert normalize_action("ACCEPT") == "allow"
    assert normalize_action("PASS") == "allow"


def test_severity_normalization():
    assert normalize_severity("high") == "high"
    assert normalize_severity("informational") == "info"
    assert normalize_severity("emerg") == "critical"
    assert normalize_severity(10) == "critical"
    assert normalize_severity(1) == "info"
