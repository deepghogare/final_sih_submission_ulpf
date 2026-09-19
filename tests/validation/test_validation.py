"""
Unit Tests for Universal Event Validation.
"""

from app.validation.validator import Validator
from app.integrity.hashing import calculate_sha256


def get_base_event_dict():
    raw_str = "src_ip=192.168.1.1 dst_ip=10.0.0.1 action=deny"
    return {
        "event_id": "ULPF-test01",
        "schema_version": "1.0",
        "event": {
            "timestamp": "2026-09-02T17:30:15Z",
            "action": "deny",
            "severity": "medium"
        },
        "source": {
            "ip": "192.168.1.1",
            "port": 443
        },
        "destination": {
            "ip": "10.0.0.1",
            "port": 80
        },
        "network": {
            "protocol": "TCP"
        },
        "device": {
            "vendor": "TestVendor"
        },
        "metadata": {
            "ingestion_timestamp": "2026-09-02T17:30:16Z",
            "parser": "text",
            "parser_version": "1.0",
            "mapping_version": "1.0",
            "raw_event_hash": calculate_sha256(raw_str)
        },
        "raw": {
            "data": raw_str,
            "format": "text"
        },
        "extensions": {}
    }


def test_valid_event():
    validator = Validator()
    event_dict = get_base_event_dict()
    is_valid, obj, err = validator.validate(event_dict)
    assert is_valid is True
    assert obj is not None
    assert err is None


def test_invalid_ip_fails_validation():
    validator = Validator()
    event_dict = get_base_event_dict()
    event_dict["source"]["ip"] = "999.999.999.999"
    is_valid, obj, err = validator.validate(event_dict)
    assert is_valid is False
    assert "Invalid source IP" in err


def test_invalid_port_fails_validation():
    validator = Validator()
    event_dict = get_base_event_dict()
    event_dict["source"]["port"] = 70000
    is_valid, obj, err = validator.validate(event_dict)
    assert is_valid is False
    assert "port out of range" in err


def test_hash_mismatch_fails_validation():
    validator = Validator()
    event_dict = get_base_event_dict()
    event_dict["metadata"]["raw_event_hash"] = "0" * 64
    is_valid, obj, err = validator.validate(event_dict, verify_hash=True)
    assert is_valid is False
    assert "hash mismatch" in err
