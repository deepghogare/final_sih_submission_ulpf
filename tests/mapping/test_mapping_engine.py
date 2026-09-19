"""
Unit Tests for MappingEngine and Semantic Synonym Taxonomy.
"""

from pathlib import Path
from app.mapping.mapping_engine import MappingEngine
from app.models.parsed_event import ParsedEvent


def test_explicit_vendor_mapping():
    engine = MappingEngine(Path("configs/mappings"))
    parsed = ParsedEvent(
        raw_data="test",
        format="json",
        fields={
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.1",
            "action": "DENY",
            "vendor": "VendorA"
        },
        detected_vendor="VendorA"
    )
    mapped, conf = engine.map_event(parsed)
    assert mapped["source"]["ip"] == "192.168.1.1"
    assert mapped["destination"]["ip"] == "10.0.0.1"
    assert mapped["event"]["action"] == "DENY"
    assert mapped["device"]["vendor"] == "VendorA"


def test_semantic_alias_resolution():
    engine = MappingEngine()
    parsed = ParsedEvent(
        raw_data="test",
        format="json",
        fields={
            "client_ip": "172.16.0.5",
            "server_ip": "8.8.8.8",
            "decision": "BLOCK"
        }
    )
    mapped, conf = engine.map_event(parsed)
    assert mapped["source"]["ip"] == "172.16.0.5"
    assert mapped["destination"]["ip"] == "8.8.8.8"
    assert mapped["event"]["action"] == "BLOCK"


def test_extensions_preservation():
    engine = MappingEngine()
    parsed = ParsedEvent(
        raw_data="test",
        format="json",
        fields={
            "src_ip": "192.168.1.1",
            "completely_unknown_vendor_sensor_id": "SENSOR-9999",
            "custom_payload_hash": "0xABCDEF"
        }
    )
    mapped, conf = engine.map_event(parsed)
    assert mapped["source"]["ip"] == "192.168.1.1"
    # Unknown fields preserved in extensions
    assert mapped["extensions"]["completely_unknown_vendor_sensor_id"] == "SENSOR-9999"
    assert mapped["extensions"]["custom_payload_hash"] == "0xABCDEF"
