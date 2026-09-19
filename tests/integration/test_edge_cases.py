"""
Comprehensive Edge Case Test Suite for ULPF.
Verifies all 17 critical edge cases mandated in Section 30 of SIH 2026 Problem Statement.
"""

from pathlib import Path
import pytest
from app.core.pipeline import Pipeline
from app.core.config import AppSettings
from app.integrity.hashing import calculate_sha256, verify_sha256, EventIdTracker
from app.plugins.loader import PluginLoader
from app.plugins.registry import PluginRegistry


@pytest.fixture
def pipeline(tmp_path):
    out_dir = tmp_path / "output"
    fail_dir = tmp_path / "failed_events"
    settings = AppSettings({
        "paths": {"output_dir": str(out_dir), "failed_events_dir": str(fail_dir)},
        "pipeline": {"stop_on_error": False, "enable_enrichment": False}
    })
    return Pipeline(settings=settings)


# Edge Case 1: Multiple events per file
def test_edge_case_multiple_events_per_file(pipeline, tmp_path):
    log_file = tmp_path / "multi.ndjson"
    log_file.write_text(
        '{"src_ip":"192.168.1.1","action":"allow"}\n{"src_ip":"192.168.1.2","action":"deny"}\n',
        encoding="utf-8"
    )
    events = pipeline.process_file(log_file)
    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


# Edge Case 2: Empty file
def test_edge_case_empty_file(pipeline, tmp_path):
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")
    events = pipeline.process_file(empty_file)
    assert events == []


# Edge Case 3: Malformed JSON
def test_edge_case_malformed_json(pipeline, tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text('{"src_ip": "1.2.3.4", BROKEN_JSON', encoding="utf-8")
    events = pipeline.process_file(bad_json)
    assert len(events) == 0
    assert pipeline.metrics.parsing_failures >= 1


# Edge Case 4: Malformed XML
def test_edge_case_malformed_xml(pipeline, tmp_path):
    bad_xml = tmp_path / "bad.xml"
    bad_xml.write_text("<Event><UnclosedTag>", encoding="utf-8")
    events = pipeline.process_file(bad_xml)
    assert len(events) == 0
    assert pipeline.metrics.parsing_failures >= 1


# Edge Case 5: Invalid CSV
def test_edge_case_invalid_csv(pipeline, tmp_path):
    csv_file = tmp_path / "broken.csv"
    csv_file.write_text("h1,h2,h3\nval1\n", encoding="utf-8")
    # Even if row is short, parser pads and doesn't crash
    events = pipeline.process_file(csv_file)
    assert isinstance(events, list)


# Edge Case 6: Invalid IP
def test_edge_case_invalid_ip(pipeline):
    raw = '{"src_ip": "300.400.500.600", "action": "allow"}'
    event = pipeline.process_raw_event(raw)
    assert event is not None
    # Invalid IP is normalized to None rather than corrupting schema
    assert event.source.ip is None


# Edge Case 7: Invalid Port
def test_edge_case_invalid_port(pipeline):
    raw = '{"src_port": 999999, "action": "allow"}'
    event = pipeline.process_raw_event(raw)
    assert event is not None
    assert event.source.port is None


# Edge Case 8: Missing timestamp
def test_edge_case_missing_timestamp(pipeline):
    raw = '{"src_ip": "192.168.1.1", "action": "deny"}'
    event = pipeline.process_raw_event(raw)
    assert event is not None
    assert event.event.timestamp is None
    # Ingestion timestamp is always recorded in metadata
    assert event.metadata.ingestion_timestamp is not None


# Edge Case 9: Unknown vendor
def test_edge_case_unknown_vendor(pipeline):
    raw = '{"src_ip": "10.0.0.1", "custom_vendor_xyz": "foo"}'
    event = pipeline.process_raw_event(raw)
    assert event is not None
    assert event.device.vendor is None or event.device.vendor == ""
    assert "custom_vendor_xyz" in event.extensions


# Edge Case 10: Unknown format fallback
def test_edge_case_unknown_format(pipeline):
    raw = "UNSTRUCTURED LOG LINE WITHOUT CLEAR FORMAT src=1.1.1.1 dst=2.2.2.2"
    event = pipeline.process_raw_event(raw)
    assert event is not None
    assert event.raw.format == "text"


# Edge Case 11: Unknown fields preserved in extensions
def test_edge_case_unknown_fields(pipeline):
    raw = '{"src_ip": "10.0.0.1", "strange_key_1": "val1", "strange_key_2": 12345}'
    event = pipeline.process_raw_event(raw)
    assert event.extensions.get("strange_key_1") == "val1"
    assert event.extensions.get("strange_key_2") == 12345


# Edge Case 12: Duplicate event IDs
def test_edge_case_duplicate_event_ids():
    tracker = EventIdTracker()
    id_1 = "ULPF-DUPLICATE-TEST"
    assert tracker.register(id_1) is True
    assert tracker.register(id_1) is False
    assert tracker.collision_count == 1


# Edge Case 13: SHA-256 verification
def test_edge_case_sha256_verification(pipeline):
    raw = '{"src_ip": "10.0.0.1", "action": "allow"}'
    event = pipeline.process_raw_event(raw)
    assert verify_sha256(event.raw.data, event.metadata.raw_event_hash) is True


# Edge Case 14: Corrupted raw event detection
def test_edge_case_corrupted_raw_event():
    raw = '{"src_ip": "10.0.0.1"}'
    computed_hash = calculate_sha256(raw)
    tampered_raw = '{"src_ip": "10.0.0.2"}'
    assert verify_sha256(tampered_raw, computed_hash) is False


# Edge Case 15: Plugin not found
def test_edge_case_plugin_not_found():
    registry = PluginRegistry()
    assert registry.get_plugin("non_existent_plugin") is None


# Edge Case 16: Invalid plugin
def test_edge_case_invalid_plugin(tmp_path):
    invalid_file = tmp_path / "broken_plugin.py"
    invalid_file.write_text("class NotAPlugin: pass", encoding="utf-8")
    loader = PluginLoader(plugin_registry=PluginRegistry())
    loaded = loader.discover_and_load(tmp_path)
    assert loaded == 0


# Edge Case 17: Partial event failure (1 event fails, others succeed)
def test_edge_case_partial_event_failure(pipeline, tmp_path):
    log_file = tmp_path / "partial.ndjson"
    log_file.write_text(
        '{"src_ip": "192.168.1.1", "action": "allow"}\n'
        'CORRUPTED NOT JSON LINE\n'
        '{"src_ip": "192.168.1.2", "action": "deny"}\n',
        encoding="utf-8"
    )
    events = pipeline.process_file(log_file)
    # The two valid events are successfully processed!
    assert len(events) == 2
    # The failed event was safely recorded in metrics/error storage
    assert pipeline.metrics.events_failed >= 1
