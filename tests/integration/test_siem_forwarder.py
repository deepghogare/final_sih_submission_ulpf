import pytest
import json
from pathlib import Path
from app.core.siem_forwarder import SiemForwarder


def test_siem_forwarder_file_streaming(tmp_path: Path):
    target_jsonl = tmp_path / "siem_events.jsonl"
    forwarder = SiemForwarder(jsonl_path=target_jsonl, enabled_syslog=False)

    test_event = {
        "event_id": "test-12345",
        "event": {"action": "deny", "severity": "high"},
        "source": {"ip": "192.168.1.100"},
        "device": {"vendor": "Cisco", "product": "ASA"}
    }

    result = forwarder.forward(test_event)
    assert result is True
    assert forwarder.forwarded_count == 1

    # Verify content written to disk
    assert target_jsonl.exists()
    with open(target_jsonl, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["event_id"] == "test-12345"
        assert data["event"]["action"] == "deny"


def test_siem_forwarder_status():
    forwarder = SiemForwarder(enabled_syslog=True, syslog_host="127.0.0.1", syslog_port=9999)
    status = forwarder.get_status()
    assert status["status"] == "active"
    assert status["forwarded_count"] == 0
    assert "syslog_target" in status


def test_siem_forwarder_failsafe_socket(tmp_path: Path):
    # Even if destination socket is unreachable, forwarding must return True and not crash
    target_jsonl = tmp_path / "siem_events_safe.jsonl"
    forwarder = SiemForwarder(jsonl_path=target_jsonl, enabled_syslog=True, syslog_host="192.0.2.1", syslog_port=1514)

    test_event = {"event_id": "safe-001", "action": "allow"}
    result = forwarder.forward(test_event)
    assert result is True
    assert forwarder.forwarded_count == 1
