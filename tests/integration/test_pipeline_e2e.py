"""
End-to-End Integration Tests for ULPF.
Processes all realistic test data formats and validates Universal Event JSON output.
"""

from pathlib import Path
from app.core.pipeline import Pipeline
from app.models.universal_event import UniversalEvent


def test_pipeline_e2e_all_formats():
    pipeline = Pipeline()
    test_data_dir = Path("test_data")

    test_files = [
        test_data_dir / "comparison" / "vendor_a.json",
        test_data_dir / "comparison" / "vendor_b.json",
        test_data_dir / "json" / "firewall_events.json",
        test_data_dir / "ndjson" / "stream_events.ndjson",
        test_data_dir / "csv" / "network_traffic.csv",
        test_data_dir / "syslog" / "system_auth.log",
        test_data_dir / "cef" / "security_alerts.cef",
        test_data_dir / "leef" / "qradar_events.leef",
        test_data_dir / "xml" / "windows_security.xml",
    ]

    total_events = 0
    for tf in test_files:
        assert tf.is_file(), f"Test file missing: {tf}"
        events = pipeline.process_file(tf)
        assert len(events) > 0, f"Expected events from {tf.name}, got 0"
        for ev in events:
            assert isinstance(ev, UniversalEvent)
            assert ev.event_id.startswith("ULPF-")
            assert len(ev.metadata.raw_event_hash) == 64
            assert ev.raw.data is not None and len(ev.raw.data) > 0
        total_events += len(events)

    assert total_events >= 20
