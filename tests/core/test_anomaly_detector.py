"""
Unit and Integration Tests for ULPF Log Anomaly & Rate Spike Detector.
"""

import time
import pytest
from app.core.anomaly_detector import LogAnomalyDetector, WelfordOnlineStats, AnomalyAlert
from app.models.universal_event import UniversalEvent, EventDetails, EndpointDetails, MetadataDetails, RawDetails
from app.core.pipeline import Pipeline


def create_sample_event(
    event_id: str = "ULPF-TEST-001",
    action: str = "allow",
    severity: str = "info",
    source_ip: str = "192.168.1.10",
    fmt: str = "syslog",
    raw_data: str = "<34>1 2026-09-25T12:00:00Z myhost app - - - User login allowed",
    parser: str = "syslog"
) -> UniversalEvent:
    return UniversalEvent(
        event_id=event_id,
        schema_version="1.0",
        event=EventDetails(
            action=action,
            severity=severity,
            timestamp="2026-09-25T12:00:00Z",
            type="auth",
            category="login"
        ),
        source=EndpointDetails(ip=source_ip, port=443),
        metadata=MetadataDetails(
            ingestion_timestamp="2026-09-25T12:00:00Z",
            parser=parser,
            raw_event_hash="abc123hash"
        ),
        raw=RawDetails(
            data=raw_data,
            format=fmt
        )
    )


class TestWelfordOnlineStats:
    def test_running_mean_and_stddev(self):
        stats = WelfordOnlineStats(min_samples=3)
        data = [10.0, 10.0, 10.0, 10.0, 10.0]
        for val in data:
            stats.update(val)

        assert stats.n == 5
        assert stats.mean == pytest.approx(10.0)
        assert stats.stddev == pytest.approx(0.0)

        z = stats.get_zscore(50.0)
        assert z > 3.0

    def test_zscore_calculation(self):
        stats = WelfordOnlineStats(min_samples=5)
        rates = [90.0, 100.0, 110.0, 95.0, 105.0]
        for r in rates:
            stats.update(r)

        assert stats.n == 5
        z = stats.get_zscore(500.0)
        assert z > 3.0


class TestLogAnomalyDetector:
    def test_null_field_detection(self):
        detector = LogAnomalyDetector()
        ev = create_sample_event()
        ev.event.action = None
        ev.event.severity = None
        ev.event.category = None

        alerts = detector.analyze(ev)
        assert any(a.anomaly_type == "UNEXPECTED_NULL_FIELD" for a in alerts)
        assert "anomalies" in ev.extensions

    def test_format_deviation_detection(self):
        detector = LogAnomalyDetector()
        ev = create_sample_event(
            fmt="json",
            raw_data="INVALID NON JSON RAW STRING",
            parser="text"
        )
        alerts = detector.analyze(ev)
        dev_alerts = [a for a in alerts if a.anomaly_type == "FORMAT_DEVIATION"]
        assert len(dev_alerts) > 0

    def test_volume_spike_zscore(self):
        detector = LogAnomalyDetector(zscore_threshold=2.0, volume_window_sec=2.0)
        detector._stats.n = 10
        detector._stats.mean = 5.0
        detector._stats.M2 = 9.0

        ev = create_sample_event()
        alerts = []
        for _ in range(40):
            alerts.extend(detector.analyze(ev))

        vol_alerts = [a for a in alerts if a.anomaly_type == "VOLUME_SPIKE"]
        assert len(vol_alerts) > 0
        stats = detector.get_stats()
        assert stats["total_anomalies_detected"] > 0
        assert stats["anomalies_by_type"]["VOLUME_SPIKE"] > 0

    def test_reset_baseline(self):
        detector = LogAnomalyDetector()
        ev = create_sample_event()
        ev.event.action = None
        ev.event.severity = None
        ev.event.category = None

        detector.analyze(ev)
        assert detector.total_anomalies > 0
        detector.reset_baseline()
        stats = detector.get_stats()
        assert stats["samples_count"] == 0


class TestPipelineAnomalyIntegration:
    def test_pipeline_attaches_anomalies_to_event(self):
        pipeline = Pipeline()
        raw_event = '{"event": "login", "status": "failed"}'
        event = pipeline.process_raw_event(raw_event, force_format="json")
        assert event is not None
        stats = pipeline.anomaly_detector.get_stats()
        assert stats["total_analyzed"] > 0
