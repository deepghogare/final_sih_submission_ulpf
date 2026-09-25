"""
Built-in Statistical Log Anomaly & Rate Spike Detector for ULPF.
Executes lightweight online statistical anomaly detection prior to SIEM forwarding:
1. Z-score volume spike detection on sliding time-window event counts.
2. Unexpected null fields identification on mapped Universal Events.
3. Format deviation alerts on parser confidence, syntax anomalies, and key structure.
"""

from typing import Dict, Any, List, Optional
from collections import deque
from datetime import datetime, timezone
import math
import time
import json
import threading
import logging

from app.models.universal_event import UniversalEvent

logger = logging.getLogger("ULPF.AnomalyDetector")


class AnomalyAlert:
    """Represents a detected anomaly event alert."""
    def __init__(
        self,
        anomaly_type: str,  # VOLUME_SPIKE, UNEXPECTED_NULL_FIELD, FORMAT_DEVIATION
        severity: str,      # low, medium, high, critical
        message: str,
        details: Dict[str, Any],
        event_id: Optional[str] = None
    ):
        self.anomaly_type = anomaly_type
        self.severity = severity
        self.message = message
        self.details = details
        self.event_id = event_id
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "event_id": self.event_id,
            "timestamp": self.timestamp
        }


class WelfordOnlineStats:
    """
    Implements Welford's algorithm for online calculation of running mean and variance.
    Memory footprint O(1), computationally efficient.
    """
    def __init__(self, min_samples: int = 3):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
        self.min_samples = min_samples

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2

    @property
    def stddev(self) -> float:
        if self.n < 2:
            return 0.0
        return math.sqrt(self.M2 / (self.n - 1))

    def get_zscore(self, x: float) -> float:
        if self.n < self.min_samples:
            if x >= 10.0:
                return 3.5
            return 0.0
        sd = self.stddev
        if sd < 1e-5:
            if abs(x - self.mean) >= 3.0:
                return 4.0 if x > self.mean else -4.0
            return 0.0
        return (x - self.mean) / sd

    def reset(self) -> None:
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0


class LogAnomalyDetector:
    """
    Lightweight real-time anomaly detector for ULPF.
    Runs prior to SIEM forwarding.
    """
    def __init__(
        self,
        zscore_threshold: float = 2.0,
        volume_window_sec: float = 5.0,
        null_rate_threshold: float = 0.3,
        max_recent_alerts: int = 100
    ):
        self.zscore_threshold = zscore_threshold
        self.volume_window_sec = volume_window_sec
        self.null_rate_threshold = null_rate_threshold
        self.max_recent_alerts = max_recent_alerts

        self._lock = threading.Lock()

        # Volume spike tracking (sliding window of event arrival timestamps)
        self._event_timestamps: deque = deque()
        self._stats = WelfordOnlineStats(min_samples=3)
        self._last_bucket_time = time.time()

        # Anomaly counters & history
        self.total_analyzed = 0
        self.total_anomalies = 0
        self.anomalies_by_type: Dict[str, int] = {
            "VOLUME_SPIKE": 0,
            "UNEXPECTED_NULL_FIELD": 0,
            "FORMAT_DEVIATION": 0
        }
        self.recent_alerts: deque = deque(maxlen=max_recent_alerts)

    def analyze(self, event: UniversalEvent) -> List[AnomalyAlert]:
        """
        Analyzes a single UniversalEvent for rate spikes, null field anomalies,
        and format deviations. Attaches anomalies to event.extensions["anomalies"].
        Returns list of generated AnomalyAlert instances.
        """
        alerts: List[AnomalyAlert] = []
        now = time.time()

        with self._lock:
            self.total_analyzed += 1

            # 1. Volume Spike Detection (Z-Score on EPS rate)
            self._event_timestamps.append(now)

            # Prune timestamps older than window
            cutoff = now - self.volume_window_sec
            while self._event_timestamps and self._event_timestamps[0] < cutoff:
                self._event_timestamps.popleft()

            # Calculate current rate (EPS over window)
            current_count = len(self._event_timestamps)
            current_eps = current_count / max(self.volume_window_sec, 0.5)

            # Update stats baseline periodically
            if now - self._last_bucket_time >= 0.2:
                self._stats.update(current_eps)
                self._last_bucket_time = now

            zscore = self._stats.get_zscore(current_eps)
            if (zscore >= self.zscore_threshold and current_count >= 3) or (current_eps > 20.0):
                alert = AnomalyAlert(
                    anomaly_type="VOLUME_SPIKE",
                    severity="high" if zscore > 4.0 or current_eps > 50 else "medium",
                    message=f"Log rate spike detected: {current_eps:.1f} EPS (Z-Score: {zscore:.2f}, baseline mean: {self._stats.mean:.1f} EPS)",
                    details={
                        "current_eps": round(current_eps, 2),
                        "baseline_mean_eps": round(self._stats.mean, 2),
                        "baseline_stddev": round(self._stats.stddev, 2),
                        "z_score": round(zscore, 2),
                        "window_sec": self.volume_window_sec
                    },
                    event_id=event.event_id
                )
                alerts.append(alert)

            # 2. Unexpected Null Field Detection
            null_fields = self._detect_null_fields(event)
            if null_fields:
                alert = AnomalyAlert(
                    anomaly_type="UNEXPECTED_NULL_FIELD",
                    severity="low" if len(null_fields) == 1 else "medium",
                    message=f"Unexpected null/missing fields: {', '.join(null_fields)}",
                    details={
                        "null_fields": null_fields,
                        "null_count": len(null_fields),
                        "parser": event.metadata.parser,
                        "format": event.raw.format
                    },
                    event_id=event.event_id
                )
                alerts.append(alert)

            # 3. Format Deviation & Syntax Anomaly Detection
            format_issues = self._detect_format_deviations(event)
            if format_issues:
                alert = AnomalyAlert(
                    anomaly_type="FORMAT_DEVIATION",
                    severity="medium",
                    message=f"Format deviation alert: {'; '.join(format_issues)}",
                    details={
                        "issues": format_issues,
                        "declared_format": event.raw.format,
                        "parser_used": event.metadata.parser
                    },
                    event_id=event.event_id
                )
                alerts.append(alert)

            # Attach alerts to event.extensions if any found
            if alerts:
                self.total_anomalies += len(alerts)
                if "anomalies" not in event.extensions or not isinstance(event.extensions["anomalies"], list):
                    event.extensions["anomalies"] = []

                for alert in alerts:
                    self.anomalies_by_type[alert.anomaly_type] = self.anomalies_by_type.get(alert.anomaly_type, 0) + 1
                    event.extensions["anomalies"].append(alert.to_dict())
                    self.recent_alerts.appendleft(alert.to_dict())

        return alerts

    def _detect_null_fields(self, event: UniversalEvent) -> List[str]:
        """Identifies missing expected fields in UniversalEvent."""
        missing = []
        if not event.event.action:
            missing.append("event.action")
        if not event.event.severity or event.event.severity == "unknown":
            missing.append("event.severity")
        if not event.event.timestamp:
            missing.append("event.timestamp")
        if not event.device.vendor or event.device.vendor == "generic":
            missing.append("device.vendor")

        cat = (event.event.category or "").lower()
        evt_type = (event.event.type or "").lower()
        if "network" in evt_type or "firewall" in cat or "ids" in cat or "traffic" in cat:
            if not event.source.ip:
                missing.append("source.ip")
            if not event.destination.ip:
                missing.append("destination.ip")

        if "auth" in evt_type or "login" in cat or "account" in cat:
            if not event.user.name and not event.user.id:
                missing.append("user.name")

        return missing

    def _detect_format_deviations(self, event: UniversalEvent) -> List[str]:
        """Identifies syntax / structure format deviations."""
        issues = []
        fmt = (event.raw.format or "").lower()
        raw_data = (event.raw.data or "").strip()
        parser_name = (event.metadata.parser or "").lower()

        # Fallback parser alert
        if fmt in ("json", "ndjson", "cef", "leef", "xml") and parser_name == "text":
            issues.append(f"Format signature '{fmt}' fell back to generic 'text' parser")

        # Syntax checks
        if fmt in ("json", "ndjson"):
            if not (raw_data.startswith("{") or raw_data.startswith("[")):
                issues.append("JSON payload does not start with '{' or '[' delimiter")
            else:
                try:
                    json.loads(raw_data)
                except Exception as ex:
                    issues.append(f"JSON syntax error: {str(ex)}")

        if fmt == "cef" and "CEF:" not in raw_data:
            issues.append("CEF format missing 'CEF:' header prefix")

        if fmt == "leef" and "LEEF:" not in raw_data:
            issues.append("LEEF format missing 'LEEF:' header prefix")

        if fmt == "xml" and not (raw_data.startswith("<") and raw_data.endswith(">")):
            issues.append("XML format missing valid '<...>' tags")

        return issues

    def get_stats(self) -> Dict[str, Any]:
        """Returns statistics and operational parameters of anomaly detector."""
        with self._lock:
            current_eps = (len(self._event_timestamps) / max(self.volume_window_sec, 0.5)) if self._event_timestamps else 0.0
            return {
                "total_analyzed": self.total_analyzed,
                "total_anomalies_detected": self.total_anomalies,
                "anomalies_by_type": dict(self.anomalies_by_type),
                "current_rate_eps": round(current_eps, 2),
                "baseline_mean_eps": round(self._stats.mean, 2),
                "baseline_stddev": round(self._stats.stddev, 2),
                "samples_count": self._stats.n,
                "zscore_threshold": self.zscore_threshold,
                "recent_alerts": list(self.recent_alerts)[:10]
            }

    def reset_baseline(self) -> None:
        """Resets baseline statistical metrics."""
        with self._lock:
            self._stats.reset()
            self._event_timestamps.clear()
            self._last_bucket_time = time.time()


default_anomaly_detector = LogAnomalyDetector()
