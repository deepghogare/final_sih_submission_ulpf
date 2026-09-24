"""
Real-Time Metrics Collection Engine for ULPF.
Tracks processing throughput, latency percentiles, stage failure rates,
and format/vendor distributions in a thread-safe manner.
"""

from typing import Dict, Any, List, Optional
import time
import threading
from collections import defaultdict


class MetricsTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.start_time: float = time.time()
            self.events_received: int = 0
            self.events_processed: int = 0
            self.events_failed: int = 0

            # Sliding window of timestamps for instantaneous real-time EPS
            self._recent_timestamps: List[float] = []
            self._last_active_time: float = 0.0
            self._last_measured_eps: float = 0.0

            # Specific stage failures
            self.detection_failures: int = 0
            self.parsing_failures: int = 0
            self.mapping_failures: int = 0
            self.validation_failures: int = 0
            self.integrity_failures: int = 0

            # Distributions
            self.format_distribution: Dict[str, int] = defaultdict(int)
            self.vendor_distribution: Dict[str, int] = defaultdict(int)

            # Performance latencies in milliseconds
            self.latencies_ms: List[float] = []

    def record_received(self, count: int = 1) -> None:
        with self._lock:
            self.events_received += count

    def record_success(self, fmt: str, vendor: str, latency_ms: float) -> None:
        now = time.time()
        with self._lock:
            self.events_processed += 1
            self.format_distribution[fmt] += 1
            self.vendor_distribution[vendor or "unknown"] += 1

            # Append timestamp to sliding window
            self._recent_timestamps.append(now)
            self._last_active_time = now

            # Keep window within last 10 seconds
            cutoff = now - 10.0
            while self._recent_timestamps and self._recent_timestamps[0] < cutoff:
                self._recent_timestamps.pop(0)

            # Keep sample of latencies for percentile calculations (up to 50,000)
            if len(self.latencies_ms) < 50000:
                self.latencies_ms.append(latency_ms)

    def record_failure(self, stage: str, fmt: Optional[str] = None) -> None:
        with self._lock:
            self.events_failed += 1
            if stage == "detection":
                self.detection_failures += 1
            elif stage == "parsing":
                self.parsing_failures += 1
            elif stage == "mapping":
                self.mapping_failures += 1
            elif stage == "validation":
                self.validation_failures += 1
            elif stage == "integrity":
                self.integrity_failures += 1

    def get_snapshot(self) -> Dict[str, Any]:
        """Returns a snapshot dictionary of all tracked metrics."""
        now = time.time()
        with self._lock:
            # Clean sliding window
            cutoff = now - 10.0
            while self._recent_timestamps and self._recent_timestamps[0] < cutoff:
                self._recent_timestamps.pop(0)

            # Calculate real-time sliding window EPS
            if len(self._recent_timestamps) > 1:
                window_span = max(now - self._recent_timestamps[0], 0.05)
                throughput = len(self._recent_timestamps) / window_span
                self._last_measured_eps = throughput
            elif len(self._recent_timestamps) == 1:
                # Instant single event rate based on latency
                avg_l = (self.latencies_ms[-1] / 1000.0) if self.latencies_ms else 0.001
                throughput = round(1.0 / max(avg_l, 0.0001), 1)
                self._last_measured_eps = throughput
            elif now - self._last_active_time < 5.0 and self._last_measured_eps > 0:
                # Keep last active burst EPS for a brief grace period
                throughput = self._last_measured_eps
            elif self.events_processed > 0:
                # Overall average
                elapsed_sec = max(now - self.start_time, 0.001)
                throughput = self.events_processed / elapsed_sec
            else:
                throughput = 0.0

            avg_latency = (sum(self.latencies_ms) / len(self.latencies_ms)) if self.latencies_ms else 0.0
            sorted_latencies = sorted(self.latencies_ms) if self.latencies_ms else []
            p50 = sorted_latencies[int(len(sorted_latencies) * 0.50)] if sorted_latencies else 0.0
            p95 = sorted_latencies[int(len(sorted_latencies) * 0.95)] if sorted_latencies else 0.0
            p99 = sorted_latencies[int(len(sorted_latencies) * 0.99)] if sorted_latencies else 0.0

            norm_success_rate = (
                (self.events_processed / (self.events_received or 1)) * 100.0
                if self.events_received > 0 else 100.0
            )

            return {
                "events_received": self.events_received,
                "events_processed": self.events_processed,
                "events_failed": self.events_failed,
                "events_per_second": round(throughput, 2),
                "elapsed_seconds": round(max(now - self.start_time, 0.001), 3),
                "average_latency_ms": round(avg_latency, 3),
                "latency_p50_ms": round(p50, 3),
                "latency_p95_ms": round(p95, 3),
                "latency_p99_ms": round(p99, 3),
                "normalization_success_rate_pct": round(norm_success_rate, 2),
                "raw_events_preserved": self.events_processed,
                "failure_breakdown": {
                    "detection": self.detection_failures,
                    "parsing": self.parsing_failures,
                    "mapping": self.mapping_failures,
                    "validation": self.validation_failures,
                    "integrity": self.integrity_failures,
                },
                "format_distribution": dict(self.format_distribution),
                "vendor_distribution": dict(self.vendor_distribution),
            }


default_metrics_tracker = MetricsTracker()
