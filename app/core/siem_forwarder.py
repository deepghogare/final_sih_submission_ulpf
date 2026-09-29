"""
ULPF SIEM Forwarder & Log Streamer.
Provides failsafe, high-throughput log forwarding from ULPF's normalization
pipeline directly into Open-Source SIEM solutions (Wazuh, OpenSearch, ELK, Graylog).
"""

from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import os
import json
import logging
import socket
import threading

logger = logging.getLogger("ULPF.SiemForwarder")


class SiemForwarder:
    """
    Failsafe forwarder that streams normalized Universal Events to SIEM collectors
    via shared JSONL file streaming and Syslog/UDP socket forwarding.
    """

    def __init__(
        self,
        jsonl_path: Optional[Path] = None,
        syslog_host: Optional[str] = None,
        syslog_port: Optional[int] = None,
        enabled_syslog: bool = True
    ):
        output_dir = os.getenv("ULPF_OUTPUT_DIR", "output")
        self.jsonl_path = Path(jsonl_path) if jsonl_path else Path(output_dir) / "universal_events.jsonl"
        self.syslog_host = syslog_host or os.getenv("ULPF_SIEM_HOST", os.getenv("SIEM_HOST", "127.0.0.1"))
        self.syslog_port = syslog_port if syslog_port is not None else int(os.getenv("ULPF_SIEM_PORT", os.getenv("SIEM_PORT", "514")))
        self.enabled_syslog = enabled_syslog
        self._lock = threading.Lock()
        self.forwarded_count = 0
        self.last_forwarded_at: Optional[str] = None
        self.last_error: Optional[str] = None

        # Ensure output directory exists
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    def forward(self, event_data: Dict[str, Any]) -> bool:
        """
        Forwards a single normalized event to the SIEM via file stream and socket.
        Returns True if forward succeeded without errors.
        """
        with self._lock:
            success = True
            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. Append to shared JSONL output (monitored by Wazuh Manager / Logstash)
            try:
                line = json.dumps(event_data, ensure_ascii=False) + "\n"
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception as e:
                self.last_error = f"File stream error: {e}"
                logger.warning(f"Failed appending event to {self.jsonl_path}: {e}")
                success = False

            # 2. Failsafe UDP Syslog streaming to Wazuh Manager listener
            if self.enabled_syslog and self.syslog_host:
                try:
                    payload = json.dumps(event_data).encode("utf-8")
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.5)
                    sock.sendto(payload, (self.syslog_host, self.syslog_port))
                    sock.close()
                except Exception as e:
                    # UDP forwarding errors are non-fatal; SIEM may be starting up
                    self.last_error = f"Socket stream error: {e}"
                    logger.debug(f"SIEM socket forward error (non-fatal): {e}")

            if success:
                self.forwarded_count += 1
                self.last_forwarded_at = now_iso

            return success

    def get_status(self) -> Dict[str, Any]:
        """Returns operational metrics of the SIEM forwarder."""
        with self._lock:
            return {
                "forwarded_count": self.forwarded_count,
                "last_forwarded_at": self.last_forwarded_at,
                "target_file": str(self.jsonl_path),
                "syslog_target": f"{self.syslog_host}:{self.syslog_port}",
                "syslog_enabled": self.enabled_syslog,
                "last_error": self.last_error,
                "status": "active"
            }


default_siem_forwarder = SiemForwarder()
