"""
Streaming JSON / JSONL Output Writer for ULPF.
Writes standardized Universal Events to disk.
"""

from typing import Union, List
from pathlib import Path
import json
import threading

from app.models.universal_event import UniversalEvent


class JsonWriter:
    """
    Thread-safe writer supporting JSON Lines streaming (preferred for SIEM pipelines)
    and formatted JSON array outputs.
    """
    def __init__(self, output_path: Union[str, Path], format_mode: str = "jsonl"):
        self.output_path = Path(output_path)
        self.format_mode = format_mode.lower()
        self._lock = threading.Lock()
        self.events_written: int = 0
        self._ensure_parent_dir()

    def _ensure_parent_dir(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def write_event(self, event: UniversalEvent) -> None:
        """Appends a single Universal Event to the output file."""
        with self._lock:
            mode = "a" if self.output_path.exists() else "w"
            event_json = event.model_dump_json()

            if self.format_mode == "jsonl":
                with open(self.output_path, mode, encoding="utf-8") as f:
                    f.write(event_json + "\n")
            else:
                # Standalone single JSON or appended
                with open(self.output_path, mode, encoding="utf-8") as f:
                    f.write(event_json + "\n")

            self.events_written += 1

    def write_batch(self, events: List[UniversalEvent]) -> None:
        """Writes a batch of events."""
        with self._lock:
            with open(self.output_path, "a", encoding="utf-8") as f:
                for ev in events:
                    f.write(ev.model_dump_json() + "\n")
                    self.events_written += 1

    def write_json_array(self, events: List[UniversalEvent]) -> None:
        """Writes all events as a single formatted JSON array."""
        with self._lock:
            data = [ev.model_dump() for ev in events]
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.events_written = len(events)
