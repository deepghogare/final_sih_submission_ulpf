"""
Dead-Letter and Error Storage Engine for ULPF.
Persists unparseable, malformed, or invalid log events to failed_events/failed_events.jsonl
with diagnostic provenance, ensuring corrupted events never abort entire file processing.
"""

from pathlib import Path
from typing import Union, Optional
import threading

from app.models.errors import FailedEventRecord


class ErrorStorage:
    def __init__(self, error_file_path: Union[str, Path] = "failed_events/failed_events.jsonl"):
        self.error_file_path = Path(error_file_path)
        self._lock = threading.Lock()
        self.failed_count: int = 0
        self._ensure_parent_dir()

    def _ensure_parent_dir(self) -> None:
        self.error_file_path.parent.mkdir(parents=True, exist_ok=True)

    def record_failure(
        self,
        raw_event: str,
        error_msg: str,
        stage: str,
        event_id: Optional[str] = None,
        parser: Optional[str] = None,
        source_file: Optional[str] = None,
        source_line: Optional[int] = None,
    ) -> FailedEventRecord:
        """Records a failed event to the dead-letter queue."""
        record = FailedEventRecord(
            event_id=event_id,
            raw_event=raw_event,
            error=error_msg,
            stage=stage,
            parser=parser,
            source_file=source_file,
            source_line=source_line
        )

        with self._lock:
            with open(self.error_file_path, "a", encoding="utf-8") as f:
                f.write(record.model_dump_json() + "\n")
            self.failed_count += 1

        return record


default_error_storage = ErrorStorage()
