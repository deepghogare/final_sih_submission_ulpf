"""
Custom exception hierarchy and dead-letter event models for ULPF.
"""

from typing import Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ULPFError(Exception):
    """Base exception for all ULPF framework errors."""
    def __init__(self, message: str, stage: str = "unknown", details: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.stage = stage
        self.details = details


class DetectionError(ULPFError):
    """Raised when format detection fails or yields unsupported format."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, stage="detection", details=details)


class ParserError(ULPFError):
    """Raised when format parsing fails on a raw event."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, stage="parsing", details=details)


class MappingError(ULPFError):
    """Raised when dynamic field mapping encounters fatal issues."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, stage="mapping", details=details)


class ValidationError(ULPFError):
    """Raised when event fails schema validation or data integrity constraints."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, stage="validation", details=details)


class IntegrityError(ULPFError):
    """Raised when SHA-256 hash or data integrity check fails."""
    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__(message, stage="integrity", details=details)


class FailedEventRecord(BaseModel):
    """
    Dead-letter queue structure for failed events.
    Written to failed_events/failed_events.jsonl so corrupted events
    do not crash the entire file processing pipeline.
    """
    event_id: Optional[str] = Field(default=None, description="Event ID if generated before failure")
    raw_event: str = Field(description="Exact raw data of the failed event")
    error: str = Field(description="Error message explaining failure")
    stage: str = Field(description="Pipeline stage: detection, parsing, mapping, validation, integrity")
    parser: Optional[str] = Field(default=None, description="Parser in use if applicable")
    source_file: Optional[str] = Field(default=None, description="Origin file name")
    source_line: Optional[int] = Field(default=None, description="Line number if available")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 timestamp of when failure occurred"
    )
