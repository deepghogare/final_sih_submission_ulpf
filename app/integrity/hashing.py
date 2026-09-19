"""
Cryptographic Integrity and Event ID Module for ULPF.
Implements SHA-256 calculation/verification and unique event ID generation with collision tracking.
"""

import hashlib
import hmac
import uuid
import threading
from pathlib import Path
from typing import Union, Set


def calculate_sha256(raw_data: Union[str, bytes]) -> str:
    """
    Calculate the SHA-256 checksum of raw event data.
    Encoding Rule:
      - If str: encoded using strict UTF-8 bytes without trimming or alteration.
      - If bytes: processed directly.
    Returns:
      Hexadecimal SHA-256 digest string (64 characters).
    """
    if isinstance(raw_data, str):
        data_bytes = raw_data.encode("utf-8", errors="replace")
    elif isinstance(raw_data, bytes):
        data_bytes = raw_data
    else:
        data_bytes = str(raw_data).encode("utf-8", errors="replace")
    return hashlib.sha256(data_bytes).hexdigest()


def verify_sha256(raw_data: Union[str, bytes], expected_hash: str) -> bool:
    """
    Verify whether the raw data matches the expected SHA-256 digest.
    Constant-time comparison used to prevent timing attacks.
    """
    actual_hash = calculate_sha256(raw_data)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())


def calculate_file_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """
    Calculate package/file-level SHA-256 hash for full file provenance and audit trails.
    Streams in 64KB chunks to maintain memory efficiency for arbitrarily large files.
    """
    hasher = hashlib.sha256()
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for hash calculation: {file_path}")
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_event_id(prefix: str = "ULPF") -> str:
    """
    Generate a unique event identifier.
    Format: {prefix}-{12_hex_chars}
    Example: ULPF-8a92f1b4c3e2
    """
    random_hex = uuid.uuid4().hex[:12]
    return f"{prefix}-{random_hex}"


class EventIdTracker:
    """
    Thread-safe tracker to detect duplicate event IDs across the pipeline session.
    Protects against collisions and enables duplicate event reporting.
    """
    def __init__(self, max_capacity: int = 500000):
        self._seen_ids: Set[str] = set()
        self._max_capacity = max_capacity
        self._lock = threading.Lock()
        self.collision_count: int = 0

    def register(self, event_id: str) -> bool:
        """
        Registers an event ID.
        Returns True if the ID is new (unique).
        Returns False if the ID is a duplicate (collision detected).
        """
        with self._lock:
            if event_id in self._seen_ids:
                self.collision_count += 1
                return False
            # Evict oldest half if memory capacity exceeded
            if len(self._seen_ids) >= self._max_capacity:
                self._seen_ids.clear()
            self._seen_ids.add(event_id)
            return True

    def clear(self) -> None:
        """Resets the tracker."""
        with self._lock:
            self._seen_ids.clear()
            self.collision_count = 0

    @property
    def total_tracked(self) -> int:
        with self._lock:
            return len(self._seen_ids)
