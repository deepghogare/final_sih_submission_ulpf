"""
Unit Tests for SHA-256 Cryptographic Integrity and Event ID Tracking.
"""

from pathlib import Path
from app.integrity.hashing import (
    calculate_sha256,
    verify_sha256,
    calculate_file_sha256,
    generate_event_id,
    EventIdTracker,
)


def test_sha256_calculation_and_verification():
    raw_text = 'src_ip=192.168.1.1 dst_ip=10.0.0.1 action=DENY'
    hash_digest = calculate_sha256(raw_text)
    assert len(hash_digest) == 64
    # Verify exact match
    assert verify_sha256(raw_text, hash_digest) is True
    # Verify tamper detection
    tampered = raw_text.replace("DENY", "ALLOW")
    assert verify_sha256(tampered, hash_digest) is False


def test_file_level_sha256(tmp_path):
    f = tmp_path / "test.log"
    f.write_text("log line 1\nlog line 2\n", encoding="utf-8")
    hash1 = calculate_file_sha256(f)
    assert len(hash1) == 64
    # Changing content changes hash
    f.write_text("log line 1\nlog line 2 modified\n", encoding="utf-8")
    hash2 = calculate_file_sha256(f)
    assert hash1 != hash2


def test_event_id_generation_and_uniqueness():
    id1 = generate_event_id()
    id2 = generate_event_id()
    assert id1.startswith("ULPF-")
    assert id2.startswith("ULPF-")
    assert id1 != id2


def test_event_id_collision_tracker():
    tracker = EventIdTracker()
    assert tracker.register("ULPF-001") is True
    assert tracker.register("ULPF-002") is True
    # Duplicate registration returns False
    assert tracker.register("ULPF-001") is False
    assert tracker.collision_count == 1
