"""
Automatic Content-Based Format Detection Engine for ULPF.
Analyzes log content, structural signatures, and magic tokens,
allowing formats to be identified independently of file extensions.
Supports pluggable detector registry.
"""

from typing import List, Callable, Optional, Tuple
from pathlib import Path
import json
import re


FormatDetectorFunc = Callable[[str], Tuple[bool, float]]


class DetectorEntry:
    def __init__(self, format_name: str, detector: FormatDetectorFunc, priority: int = 100):
        self.format_name = format_name
        self.detector = detector
        self.priority = priority  # Higher priority checked earlier


class FormatDetector:
    """
    Registry and evaluator for content-based format detectors.
    Plugins can register custom format detectors at runtime.
    """
    def __init__(self):
        self._detectors: List[DetectorEntry] = []
        self._register_default_detectors()

    def register_detector(self, format_name: str, detector: FormatDetectorFunc, priority: int = 100) -> None:
        """Register a format detector with priority weighting."""
        entry = DetectorEntry(format_name, detector, priority)
        self._detectors.append(entry)
        self._detectors.sort(key=lambda d: d.priority, reverse=True)

    def detect_format(self, content_or_path: str) -> str:
        """
        Detect the format of a file or raw string content.
        Returns format name (e.g. 'json', 'ndjson', 'syslog', 'cef', 'leef', 'xml', 'csv', 'text').
        Falls back to 'text' if no specific format matches.
        """
        sample = self._extract_sample(content_or_path)
        if not sample.strip():
            return "text"

        best_format = "text"
        highest_confidence = 0.0

        for entry in self._detectors:
            try:
                matches, confidence = entry.detector(sample)
                if matches and confidence > highest_confidence:
                    highest_confidence = confidence
                    best_format = entry.format_name
                    # High confidence shortcut
                    if confidence >= 0.95:
                        break
            except Exception:
                continue

        # If confidence is low or default 'text', check file extension as auxiliary hint
        if highest_confidence < 0.5:
            ext_map = {
                ".json": "json",
                ".ndjson": "ndjson",
                ".jsonl": "ndjson",
                ".xml": "xml",
                ".csv": "csv",
                ".tsv": "csv",
                ".cef": "cef",
                ".leef": "leef",
                ".syslog": "syslog"
            }
            try:
                suffix = Path(content_or_path).suffix.lower()
                if suffix in ext_map:
                    return ext_map[suffix]
            except Exception:
                pass

        return best_format

    def _extract_sample(self, content_or_path: str, max_bytes: int = 8192) -> str:
        """Safely reads the initial sample if input is a valid file path, else treats as string."""
        path = Path(content_or_path)
        try:
            if path.is_file():
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read(max_bytes)
        except Exception:
            pass
        return content_or_path[:max_bytes]

    def _register_default_detectors(self) -> None:
        # CEF detector (priority 900)
        def detect_cef(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if lines and "CEF:" in lines[0]:
                return True, 0.98
            return False, 0.0

        # LEEF detector (priority 900)
        def detect_leef(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if lines and ("LEEF:1.0|" in lines[0] or "LEEF:2.0|" in lines[0] or "LEEF:" in lines[0]):
                return True, 0.98
            return False, 0.0

        # XML detector (priority 800)
        def detect_xml(sample: str) -> Tuple[bool, float]:
            trimmed = sample.strip()
            if trimmed.startswith("<?xml") or (trimmed.startswith("<") and "</" in trimmed and trimmed.endswith(">")):
                return True, 0.95
            return False, 0.0

        # NDJSON detector (priority 750)
        def detect_ndjson(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if len(lines) >= 2:
                valid_count = 0
                for line in lines[:5]:
                    if line.startswith("{") and line.endswith("}"):
                        try:
                            if isinstance(json.loads(line), dict):
                                valid_count += 1
                        except Exception:
                            pass
                if valid_count >= 2 and valid_count >= len(lines[:5]) * 0.75:
                    return True, 0.96
            return False, 0.0

        # JSON detector (priority 700)
        def detect_json(sample: str) -> Tuple[bool, float]:
            trimmed = sample.strip()
            if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
                try:
                    json.loads(trimmed)
                    return True, 0.95
                except Exception:
                    pass
            return False, 0.0

        # Syslog detector (priority 600)
        rfc5424_re = re.compile(r"^<\d{1,3}>1\s+\S+\s+\S+")
        rfc3164_re = re.compile(r"^(?:<\d{1,3}>)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+\S+")

        def detect_syslog(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if not lines:
                return False, 0.0
            first = lines[0]
            if rfc5424_re.match(first):
                return True, 0.95
            if rfc3164_re.match(first):
                return True, 0.90
            return False, 0.0

        # CSV detector (priority 500)
        def detect_csv(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if len(lines) < 2:
                return False, 0.0
            for delim in (",", ";", "\t"):
                counts = [line.count(delim) for line in lines[:5]]
                if counts and counts[0] >= 2 and all(c == counts[0] for c in counts):
                    return True, 0.85
            return False, 0.0

        # Key-Value Text detector (priority 400)
        kv_re = re.compile(r'\b[a-zA-Z0-9_\-\.]+=["][^"]*["]|\b[a-zA-Z0-9_\-\.]=[^\s,;]+')

        def detect_text(sample: str) -> Tuple[bool, float]:
            lines = [l.strip() for l in sample.splitlines() if l.strip()]
            if lines and len(kv_re.findall(lines[0])) >= 2:
                return True, 0.70
            return True, 0.10  # Fallback

        self.register_detector("cef", detect_cef, priority=900)
        self.register_detector("leef", detect_leef, priority=900)
        self.register_detector("xml", detect_xml, priority=800)
        self.register_detector("ndjson", detect_ndjson, priority=750)
        self.register_detector("json", detect_json, priority=700)
        self.register_detector("syslog", detect_syslog, priority=600)
        self.register_detector("csv", detect_csv, priority=500)
        self.register_detector("text", detect_text, priority=400)


# Global singleton detector
default_format_detector = FormatDetector()
