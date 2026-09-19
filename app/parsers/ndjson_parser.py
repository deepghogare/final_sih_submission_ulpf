"""
NDJSON (Newline-Delimited JSON) Parser for ULPF.
Processes streaming logs where each line is an independent JSON object.
"""

import json
from typing import Optional
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class NdjsonParser(BaseParser):
    name: str = "ndjson"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".ndjson", ".jsonl")

    def can_parse(self, sample: str) -> bool:
        lines = [line.strip() for line in sample.splitlines() if line.strip()]
        if len(lines) < 2:
            # Single line could be JSON, but let's see if line 1 is valid JSON object
            if lines and lines[0].startswith("{") and lines[0].endswith("}"):
                try:
                    obj = json.loads(lines[0])
                    return isinstance(obj, dict)
                except Exception:
                    return False
            return False

        # Multiple lines: check if first two non-empty lines are valid JSON objects
        valid_count = 0
        for line in lines[:3]:
            if line.startswith("{") and line.endswith("}"):
                try:
                    if isinstance(json.loads(line), dict):
                        valid_count += 1
                except Exception:
                    return False
        return valid_count >= 2

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty event line")
        try:
            data = json.loads(clean)
            if not isinstance(data, dict):
                raise ParserError("NDJSON line must be a JSON object")
            return ParsedEvent(
                raw_data=clean,
                format="ndjson",
                fields=data,
                source_file=source_file,
                source_line=source_line,
                parser_name=self.name,
                parser_version=self.version
            )
        except json.JSONDecodeError as e:
            raise ParserError(f"Malformed NDJSON line: {e.msg}") from e
