"""
Key-Value / Plain Text Parser for ULPF.
Parses arbitrary space- or delimiter-separated key=value pairs,
handling quoted strings and unstructured prefix messages.
"""

import re
from typing import Optional, Dict, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class TextParser(BaseParser):
    name: str = "text"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".txt", ".log")

    KV_PATTERN = re.compile(r'([a-zA-Z0-9_\-\.]+)=(["][^"]*["]|[\'][^\']*[\']|[^\s,;]+)')

    def can_parse(self, sample: str) -> bool:
        lines = [l.strip() for l in sample.splitlines() if l.strip()]
        if not lines:
            return False
        # Needs at least 2 key=value pairs
        matches = self.KV_PATTERN.findall(lines[0])
        return len(matches) >= 2

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty text event")

        matches = self.KV_PATTERN.findall(clean)
        if not matches:
            raise ParserError(f"No key=value pairs found in text event: {clean[:80]}")

        fields: Dict[str, Any] = {}
        for k, v in matches:
            cleaned_val = v.strip('"\'')
            fields[k] = cleaned_val

        return ParsedEvent(
            raw_data=clean,
            format="text",
            fields=fields,
            source_file=source_file,
            source_line=source_line,
            parser_name=self.name,
            parser_version=self.version
        )
