"""
LEEF (Log Event Extended Format) Parser for ULPF.
Supports IBM QRadar LEEF 1.0 and LEEF 2.0 syntax:
LEEF:1.0|Vendor|Product|Version|EventID|Key=Value...
LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Key=Value...
"""

import re
from typing import Optional, Dict, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class LeefParser(BaseParser):
    name: str = "leef"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".leef", ".log")

    PIPE_SPLIT_REGEX = re.compile(r'(?<!\\)\|')

    def can_parse(self, sample: str) -> bool:
        lines = [l.strip() for l in sample.splitlines() if l.strip()]
        if not lines:
            return False
        first = lines[0]
        return "LEEF:1.0|" in first or "LEEF:2.0|" in first or "LEEF:" in first

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty LEEF event")

        pos = clean.find("LEEF:")
        if pos == -1:
            raise ParserError("Missing 'LEEF:' token")

        leef_data = clean[pos:]
        parts = self.PIPE_SPLIT_REGEX.split(leef_data)

        if len(parts) < 6:
            raise ParserError(f"Malformed LEEF event: expected at least 6 pipe-delimited fields, got {len(parts)}")

        version_str = parts[0].replace("LEEF:", "").strip()
        vendor = parts[1].replace(r"\|", "|").strip()
        product = parts[2].replace(r"\|", "|").strip()
        version = parts[3].replace(r"\|", "|").strip()
        event_id = parts[4].replace(r"\|", "|").strip()

        delimiter = "\t"
        extension_str = ""

        if version_str == "2.0" and len(parts) >= 7:
            delim_field = parts[5]
            if delim_field.startswith("0x") or delim_field.startswith("x"):
                try:
                    delimiter = chr(int(delim_field.replace("0x", "").replace("x", ""), 16))
                except Exception:
                    delimiter = "\t"
            elif delim_field:
                delimiter = delim_field
            extension_str = "|".join(parts[6:])
        else:
            extension_str = "|".join(parts[5:])

        fields: Dict[str, Any] = {
            "leef_version": version_str,
            "device_vendor": vendor,
            "device_product": product,
            "device_version": version,
            "device_event_class_id": event_id,
        }

        # Parse key=value pairs using delimiter or fallback to tab/space
        if extension_str:
            tokens = extension_str.split(delimiter)
            for token in tokens:
                token = token.strip()
                if not token:
                    continue
                if "=" in token:
                    k, v = token.split("=", 1)
                    fields[k.strip()] = v.strip().replace(r"\=", "=").replace(r"\|", "|")

        return ParsedEvent(
            raw_data=clean,
            format="leef",
            fields=fields,
            source_file=source_file,
            source_line=source_line,
            detected_vendor=vendor,
            parser_name=self.name,
            parser_version=self.version
        )
