"""
CSV Parser for ULPF.
Handles delimited network/security logs (firewall dumps, proxy logs, endpoint reports).
Performs dialect sniffing, header extraction, and per-row event generation.
"""

import csv
import io
from pathlib import Path
from typing import Iterator, Union, Optional, List, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class CsvParser(BaseParser):
    name: str = "csv"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".csv", ".tsv")

    def __init__(self, headers: Optional[List[str]] = None, delimiter: str = ","):
        self.headers = headers
        self.delimiter = delimiter

    def can_parse(self, sample: str) -> bool:
        lines = [line.strip() for line in sample.splitlines() if line.strip()]
        if not lines:
            return False
        # If it looks like JSON/XML/Syslog/CEF, it's not CSV
        first = lines[0]
        if first.startswith(("{", "[", "<", "CEF:", "LEEF:")):
            return False
        if first.startswith("<") and ">" in first: # syslog PRI
            return False

        # Check delimiter presence
        for delim in (",", ";", "\t"):
            counts = [line.count(delim) for line in lines[:5]]
            if counts and counts[0] >= 2 and all(c == counts[0] for c in counts):
                return True
        return False

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty CSV row")

        reader = csv.reader(io.StringIO(clean), delimiter=self.delimiter)
        try:
            row = next(reader)
        except Exception as e:
            raise ParserError(f"Failed to parse CSV row: {str(e)}") from e

        if self.headers:
            fields = dict(zip(self.headers, row))
        else:
            fields = {f"col_{idx}": val for idx, val in enumerate(row)}

        return ParsedEvent(
            raw_data=clean,
            format="csv",
            fields=fields,
            source_file=source_file,
            source_line=source_line,
            parser_name=self.name,
            parser_version=self.version
        )

    def parse_file(self, file_path: Union[str, Path], error_handler: Optional[Any] = None) -> Iterator[ParsedEvent]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"CSV file not found: {file_path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(4096)
            f.seek(0)
            if not sample.strip():
                return

            # Determine delimiter
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
                self.delimiter = dialect.delimiter
            except Exception:
                self.delimiter = ","

            reader = csv.reader(f, delimiter=self.delimiter)
            try:
                raw_headers = next(reader)
                headers = [h.strip().strip('"').strip("'") for h in raw_headers]
                self.headers = headers
            except StopIteration:
                return

            for line_no, row in enumerate(reader, start=2):
                if not row or all(c.strip() == "" for c in row):
                    continue
                if len(row) != len(headers):
                    # Pad or truncate row to prevent crash
                    if len(row) < len(headers):
                        row.extend([""] * (len(headers) - len(row)))
                    else:
                        row = row[:len(headers)]

                # Reconstruct or preserve raw row text
                raw_line = self.delimiter.join(f'"{val}"' if self.delimiter in str(val) else str(val) for val in row)
                fields = dict(zip(headers, [c.strip() for c in row]))

                yield ParsedEvent(
                    raw_data=raw_line,
                    format="csv",
                    fields=fields,
                    source_file=str(path),
                    source_line=line_no,
                    parser_name=self.name,
                    parser_version=self.version
                )
