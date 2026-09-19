"""
Base Parser Interface for ULPF.
All modular format parsers inherit from BaseParser.
Parsers focus strictly on syntactic extraction (format to dict),
NOT semantic normalization.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Union, Optional, Any
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class BaseParser(ABC):
    """
    Abstract Base Class for all format parsers.
    Ensures a consistent interface across JSON, NDJSON, CSV, Syslog, CEF, LEEF, XML, Text.
    """
    name: str = "base"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = ()

    @abstractmethod
    def can_parse(self, sample: str) -> bool:
        """
        Evaluate a text sample to determine if this parser can parse the content.
        Uses content structure and signatures, not just file extensions.
        """
        pass

    @abstractmethod
    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        """
        Parse a single event string into an intermediate ParsedEvent object.
        Must raise ParserError if syntactic parsing fails.
        """
        pass

    def parse_file(self, file_path: Union[str, Path], error_handler: Optional[Any] = None) -> Iterator[ParsedEvent]:
        """
        Parse an entire log file, yielding individual ParsedEvents.
        Default implementation reads line by line; override for whole-file formats like JSON array or XML.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue
                try:
                    yield self.parse_event(clean_line, source_file=str(path), source_line=line_no)
                except Exception as e:
                    if error_handler:
                        error_handler(clean_line, str(e), line_no)
                    else:
                        raise ParserError(f"Failed to parse line {line_no}: {str(e)}") from e

    def parse_stream(self, lines: Iterator[str], source_name: Optional[str] = "stream") -> Iterator[ParsedEvent]:
        """Parse an iterable/stream of log lines."""
        for line_no, line in enumerate(lines, start=1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue
            yield self.parse_event(clean_line, source_file=source_name, source_line=line_no)
