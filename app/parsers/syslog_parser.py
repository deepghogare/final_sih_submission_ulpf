"""
Syslog Parser for ULPF.
Supports RFC 3164 (BSD syslog) and RFC 5424 (Modern IETF syslog).
Extracts PRI, facility, severity, timestamps, hostnames, tags, and message content.
"""

import re
from typing import Optional, Dict, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class SyslogParser(BaseParser):
    name: str = "syslog"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".log", ".syslog")

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
    RFC5424_PATTERN = re.compile(
        r"^<(?P<pri>\d{1,3})>1\s+"
        r"(?P<timestamp>[^\s]+)\s+"
        r"(?P<hostname>[^\s]+)\s+"
        r"(?P<appname>[^\s]+)\s+"
        r"(?P<procid>[^\s]+)\s+"
        r"(?P<msgid>[^\s]+)\s*"
        r"(?P<structured_data>-(?:\[.*?\])*|\[.*?\])?\s*"
        r"(?P<msg>.*)$"
    )

    # RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG[PID]: MSG or without PRI
    RFC3164_PATTERN = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?"
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
        r"(?P<hostname>[^\s:]+)\s+"
        r"(?:(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*)?"
        r"(?P<msg>.*)$"
    )

    KV_PATTERN = re.compile(r'(\w+)=["\']?([^"\'\s,]+|"[^"]*")["\']?')

    def can_parse(self, sample: str) -> bool:
        lines = [l.strip() for l in sample.splitlines() if l.strip()]
        if not lines:
            return False
        first = lines[0]
        if first.startswith("CEF:") or first.startswith("LEEF:"):
            return False
        if self.RFC5424_PATTERN.match(first):
            return True
        if self.RFC3164_PATTERN.match(first):
            return True
        return False

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty syslog event")

        fields: Dict[str, Any] = {}
        msg_text = clean

        # Try RFC 5424
        match5424 = self.RFC5424_PATTERN.match(clean)
        if match5424:
            d = match5424.groupdict()
            pri = int(d["pri"])
            fields["pri"] = pri
            fields["facility"] = pri >> 3
            fields["syslog_severity"] = pri & 7
            fields["timestamp"] = d["timestamp"] if d["timestamp"] != "-" else None
            fields["hostname"] = d["hostname"] if d["hostname"] != "-" else None
            fields["app_name"] = d["appname"] if d["appname"] != "-" else None
            fields["proc_id"] = d["procid"] if d["procid"] != "-" else None
            fields["msg_id"] = d["msgid"] if d["msgid"] != "-" else None
            if d.get("structured_data") and d["structured_data"] != "-":
                fields["structured_data"] = d["structured_data"]
            msg_text = d["msg"]
            fields["message"] = msg_text
        else:
            # Try RFC 3164
            match3164 = self.RFC3164_PATTERN.match(clean)
            if match3164:
                d = match3164.groupdict()
                if d.get("pri"):
                    pri = int(d["pri"])
                    fields["pri"] = pri
                    fields["facility"] = pri >> 3
                    fields["syslog_severity"] = pri & 7
                fields["timestamp"] = d["timestamp"]
                fields["hostname"] = d["hostname"]
                if d.get("tag"):
                    fields["tag"] = d["tag"]
                if d.get("pid"):
                    fields["pid"] = d["pid"]
                msg_text = d["msg"]
                fields["message"] = msg_text
            else:
                fields["message"] = clean

        # Extract any embedded key=value pairs from message body
        if msg_text:
            for k, v in self.KV_PATTERN.findall(msg_text):
                cleaned_val = v.strip('"\'')
                if k not in fields:
                    fields[k] = cleaned_val

        return ParsedEvent(
            raw_data=clean,
            format="syslog",
            fields=fields,
            source_file=source_file,
            source_line=source_line,
            parser_name=self.name,
            parser_version=self.version
        )
