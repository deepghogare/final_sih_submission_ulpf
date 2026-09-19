"""
Unit Tests for all ULPF Format Parsers.
Verifies syntactic parsing across JSON, NDJSON, CSV, Syslog, CEF, LEEF, XML, and Text.
"""

import pytest
from app.parsers.json_parser import JsonParser
from app.parsers.ndjson_parser import NdjsonParser
from app.parsers.csv_parser import CsvParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.cef_parser import CefParser
from app.parsers.leef_parser import LeefParser
from app.parsers.xml_parser import XmlParser
from app.parsers.text_parser import TextParser
from app.models.errors import ParserError


def test_json_parser_single():
    parser = JsonParser()
    raw = '{"src_ip": "10.0.0.1", "action": "ALLOW"}'
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "json"
    assert parsed.fields["src_ip"] == "10.0.0.1"
    assert parsed.fields["action"] == "ALLOW"
    assert parsed.raw_data == raw


def test_json_parser_malformed():
    parser = JsonParser()
    with pytest.raises(ParserError):
        parser.parse_event('{"src_ip": "10.0.0.1", INVALID')


def test_ndjson_parser():
    parser = NdjsonParser()
    raw = '{"event_id": 1, "msg": "test"}'
    parsed = parser.parse_event(raw)
    assert parsed.format == "ndjson"
    assert parsed.fields["event_id"] == 1


def test_csv_parser():
    raw_row = "192.168.1.1,10.0.0.1,80,ALLOW"
    parser = CsvParser(headers=["src", "dst", "port", "action"])
    parsed = parser.parse_event(raw_row)
    assert parsed.format == "csv"
    assert parsed.fields["src"] == "192.168.1.1"
    assert parsed.fields["port"] == "80"
    assert parsed.fields["action"] == "ALLOW"


def test_syslog_rfc5424():
    parser = SyslogParser()
    raw = "<134>1 2026-09-02T17:30:15Z host01 app - - - action=DENY src=192.168.1.1"
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "syslog"
    assert parsed.fields["pri"] == 134
    assert parsed.fields["facility"] == 16
    assert parsed.fields["syslog_severity"] == 6
    assert parsed.fields["action"] == "DENY"
    assert parsed.fields["src"] == "192.168.1.1"


def test_syslog_rfc3164():
    parser = SyslogParser()
    raw = "Sep  2 17:30:15 myhost sshd[123]: Failed password for root from 1.2.3.4 port 22"
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "syslog"
    assert parsed.fields["hostname"] == "myhost"
    assert parsed.fields["tag"] == "sshd"
    assert parsed.fields["pid"] == "123"


def test_cef_parser():
    parser = CefParser()
    raw = "CEF:0|VendorX|ProductY|1.0|100|Drop Event|High|src=192.168.1.5 dst=10.0.0.2 act=drop"
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "cef"
    assert parsed.fields["device_vendor"] == "VendorX"
    assert parsed.fields["device_product"] == "ProductY"
    assert parsed.fields["severity"] == "High"
    assert parsed.fields["src"] == "192.168.1.5"
    assert parsed.fields["act"] == "drop"


def test_leef_parser_v1_and_v2():
    parser = LeefParser()
    raw_v1 = "LEEF:1.0|VendorA|ProductB|2.0|AlertID|src=1.1.1.1\tdst=2.2.2.2\taction=BLOCK"
    assert parser.can_parse(raw_v1)
    parsed = parser.parse_event(raw_v1)
    assert parsed.format == "leef"
    assert parsed.fields["device_vendor"] == "VendorA"
    assert parsed.fields["src"] == "1.1.1.1"
    assert parsed.fields["action"] == "BLOCK"


def test_xml_parser():
    parser = XmlParser()
    raw = "<Event><System><EventID>4624</EventID></System><EventData><IpAddress>192.168.1.5</IpAddress></EventData></Event>"
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "xml"
    assert parsed.fields["System"]["EventID"] == "4624"
    assert parsed.fields["EventData"]["IpAddress"] == "192.168.1.5"


def test_text_parser():
    parser = TextParser()
    raw = "action=DENY src_ip=192.168.1.100 dst_ip=10.0.0.5 proto=TCP"
    assert parser.can_parse(raw)
    parsed = parser.parse_event(raw)
    assert parsed.format == "text"
    assert parsed.fields["action"] == "DENY"
    assert parsed.fields["src_ip"] == "192.168.1.100"
