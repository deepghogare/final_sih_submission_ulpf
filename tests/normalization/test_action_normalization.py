"""
Unit Tests for Action Field Normalization and Fallback Inference in ULPF.
"""

import pytest
from app.core.pipeline import Pipeline
from app.normalization.actions import normalize_action, infer_action_from_fields_and_raw


def test_normalize_action_direct_mapping():
    assert normalize_action("ALLOW") == "allow"
    assert normalize_action("permit") == "allow"
    assert normalize_action("ACCEPT") == "allow"
    assert normalize_action("DENY") == "deny"
    assert normalize_action("drop") == "deny"
    assert normalize_action("BLOCK") == "deny"
    assert normalize_action("Built") == "allow"
    assert normalize_action("login") == "login"
    assert normalize_action("logout") == "logout"


def test_cisco_asa_action_normalization():
    pipeline = Pipeline()
    raw_asa_built = "<34>1 2026-09-23T23:45:00.123Z firewall.corp.local %ASA-6-302013: Built inbound TCP connection 120934 for outside:198.51.100.45/443 to inside:10.0.1.20/54321"
    ev = pipeline.process_raw_event(raw_asa_built)
    assert ev is not None
    assert ev.event.action == "allow"

    raw_asa_deny = "<34>1 2026-09-23T23:45:00.123Z firewall.corp.local %ASA-4-106023: Deny inbound UDP from 198.51.100.45/53 to 10.0.1.20/53"
    ev_deny = pipeline.process_raw_event(raw_asa_deny)
    assert ev_deny is not None
    assert ev_deny.event.action == "deny"


def test_checkpoint_leef_action_normalization():
    pipeline = Pipeline()
    raw_leef = "LEEF:2.0|CheckPoint|FW1|6.0|Accept|devTime=2026-09-23T23:45:04Z\tusrName=jdoe\tsrc=10.10.1.50\tdst=10.10.2.100\tproto=TCP\tsrcPort=49300\tdstPort=22"
    ev = pipeline.process_raw_event(raw_leef)
    assert ev is not None
    assert ev.event.action == "allow"
