"""
Event Action Normalization for ULPF.
Normalizes heterogeneous vendor action verbs (DENY, DROP, BLOCK, ALLOW, PERMIT, ACCEPT)
into standardized semantic actions.
"""

import re
from typing import Optional, Dict, Any

ACTION_MAP = {
    # Deny actions
    "deny": "deny",
    "denied": "deny",
    "block": "deny",
    "blocked": "deny",
    "drop": "deny",
    "dropped": "deny",
    "reject": "deny",
    "rejected": "deny",
    "discard": "deny",
    "discarded": "deny",
    "reset": "deny",
    "reset-server": "deny",
    "reset-client": "deny",
    "reset-both": "deny",
    "failed": "deny",
    "failure": "deny",
    "fail": "deny",
    "refused": "deny",

    # Allow actions
    "allow": "allow",
    "allowed": "allow",
    "permit": "allow",
    "permitted": "allow",
    "accept": "allow",
    "accepted": "allow",
    "pass": "allow",
    "passed": "allow",
    "forward": "allow",
    "forwarded": "allow",
    "built": "allow",
    "teardown": "allow",
    "established": "allow",
    "granted": "allow",
    "success": "allow",
    "succeeded": "allow",

    # Alert actions
    "alert": "alert",
    "alerted": "alert",
    "detect": "alert",
    "detected": "alert",
    "warn": "alert",
    "warning": "alert",

    # Auth actions
    "logon": "login",
    "login": "login",
    "sign-in": "login",
    "signin": "login",
    "authenticated": "login",
    "4624": "login",
    "logoff": "logout",
    "logout": "logout",
    "sign-out": "logout",
    "signout": "logout",
    "4634": "logout",
    "4647": "logout",
    "4625": "deny",
}

CANONICAL_ACTIONS = {"allow", "deny", "alert", "login", "logout"}

ALLOW_REGEX = re.compile(r'\b(allow|allowed|permit|permitted|accept|accepted|built|teardown|established|pass|passed|forward|forwarded|granted|success|succeeded)\b', re.IGNORECASE)
DENY_REGEX = re.compile(r'\b(deny|denied|block|blocked|drop|dropped|reject|rejected|discard|discarded|reset|failed|failure|refused)\b', re.IGNORECASE)
ALERT_REGEX = re.compile(r'\b(alert|alerted|detect|detected|warn|warning)\b', re.IGNORECASE)
LOGIN_REGEX = re.compile(r'\b(login|logon|signin|sign-in|authenticated)\b', re.IGNORECASE)
LOGOUT_REGEX = re.compile(r'\b(logout|logoff|signout|sign-out)\b', re.IGNORECASE)


def normalize_action(raw_action: Optional[str]) -> Optional[str]:
    """
    Standardize raw action verb into canonical taxonomy:
    'allow', 'deny', 'alert', 'login', 'logout'.
    """
    if not raw_action:
        return None
    cleaned = str(raw_action).strip().lower().replace("_", "-")
    return ACTION_MAP.get(cleaned, cleaned)


def infer_action_from_fields_and_raw(fields_or_event: Dict[str, Any], raw_text: str = "") -> Optional[str]:
    """
    Infers standard action verb from candidate parsed fields or unmapped raw log text
    when explicit vendor action field is absent.
    """
    candidates = []

    # Helper to recursively gather candidates from dictionaries
    def collect_values(d: Dict[str, Any]):
        if not isinstance(d, dict):
            return
        for k, v in d.items():
            if isinstance(v, str) and v.strip():
                candidates.append(v.strip())
            elif isinstance(v, dict):
                collect_values(v)

    if isinstance(fields_or_event, dict):
        collect_values(fields_or_event)

    # 1. Try matching extracted candidates against normalize_action
    for cand in candidates:
        norm = normalize_action(cand)
        if norm in CANONICAL_ACTIONS:
            return norm

    # 2. Extract raw text fallback if candidate matching failed
    txt = raw_text
    if not txt and isinstance(fields_or_event, dict):
        raw_sec = fields_or_event.get("raw")
        if isinstance(raw_sec, dict):
            txt = raw_sec.get("data", "")
        elif isinstance(raw_sec, str):
            txt = raw_sec

    if txt:
        if DENY_REGEX.search(txt):
            return "deny"
        if ALLOW_REGEX.search(txt):
            return "allow"
        if ALERT_REGEX.search(txt):
            return "alert"
        if LOGIN_REGEX.search(txt):
            return "login"
        if LOGOUT_REGEX.search(txt):
            return "logout"

    return None
