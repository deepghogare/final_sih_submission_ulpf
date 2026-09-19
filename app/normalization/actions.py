"""
Event Action Normalization for ULPF.
Normalizes heterogeneous vendor action verbs (DENY, DROP, BLOCK, ALLOW, PERMIT, ACCEPT)
into standardized semantic actions.
"""

from typing import Optional

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
    "logoff": "logout",
    "logout": "logout",
    "sign-out": "logout",
}


def normalize_action(raw_action: Optional[str]) -> Optional[str]:
    """
    Standardize raw action verb into canonical taxonomy:
    'allow', 'deny', 'alert', 'login', 'logout'.
    """
    if not raw_action:
        return None
    cleaned = str(raw_action).strip().lower().replace("_", "-")
    return ACTION_MAP.get(cleaned, cleaned)
