"""
Severity Normalization Engine for ULPF.
Normalizes heterogeneous severity scales (0-10, Syslog 0-7, qualitative text)
into standard: 'info', 'low', 'medium', 'high', 'critical'.
"""

from typing import Optional, Union

TEXT_SEVERITY_MAP = {
    # Info
    "informational": "info",
    "info": "info",
    "debug": "info",
    "trace": "info",
    "notice": "info",
    "none": "info",

    # Low
    "low": "low",
    "minor": "low",
    "warning": "low",
    "warn": "low",

    # Medium
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "major": "medium",

    # High
    "high": "high",
    "error": "high",
    "err": "high",
    "severe": "high",

    # Critical
    "critical": "critical",
    "crit": "critical",
    "fatal": "critical",
    "emerg": "critical",
    "emergency": "critical",
    "alert": "critical",
}


def normalize_severity(raw_severity: Optional[Union[str, int, float]]) -> Optional[str]:
    """
    Standardize severity to: 'info', 'low', 'medium', 'high', 'critical'.
    """
    if raw_severity is None:
        return None

    # Handle numeric severity
    if isinstance(raw_severity, (int, float)):
        return _from_numeric(raw_severity)

    s = str(raw_severity).strip().lower()
    if not s or s in ("-", "null"):
        return None

    # Numeric as string
    if s.isdigit():
        return _from_numeric(int(s))

    return TEXT_SEVERITY_MAP.get(s, "info")


def _from_numeric(val: Union[int, float]) -> str:
    """
    Handles standard 0-10 CEF scale or 0-7 Syslog scale.
    """
    num = float(val)
    if num <= 2:
        return "info"
    elif num <= 4:
        return "low"
    elif num <= 6:
        return "medium"
    elif num <= 8:
        return "high"
    else:
        return "critical"
