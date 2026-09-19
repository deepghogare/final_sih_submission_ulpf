"""
Timestamp Normalization Engine for ULPF.
Normalizes diverse date/time representations to standard ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ).
Supports:
  - ISO 8601 (2026-09-02T17:30:15Z, 2026-09-02T17:30:15+05:30)
  - RFC 2822 (Wed, 02 Sep 2026 17:30:15 +0000)
  - Syslog BSD format (Sep  2 17:30:15 or Sep 02 17:30:15)
  - UNIX Epoch seconds (1788370215) and milliseconds (1788370215000)
  - CEF timestamp formats (Sep 02 2026 17:30:15)
"""

from datetime import datetime, timezone
import re
from typing import Optional, Union

MONTH_MAP = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12
}

BSD_SYSLOG_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<subsecond>\d+))?$"
)

CEF_DATE_REGEX = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})$"
)


def normalize_timestamp(raw_time: Optional[Union[str, int, float]], default_year: Optional[int] = None) -> Optional[str]:
    """
    Parses and standardizes any supported timestamp representation to ISO 8601 UTC.
    Returns: string formatted as 'YYYY-MM-DDTHH:MM:SSZ' or None if invalid/empty.
    """
    if raw_time is None:
        return None

    # Handle numeric epoch timestamp
    if isinstance(raw_time, (int, float)):
        return _from_epoch(raw_time)

    raw_str = str(raw_time).strip()
    if not raw_str or raw_str in ("-", "null", "None"):
        return None

    # Epoch as string (e.g. "1788370215" or "1788370215.123" or "1788370215000")
    if raw_str.isdigit() or (raw_str.replace(".", "", 1).isdigit() and raw_str.count(".") <= 1):
        try:
            num = float(raw_str)
            # If timestamp is likely milliseconds (greater than year 2286 in seconds)
            if num > 1e11:
                num = num / 1000.0
            dt = datetime.fromtimestamp(num, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # Try standard ISO 8601 parsing (built-in in Python 3.11+)
    try:
        clean_iso = raw_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass

    # Try CEF date pattern: "Sep 02 2026 17:30:15"
    cef_match = CEF_DATE_REGEX.match(raw_str)
    if cef_match:
        m = cef_match.group("month").lower()
        if m in MONTH_MAP:
            try:
                dt = datetime(
                    year=int(cef_match.group("year")),
                    month=MONTH_MAP[m],
                    day=int(cef_match.group("day")),
                    hour=int(cef_match.group("hour")),
                    minute=int(cef_match.group("minute")),
                    second=int(cef_match.group("second")),
                    tzinfo=timezone.utc
                )
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass

    # Try BSD Syslog pattern: "Sep  2 17:30:15"
    bsd_match = BSD_SYSLOG_REGEX.match(raw_str)
    if bsd_match:
        m = bsd_match.group("month").lower()
        if m in MONTH_MAP:
            year = default_year or datetime.now(timezone.utc).year
            try:
                dt = datetime(
                    year=year,
                    month=MONTH_MAP[m],
                    day=int(bsd_match.group("day")),
                    hour=int(bsd_match.group("hour")),
                    minute=int(bsd_match.group("minute")),
                    second=int(bsd_match.group("second")),
                    tzinfo=timezone.utc
                )
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass

    # Common standard format trials
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%b/%Y:%H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %z",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(raw_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue

    # Return None if unparseable rather than throwing fatal error
    return None


def _from_epoch(num: Union[int, float]) -> Optional[str]:
    try:
        val = float(num)
        if val > 1e11:  # Milliseconds
            val = val / 1000.0
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None
