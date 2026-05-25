"""Cisco IOS-XR syslog parser for BSCCL NetWatch.

Handles 4 distinct IOS-XR syslog formats:
  1. +06 timezone offset with hostname prefix
  2. BDT timezone name without hostname prefix
  3. ADMIN plane (0/RP0/ADMIN0 location prefix)
  4. No timezone, no hostname, no fractional seconds
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Maximum accepted input line length (bytes/chars).  Lines longer than this cap
# are rejected immediately — before any regex is applied — to prevent a hostile
# syslog sender from triggering catastrophic backtracking (ReDoS) or excessive
# memory allocation on the regex engine.  8 KiB is far above any legitimate
# Cisco IOS-XR syslog line (~500 chars typical, ~2 KiB absolute upper bound).
_MAX_LINE_LEN: int = 8192

# UTC+6 timezone (Bangladesh Standard Time / BDT)
_UTC6 = timezone(timedelta(hours=6))

# Syslog header: <month> <day> <time> <source_ip> <seq>:
# Optionally followed by a hostname (uppercase word with dashes/digits)
# Then the RP/LC/ADMIN location, colon, inner timestamp, process, and % code.
#
# The inner_ts uses a non-greedy .+? anchored by the process pattern
# (\S+\[\d+\]) to correctly handle timestamps with colons (e.g. 21:12:21.651 +06).
_HEADER_RE = re.compile(
    r"^(?:\w+)\s+(?:\d+)\s+(?:\d{2}:\d{2}:\d{2})"
    r"\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
    r"\s+\d+:"
    r"(?:\s+(?P<hostname>[A-Z][A-Z0-9_-]+))?"
    r"\s+(?P<rp_location>(?:RP|LC)/\d+/[A-Z0-9]+/[A-Z0-9]+|0/RP\d+/ADMIN\d+)"
    r":(?P<inner_ts>.+?):\s+(?P<process>\S+\[\d+\]):\s+"
    r"%(?P<facility>[A-Z][A-Z0-9_]*)-(?P<subfacility>[A-Z][A-Z0-9_]*)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+)"
    r"\s+:\s+(?P<message>.+)$",
)

_INNER_TS_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?:\s+(?P<tz>\+\d+|[A-Z]+))?"
)


@dataclass(frozen=True)
class ParsedLog:
    """Structured representation of a parsed Cisco IOS-XR syslog line."""

    timestamp: datetime
    source_ip: str
    hostname: str
    rp_location: str
    facility: str
    subfacility: str
    severity_level: int
    mnemonic: str
    message: str
    raw: str


_MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_inner_timestamp(inner: str) -> datetime:
    """Parse the inner device timestamp (after RP location colon).

    Handles three sub-formats:
      - ``May 22 21:12:21.651 +06``
      - ``May 22 19:33:37.787 BDT``
      - ``May 22 05:27:59``   (no TZ, no fractional)
    """
    inner = inner.strip()
    m = _INNER_TS_RE.search(inner)
    if not m:
        raise ValueError(f"Unparseable inner timestamp: {inner!r}")

    month_str = m.group("month")
    month = _MONTH_MAP.get(month_str)
    if month is None:
        raise ValueError(
            f"Unknown month abbreviation: {month_str!r} in timestamp: {inner!r}"
        )
    day = int(m.group("day"))
    hour = int(m.group("hour"))
    minute = int(m.group("minute"))
    second = int(m.group("second"))
    frac = m.group("frac")
    microsecond = int(frac[:6].ljust(6, "0")) if frac else 0

    # All BSCCL devices are UTC+6 regardless of whether the log says +06, BDT,
    # or nothing.
    now = datetime.now(_UTC6)
    year = now.year

    parsed_ts = datetime(
        year=year,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
        microsecond=microsecond,
        tzinfo=_UTC6,
    )

    # Year-rollover heuristic
    # -------------------------------------------------------------------
    # IOS-XR syslogs carry a month+day but no year.  We assume the current
    # year initially, then correct for two edge cases:
    #
    # Case A — log from previous calendar year (common near Jan 1):
    #   A log sent on Dec 31 and received on Jan 3 would have month=12
    #   while now.month=1.  The condition ``parsed_ts.month > now.month + 1``
    #   catches this: month 12 > 1+1=2, so we roll back to year-1.
    #
    # Case B — current month or one month ahead:
    #   ``> now.month + 1`` deliberately allows a 1-month lookahead window
    #   to tolerate small clock skew between the Loki forwarder and the
    #   device without misclassifying the year.  A device with an NTP drift
    #   of up to ~30 days is not back-dated to the previous year.
    #
    # Case C — log from next calendar year (Dec→Jan forward rollover):
    #   In late November or December (now.month >= 11) a January/February
    #   log (parsed_ts.month <= 2) is from the upcoming year, not the
    #   current one.  Without this forward case, a Jan log received in Dec
    #   would stay in the current year instead of rolling forward.
    #
    # Known limitation: the heuristic fails if a log is delayed by more
    # than one calendar month before reaching the collector, but that is
    # not a realistic scenario for live syslog streams.
    if parsed_ts.month > now.month + 1:
        parsed_ts = parsed_ts.replace(year=year - 1)
    elif now.month >= 11 and parsed_ts.month <= 2:
        parsed_ts = parsed_ts.replace(year=year + 1)

    return parsed_ts


def parse_syslog(line: str) -> ParsedLog | None:
    """Parse a single Cisco IOS-XR syslog line.

    Returns ``None`` for:
    - empty / whitespace-only lines
    - lines exceeding ``_MAX_LINE_LEN`` (DoS guard — checked before any regex)
    - lines that do not match any known format
    """
    if not line or not line.strip():
        return None

    # Reject oversized lines before running any regex to prevent ReDoS /
    # memory-DoS from a hostile syslog sender.
    if len(line) > _MAX_LINE_LEN:
        return None

    m = _HEADER_RE.match(line)
    if not m:
        return None

    inner_ts_raw = m.group("inner_ts")
    try:
        ts = _parse_inner_timestamp(inner_ts_raw)
    except ValueError:
        return None

    return ParsedLog(
        timestamp=ts,
        source_ip=m.group("source_ip"),
        hostname=m.group("hostname") or "",
        rp_location=m.group("rp_location"),
        facility=m.group("facility"),
        subfacility=m.group("subfacility"),
        severity_level=int(m.group("severity")),
        mnemonic=m.group("mnemonic"),
        message=m.group("message"),
        raw=line,
    )
