"""Robustness / failure-path tests for src.core.parser.

All tests use stdlib only -- no hypothesis or third-party fuzz libraries.

Coverage goals:
  - Input-length guard (_MAX_LINE_LEN)
  - Year-rollover heuristic edge cases
  - Pathological inputs: null bytes, many colons, missing fields,
    invalid month/day, non-printable characters
  - All failure paths must return None -- never raise, never hang
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.core.parser import _MAX_LINE_LEN, ParsedLog, parse_syslog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UTC6 = timezone(timedelta(hours=6))

# A valid canonical log line -- used as a template for mutation tests.
_VALID_LINE = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 192.0.2.1 Down - test"
)


def _make_long_line(length: int, char: str = "A") -> str:
    """Return a string of *length* repeated *char* characters."""
    return char * length


# ---------------------------------------------------------------------------
# _MAX_LINE_LEN constant sanity
# ---------------------------------------------------------------------------


def test_max_line_len_constant_is_sane() -> None:
    """_MAX_LINE_LEN must be a positive integer >= 1024."""
    assert isinstance(_MAX_LINE_LEN, int)
    assert _MAX_LINE_LEN >= 1024


# ---------------------------------------------------------------------------
# Input-length guard
# ---------------------------------------------------------------------------


def test_line_exactly_at_limit_is_rejected() -> None:
    """A line _MAX_LINE_LEN+1 chars long is the first to be rejected."""
    # The guard is ``len(line) > _MAX_LINE_LEN`` so _MAX_LINE_LEN+1 triggers it.
    line = _make_long_line(_MAX_LINE_LEN + 1)
    assert parse_syslog(line) is None


def test_line_one_over_limit_rejected() -> None:
    """Any line longer than _MAX_LINE_LEN returns None."""
    line = _make_long_line(_MAX_LINE_LEN + 500)
    assert parse_syslog(line) is None


def test_very_long_garbage_line_returns_none() -> None:
    """A 100 KiB garbage line returns None without raising."""
    line = _make_long_line(100_000)
    assert parse_syslog(line) is None


def test_very_long_line_is_fast() -> None:
    """Rejecting a 1 MiB line must complete in under 100 ms (DoS guard works)."""
    line = _make_long_line(1_000_000)
    start = time.monotonic()
    result = parse_syslog(line)
    elapsed = time.monotonic() - start
    assert result is None
    assert elapsed < 0.1, f"Length guard took too long: {elapsed:.3f}s"


def test_long_line_with_many_colons_rejected() -> None:
    """A line longer than _MAX_LINE_LEN consisting of colons is rejected."""
    line = ":" * (_MAX_LINE_LEN + 100)
    assert parse_syslog(line) is None


def test_valid_line_just_under_limit_accepted() -> None:
    """A well-formed line well under _MAX_LINE_LEN is parsed normally."""
    # _VALID_LINE is ~190 chars -- far under the 8192 cap.
    result = parse_syslog(_VALID_LINE)
    assert result is not None
    assert isinstance(result, ParsedLog)


# ---------------------------------------------------------------------------
# Null bytes and non-printable characters
# ---------------------------------------------------------------------------


def test_null_byte_only_returns_none() -> None:
    """A string of null bytes returns None."""
    assert parse_syslog("\x00" * 100) is None


def test_line_with_embedded_null_bytes_returns_none() -> None:
    """A line containing null bytes (hostile input) returns None."""
    line = "May 22 21:12:21 192.168.1.1 123:\x00" + "A" * 200
    assert parse_syslog(line) is None


def test_line_with_control_characters_returns_none() -> None:
    """A line with control characters (BEL, ESC, etc.) returns None."""
    line = "\x07\x1b\x0c" + "X" * 50
    assert parse_syslog(line) is None


def test_line_with_only_newlines_returns_none() -> None:
    """A line of newline characters is treated as whitespace -- returns None."""
    assert parse_syslog("\n\n\n") is None


# ---------------------------------------------------------------------------
# Many colons (potential ReDoS input)
# ---------------------------------------------------------------------------


def test_many_colons_line_returns_none() -> None:
    """A line of 1000 colons returns None quickly."""
    line = ":" * 1000
    assert parse_syslog(line) is None


def test_many_colons_mixed_with_valid_prefix_returns_none() -> None:
    """Partial valid prefix followed by many colons returns None."""
    line = "May 22 21:12:21 192.168.1.1 123: RP/0/RP0/CPU0" + ":" * 500
    assert parse_syslog(line) is None


def test_many_colons_under_limit_is_fast() -> None:
    """Parsing a 4000-colon line under _MAX_LINE_LEN completes in < 100 ms."""
    line = ":" * 4000  # under 8192 limit
    start = time.monotonic()
    result = parse_syslog(line)
    elapsed = time.monotonic() - start
    assert result is None
    assert elapsed < 0.1, f"Regex on colon line took too long: {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# Missing fields / truncated lines
# ---------------------------------------------------------------------------


def test_empty_string_returns_none() -> None:
    """Empty string returns None."""
    assert parse_syslog("") is None


def test_whitespace_only_returns_none() -> None:
    """Whitespace-only string returns None."""
    assert parse_syslog("   \t\n  ") is None


def test_missing_source_ip_returns_none() -> None:
    """Line missing source IP returns None."""
    line = (
        "May 22 21:12:21 9238766: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : msg"
    )
    assert parse_syslog(line) is None


def test_missing_facility_code_returns_none() -> None:
    """Line without the %FACILITY-...-MNEMONIC block returns None."""
    line = (
        "May 22 21:12:21 192.168.1.1 123: "
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
        "no percent sign here"
    )
    assert parse_syslog(line) is None


def test_missing_rp_location_returns_none() -> None:
    """Line missing RP/LC location returns None."""
    line = (
        "May 22 21:12:21 192.168.1.1 123: BSCCL-RTR "
        "bgp[1097]: %ROUTING-BGP-5-ADJCHANGE : msg"
    )
    assert parse_syslog(line) is None


def test_truncated_at_timestamp_returns_none() -> None:
    """Line truncated after the outer timestamp returns None."""
    line = "May 22 21:12:21"
    assert parse_syslog(line) is None


def test_truncated_midway_returns_none() -> None:
    """Line truncated midway through the header returns None."""
    line = "May 22 21:12:21 192.168.1.1 123:"
    assert parse_syslog(line) is None


# ---------------------------------------------------------------------------
# Invalid month / day values in inner timestamp
# ---------------------------------------------------------------------------


def test_invalid_month_abbreviation_returns_none() -> None:
    """Inner timestamp with an unrecognised month returns None."""
    line = _VALID_LINE.replace(
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06:",
        "RP/0/RP0/CPU0:Abc 22 21:12:21.651 +06:",
    )
    assert parse_syslog(line) is None


def test_numeric_month_instead_of_abbrev_returns_none() -> None:
    """Inner timestamp with a numeric month (e.g. '05') returns None."""
    line = _VALID_LINE.replace(
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06:",
        "RP/0/RP0/CPU0:05 22 21:12:21.651 +06:",
    )
    # The regex will still find \w+ for the month but _MONTH_MAP won't map "05"
    assert parse_syslog(line) is None


def test_invalid_day_32_returns_none() -> None:
    """Inner timestamp with day=32 (invalid) returns None."""
    line = _VALID_LINE.replace(
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06:",
        "RP/0/RP0/CPU0:May 32 21:12:21.651 +06:",
    )
    assert parse_syslog(line) is None


def test_invalid_day_0_returns_none() -> None:
    """Inner timestamp with day=0 (invalid) returns None."""
    line = _VALID_LINE.replace(
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06:",
        "RP/0/RP0/CPU0:May  0 21:12:21.651 +06:",
    )
    assert parse_syslog(line) is None


# ---------------------------------------------------------------------------
# Year-rollover heuristic
# ---------------------------------------------------------------------------


def _make_fake_now(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, 12, 0, 0, tzinfo=_UTC6)


def test_year_rollover_december_log_in_january() -> None:
    """Dec log received in Jan must resolve to previous year."""
    from src.core.parser import _parse_inner_timestamp

    fake_now = _make_fake_now(2026, 1, 3)

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        ts = _parse_inner_timestamp("Dec 31 23:59:59.000 +06")

    assert ts.year == 2025  # rolled back to previous year


def test_year_rollover_november_log_in_january() -> None:
    """Nov log received in Jan is also rolled back (month 11 > 1+1=2)."""
    from src.core.parser import _parse_inner_timestamp

    fake_now = _make_fake_now(2026, 1, 15)

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        ts = _parse_inner_timestamp("Nov 15 08:00:00 +06")

    assert ts.year == 2025


def test_no_year_rollover_when_months_match() -> None:
    """Log from current month is NOT rolled back."""
    from src.core.parser import _parse_inner_timestamp

    fake_now = _make_fake_now(2026, 5, 24)

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        ts = _parse_inner_timestamp("May 22 21:12:21.651 +06")

    assert ts.year == 2026


def test_no_year_rollover_one_month_ahead() -> None:
    """Log one month ahead is kept in current year (lookahead window)."""
    from src.core.parser import _parse_inner_timestamp

    # Current month = May (5); log month = Jun (6); 6 > 5+1=6 is False
    fake_now = _make_fake_now(2026, 5, 24)

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        ts = _parse_inner_timestamp("Jun 01 00:00:00 +06")

    assert ts.year == 2026


def test_year_rollover_two_months_ahead_rolls_back() -> None:
    """Log two months ahead of current month triggers year rollback."""
    from src.core.parser import _parse_inner_timestamp

    # Current month = May (5); log month = Aug (8); 8 > 5+1=6 -> rollback
    fake_now = _make_fake_now(2026, 5, 24)

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        ts = _parse_inner_timestamp("Aug 01 00:00:00 +06")

    assert ts.year == 2025


# ---------------------------------------------------------------------------
# Mixed / fuzz-style corpus
# ---------------------------------------------------------------------------

# Lines in this corpus that exceed 88 chars are broken with string concatenation
# to satisfy ruff E501 while keeping the inputs realistic.
_BGP_PREFIX = (
    "May 22 21:12:21 192.168.1.1 123: RP/0/RP0/CPU0:May 22 21:12:21 +06: bgp[1]: "
)

_FUZZ_CORPUS = [
    # Completely random printable characters
    "xYz abc 123 !!@@##$$%%",
    # Unicode characters
    "五月 22 21:12:21 192.168.1.1 123",
    # Looks like a syslog but severity field is non-numeric
    _BGP_PREFIX + "%A-B-X-C : msg",
    # Facility/subfacility starting with lowercase
    _BGP_PREFIX + "%routing-bgp-5-ADJCHANGE : msg",
    # Process field without brackets
    (
        "May 22 21:12:21 192.168.1.1 123: "
        "RP/0/RP0/CPU0:May 22 21:12:21 +06: bgp: "
        "%ROUTING-BGP-5-ADJCHANGE : msg"
    ),
    # IP address with letters
    (
        "May 22 21:12:21 192.168.XYZ.1 123: "
        "RP/0/RP0/CPU0:May 22 21:12:21 +06: bgp[1]: "
        "%ROUTING-BGP-5-ADJCHANGE : msg"
    ),
    # Just a number
    "42",
    # Just whitespace
    "   ",
    # Slash-only line
    "////////",
    # Percent sign only
    "%",
    # Very short junk
    "x",
    # SQL injection attempt
    "'; DROP TABLE logs; --",
    # Shell injection attempt
    "$(rm -rf /)",
    # Repeated dashes
    "-" * 500,
    # Tab characters
    "\t\t\t\t",
    # Mixed unicode and ASCII (zero-width space)
    "May 22​21:12:21 192.168.1.1",
]


@pytest.mark.parametrize("bad_input", _FUZZ_CORPUS)
def test_fuzz_corpus_returns_none(bad_input: str) -> None:
    """Fuzz-style corpus: every pathological input must return None, never raise."""
    result = parse_syslog(bad_input)
    assert result is None


_CONTROL_CORPUS = [
    # Null bytes
    "\x00",
    "\x00" * 100,
    "May 22\x0021:12:21 192.168.1.1 123:",
    # Surrogate escape codepoints (lone surrogates)
    "\udcfe\udcff",
    # Control characters
    "\x01\x02\x03\x04\x05",
    "\x07\x08\x0b\x0c\x0e\x0f",
    # DEL character
    "\x7f" * 50,
]


@pytest.mark.parametrize("bad_input", _CONTROL_CORPUS)
def test_fuzz_control_chars_return_none(bad_input: str) -> None:
    """Control-character corpus: must return None, never raise."""
    result = parse_syslog(bad_input)
    assert result is None
