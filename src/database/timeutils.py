"""Time helpers for the BSCCL NetWatch database layer.

The DB stores naive Bangladesh-time (UTC+6) face values by convention, so
incident/audit write-sites must use :func:`now_bdt_naive` rather than
``datetime.now(UTC)`` (which is 6 hours behind Bangladesh local time).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_BDT = timezone(timedelta(hours=6))


def now_bdt_naive() -> datetime:
    """Current Bangladesh local time (UTC+6) as a naive datetime (tzinfo=None).

    Returns:
        A naive ``datetime`` whose face value matches the current time in
        Bangladesh (UTC+6), with ``tzinfo`` stripped so it can be stored
        in SQLite without an offset suffix.
    """
    return datetime.now(_BDT).replace(tzinfo=None)
