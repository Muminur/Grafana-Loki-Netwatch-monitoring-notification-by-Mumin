"""Regression tests for the maintenance-window suppression path in _on_syslog_line.

The suppression block computes the current time with ``datetime.now(UTC)``.  A
missing ``UTC`` import caused a ``NameError`` for every notify-worthy alert,
which is only reachable when ``will_notify`` is True — a path no other test
exercised.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import src.main as main_mod
from src.api.routes import get_maintenance_store


@pytest.fixture
def _isolated_pipeline() -> None:
    """Force the minimal globals so a parsed line reaches the notify path.

    _dedup=None  → should_send=True
    _correlator=None → suppress=False
    _engine=None → DB write skipped
    Together these make ``will_notify`` True for a notify-worthy log.
    """
    main_mod._dedup = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._engine = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001


@pytest.mark.usefixtures("_isolated_pipeline")
async def test_notify_worthy_alert_does_not_raise(sample_bgp_down_log: str) -> None:
    """A notify-worthy alert must traverse the maintenance block without error."""
    # Must not raise NameError: name 'UTC' is not defined
    await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001


@pytest.mark.usefixtures("_isolated_pipeline")
async def test_active_maintenance_window_is_evaluated(sample_bgp_down_log: str) -> None:
    """An active window matching the device exercises lines 162-176 cleanly."""
    store = get_maintenance_store()
    original = list(store)
    now = datetime.now(UTC)
    store.append(
        {
            "id": "test-window",
            "device_name": "EQ-RTR-01",
            "start_time": (now - timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(hours=1)).isoformat(),
        }
    )
    try:
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001
    finally:
        store.clear()
        store.extend(original)
