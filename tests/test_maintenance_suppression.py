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


async def test_resolution_notification_suppressed_during_maintenance(
    sample_bgp_up_log: str,
) -> None:
    """A RESOLVED notification must be suppressed during an active window.

    The alert path already checks the maintenance store, but the recovery /
    resolution path sent RESOLVED Discord/Telegram messages regardless — noise
    the operator scheduled the window to silence.
    """
    from dataclasses import replace  # noqa: PLC0415
    from unittest.mock import AsyncMock, patch  # noqa: PLC0415

    from src.config import Settings  # noqa: PLC0415
    from src.core.correlator import CorrelationEngine  # noqa: PLC0415
    from src.core.enricher import enrich  # noqa: PLC0415
    from src.core.parser import parse_syslog  # noqa: PLC0415

    parsed = parse_syslog(sample_bgp_up_log)
    assert parsed is not None
    enriched = enrich(parsed)

    # Correlator holding an active incident for the device, so the recovery
    # event reaches the resolution-notification block.
    correlator = CorrelationEngine()
    correlator._incidents["INC-D2-TEST"] = [enriched]  # noqa: SLF001
    correlator._device_incidents[parsed.source_ip] = ["INC-D2-TEST"]  # noqa: SLF001

    orig = (
        main_mod._dedup,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._engine,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    main_mod._dedup = None  # noqa: SLF001
    main_mod._correlator = correlator  # noqa: SLF001
    main_mod._engine = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    store = get_maintenance_store()
    original_store = list(store)
    now = datetime.now(UTC)
    store.append(
        {
            "id": "win-d2",
            "device_name": enriched.device_name,
            "start_time": (now - timedelta(hours=1)).isoformat(),
            "end_time": (now + timedelta(hours=1)).isoformat(),
        }
    )

    settings = replace(Settings(), discord_enabled=True, telegram_enabled=True)
    discord = AsyncMock(return_value=True)
    telegram = AsyncMock(return_value=True)
    try:
        with (
            patch("src.main.get_settings", return_value=settings),
            patch("src.main.send_discord_resolution", discord),
            patch("src.main.send_telegram_resolution", telegram),
        ):
            await main_mod._on_syslog_line(sample_bgp_up_log)  # noqa: SLF001
        discord.assert_not_awaited()
        telegram.assert_not_awaited()
    finally:
        store.clear()
        store.extend(original_store)
        (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = orig
