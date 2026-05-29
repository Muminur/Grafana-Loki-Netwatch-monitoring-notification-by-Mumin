"""Tests that acknowledging an incident suppresses repeat notifications.

Reproduces the operator-reported bug: a MAXPFX alert on KKT-Core-2 was
acknowledged in the dashboard, yet subsequent matching MAXPFX events kept
firing Discord notifications.  Acknowledging an incident must stop further
Discord/Telegram alerts for events that fold onto the same incident card,
while a *different* fault (different group key) must still notify.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

import src.main as main_mod
from src.api import routes as routes_mod
from src.config import Settings

if TYPE_CHECKING:
    from collections.abc import Iterator


def _settings() -> Settings:
    """Minimal Settings stub carrying only what the notify path reads."""
    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", True)
    object.__setattr__(s, "telegram_enabled", False)
    object.__setattr__(s, "notify_severity", "CRITICAL")
    return s


@pytest.fixture
def _isolated_pipeline() -> Iterator[None]:
    """Force minimal globals so a parsed line reaches the notify gate cleanly.

    _dedup=None      → should_send=True (no dedup interference; simulates a
                       repeat event arriving after the 5-min dedup window).
    _correlator=None → independent event, incident_id="" (the MAXPFX case).
    _engine=None     → DB writes skipped.
    _escalation=None → escalation skipped.

    Snapshots and restores the globals + stores so the changes cannot leak
    into other tests (no cross-test global poisoning).
    """
    orig = (
        main_mod._dedup,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._engine,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    orig_inc = list(routes_mod._incidents_store)  # noqa: SLF001
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._engine = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001
    routes_mod._incidents_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    try:
        yield
    finally:
        (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = orig
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_inc)  # noqa: SLF001
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001


# ─────────────────────────────────────────────────────────────────────────────
# Unit — the acknowledgement lookup helper
# ─────────────────────────────────────────────────────────────────────────────


class TestIsAlertAcknowledged:
    """``is_alert_acknowledged`` resolves the right incident card by group key."""

    def setup_method(self) -> None:
        routes_mod._incidents_store.clear()  # noqa: SLF001

    def test_unknown_alert_is_not_acknowledged(self) -> None:
        assert (
            routes_mod.is_alert_acknowledged(
                "KKT-Core-02", "MAXPFX", "", "163.47.83.6", 0, "reached 782, max 1000"
            )
            is False
        )

    def test_matching_acked_card_returns_true(self) -> None:
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "ALERT-1",
                "device": "KKT-Core-02",
                "mnemonic": "MAXPFX",
                "interface": "",
                "neighbor": "163.47.83.6",
                "as_number": 0,
                "message": "reached 782, max 1000",
                "acknowledged": True,
            }
        )
        assert (
            routes_mod.is_alert_acknowledged(
                # A *different* neighbor must still match — MAXPFX groups on
                # device:MAXPFX: (neighbor ignored), per _incident_group_key.
                "KKT-Core-02",
                "MAXPFX",
                "",
                "9.9.9.9",
                0,
                "reached 950, max 1000",
            )
            is True
        )

    def test_matching_but_unacked_card_returns_false(self) -> None:
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "ALERT-1",
                "device": "KKT-Core-02",
                "mnemonic": "MAXPFX",
                "interface": "",
                "neighbor": "163.47.83.6",
                "as_number": 0,
                "message": "reached 782, max 1000",
            }
        )
        assert (
            routes_mod.is_alert_acknowledged(
                "KKT-Core-02", "MAXPFX", "", "163.47.83.6", 0, "reached 782, max 1000"
            )
            is False
        )

    def test_different_device_does_not_match(self) -> None:
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "ALERT-1",
                "device": "KKT-Core-02",
                "mnemonic": "MAXPFX",
                "interface": "",
                "neighbor": "",
                "as_number": 0,
                "message": "reached 782, max 1000",
                "acknowledged": True,
            }
        )
        assert (
            routes_mod.is_alert_acknowledged(
                "EQ-RTR-01", "MAXPFX", "", "", 0, "reached 782, max 1000"
            )
            is False
        )

    def test_correlator_incident_matched_by_id(self) -> None:
        """A correlator-owned (INC-) incident is matched by id, not group key."""
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "INC-20260529-001",
                "device": "EQ-RTR-01",
                "mnemonic": "ADJCHANGE",
                "interface": "",
                "neighbor": "",
                "as_number": 0,
                "message": "backhaul down",
                "acknowledged": True,
            }
        )
        assert (
            routes_mod.is_alert_acknowledged(
                "EQ-RTR-01",
                "ADJCHANGE",
                "",
                "",
                0,
                "backhaul down",
                incident_id="INC-20260529-001",
            )
            is True
        )

    def test_inc_card_skipped_in_group_key_scan(self) -> None:
        """An INC- card must never satisfy the ungrouped group-key fallback."""
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "INC-20260529-002",
                "device": "KKT-Core-02",
                "mnemonic": "MAXPFX",
                "interface": "",
                "neighbor": "",
                "as_number": 0,
                "message": "reached 782, max 1000",
                "acknowledged": True,
            }
        )
        # No incident_id passed → group-key scan, which must skip the INC- card.
        assert (
            routes_mod.is_alert_acknowledged(
                "KKT-Core-02", "MAXPFX", "", "", 0, "reached 782, max 1000"
            )
            is False
        )


# ─────────────────────────────────────────────────────────────────────────────
# Integration — the gate inside _on_syslog_line
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("_isolated_pipeline")
class TestAckNotificationGate:
    """Acknowledging an incident card stops further pipeline notifications."""

    @pytest.mark.asyncio
    async def test_acked_incident_suppresses_repeat_notification(
        self, sample_maxpfx_log: str
    ) -> None:
        """The reported bug: after ACK, a repeat MAXPFX must NOT notify again."""
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            # First MAXPFX → notifies once and opens an incident card.
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            assert mock_discord.call_count == 1
            assert len(routes_mod._incidents_store) == 1  # noqa: SLF001

            # Operator acknowledges the incident in the dashboard.
            routes_mod._incidents_store[0]["acknowledged"] = True  # noqa: SLF001

            # A second identical MAXPFX must be suppressed.
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            assert mock_discord.call_count == 1

    @pytest.mark.asyncio
    async def test_unacked_incident_still_notifies(
        self, sample_maxpfx_log: str
    ) -> None:
        """Control: without ACK, the repeat MAXPFX notifies again (dedup off)."""
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            assert mock_discord.call_count == 2

    @pytest.mark.asyncio
    async def test_ack_does_not_suppress_a_different_fault(
        self, sample_maxpfx_log: str, sample_signal_failure_log: str
    ) -> None:
        """ACKing MAXPFX must not silence an unrelated fault (different key)."""
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            for inc in routes_mod._incidents_store:  # noqa: SLF001
                inc["acknowledged"] = True

            # A different device/mnemonic fault must still notify.
            await main_mod._on_syslog_line(sample_signal_failure_log)  # noqa: SLF001
            assert mock_discord.call_count == 2
