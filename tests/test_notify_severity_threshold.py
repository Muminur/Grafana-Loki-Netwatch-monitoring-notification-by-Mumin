"""Tests for the notify_severity threshold gate in ``_on_syslog_line``.

The "Minimum Alert Severity" settings dropdown persists ``notify_severity``,
but until this gate was wired the value had **no effect** on dispatch: the
``will_notify`` gate keyed off each rule's hard-coded ``notify`` flag, which is
``True`` only for CRITICAL rules.  WARNING/INFO rules are ``notify=False``, so a
WARNING event never notified regardless of the configured floor — the dropdown
was a dead control.

These tests pin the corrected threshold semantics:

* ``notify_severity=CRITICAL`` (default) → only CRITICAL notifies (unchanged).
* ``notify_severity=WARNING`` → WARNING **and** CRITICAL notify.
* NOISE / USER_LOGIN (rank 0) never notify, at any floor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

import src.main as main_mod
from src.config import Settings

if TYPE_CHECKING:
    from collections.abc import Iterator


def _settings(*, notify_severity: str) -> Settings:
    """Minimal Settings stub carrying only what the notify path reads."""
    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", True)
    object.__setattr__(s, "telegram_enabled", False)
    object.__setattr__(s, "notify_severity", notify_severity)
    return s


@pytest.fixture
def _isolated_pipeline() -> Iterator[None]:
    """Force minimal globals so a parsed line reaches the notify gate cleanly.

    _dedup=None      → should_send=True
    _correlator=None → suppress=False
    _engine=None     → DB write skipped
    _escalation=None → escalation skipped

    Snapshots and restores the globals so the changes cannot leak into other
    tests (no cross-test global poisoning).
    """
    orig = (
        main_mod._dedup,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._engine,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    main_mod._dedup = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._engine = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001
    try:
        yield
    finally:
        (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = orig


# ─────────────────────────────────────────────────────────────────────────────
# Unit — the pure threshold helper
# ─────────────────────────────────────────────────────────────────────────────


class TestMeetsNotifyThreshold:
    """``_meets_notify_threshold(classification, floor)`` rank semantics."""

    @pytest.mark.parametrize(
        ("classification", "floor", "expected"),
        [
            # Default floor: only CRITICAL clears it.
            ("CRITICAL", "CRITICAL", True),
            ("WARNING", "CRITICAL", False),
            ("INFO", "CRITICAL", False),
            # WARNING floor: WARNING and above.
            ("CRITICAL", "WARNING", True),
            ("WARNING", "WARNING", True),
            ("INFO", "WARNING", False),
            # INFO floor: INFO and above.
            ("CRITICAL", "INFO", True),
            ("WARNING", "INFO", True),
            ("INFO", "INFO", True),
            # Non-notifiable classes never clear any floor.
            ("NOISE", "INFO", False),
            ("USER_LOGIN", "INFO", False),
            ("NOISE", "CRITICAL", False),
            ("USER_LOGIN", "WARNING", False),
        ],
    )
    def test_rank(self, classification: str, floor: str, expected: bool) -> None:
        assert (
            main_mod._meets_notify_threshold(classification, floor)  # noqa: SLF001
            is expected
        )

    def test_unknown_floor_defaults_to_critical(self) -> None:
        """An unexpected floor value falls back to the CRITICAL floor."""
        assert (
            main_mod._meets_notify_threshold("CRITICAL", "BOGUS") is True
        )  # noqa: SLF001
        assert (
            main_mod._meets_notify_threshold("WARNING", "BOGUS") is False
        )  # noqa: SLF001


# ─────────────────────────────────────────────────────────────────────────────
# Integration — the gate inside _on_syslog_line
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("_isolated_pipeline")
class TestNotifySeverityGate:
    """End-to-end: the configured floor controls whether senders fire."""

    @pytest.mark.asyncio
    async def test_warning_suppressed_at_critical_floor(
        self, sample_ber_clear_log: str
    ) -> None:
        """A WARNING event must NOT notify when the floor is CRITICAL (default)."""
        with (
            patch(
                "src.main.get_settings",
                return_value=_settings(notify_severity="CRITICAL"),
            ),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_ber_clear_log)  # noqa: SLF001

        mock_discord.assert_not_called()

    @pytest.mark.asyncio
    async def test_warning_notifies_at_warning_floor(
        self, sample_ber_clear_log: str
    ) -> None:
        """The same WARNING event MUST notify once the floor is lowered."""
        with (
            patch(
                "src.main.get_settings",
                return_value=_settings(notify_severity="WARNING"),
            ),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_ber_clear_log)  # noqa: SLF001

        mock_discord.assert_called_once()

    @pytest.mark.asyncio
    async def test_critical_notifies_at_critical_floor(
        self, sample_bgp_down_log: str
    ) -> None:
        """Regression: CRITICAL still notifies at the default floor (unchanged)."""
        with (
            patch(
                "src.main.get_settings",
                return_value=_settings(notify_severity="CRITICAL"),
            ),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

        mock_discord.assert_called_once()
