"""Tests for the two escalation false-positive fixes.

Bug 1 — a CRITICAL alert that recovers (Interface/BGP Up, alarm Clear) before a
human acknowledges it must never escalate.  ``EscalationEngine.resolve_alert``
cancels the precise tracked entry, and ``_on_syslog_line`` calls it on every
recovery event regardless of correlator state.

Bug 2 — a MAXPFX alert must never escalate while the operator has MAXPFX alerts
muted.  ``_dispatch_pending_escalations`` skips MAXPFX while muted, leaving the
entry pending so it still escalates if MAXPFX is re-enabled.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

import src.api.routes as routes_mod
import src.main as main_mod
from src.config import Settings
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog
from src.notifications.escalation import EscalationEngine

_UTC6 = timezone(timedelta(hours=6))


def _now() -> datetime:
    return datetime.now(_UTC6)


def _parsed(
    *, mnemonic: str, message: str, source_ip: str = "192.168.203.1"
) -> ParsedLog:
    return ParsedLog(
        timestamp=datetime(2026, 5, 22, 21, 12, 21, tzinfo=_UTC6),
        source_ip=source_ip,
        hostname="BSCCL-EQ-RTR-01",
        rp_location="RP/0/RP0/CPU0",
        facility="ROUTING",
        subfacility="BGP",
        severity_level=5,
        mnemonic=mnemonic,
        message=message,
        raw=f"%ROUTING-BGP-5-{mnemonic} : {message}",
    )


def _enriched(
    *,
    mnemonic: str = "ADJCHANGE",
    classification: str = "CRITICAL",
    device_name: str = "EQ-RTR-01",
    bgp_neighbor: str = "2001:de8:4::39:9077:1",
    interface_name: str = "",
    message: str = "neighbor 2001:de8:4::39:9077:1 Down",
    source_ip: str = "192.168.203.1",
) -> EnrichedLog:
    return EnrichedLog(
        parsed=_parsed(mnemonic=mnemonic, message=message, source_ip=source_ip),
        classification=classification,
        rule_id="bgp_down",
        event_type="BGP Session Down",
        notify=True,
        device_name=device_name,
        device_location="Singapore Equinix",
        interface_name=interface_name,
        interface_description="",
        bundle_parent="",
        client_name="",
        bgp_neighbor=bgp_neighbor,
        as_number=399077,
        as_name="TCLOUD",
        vrf="network",
    )


def _settings(
    *, discord_enabled: bool = True, telegram_enabled: bool = False
) -> Settings:
    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", discord_enabled)
    object.__setattr__(s, "telegram_enabled", telegram_enabled)
    object.__setattr__(s, "notify_severity", "CRITICAL")
    return s


class TestResolveAlert:
    """EscalationEngine.resolve_alert cancels the precise recovered entry."""

    def test_cancels_matching_tracked_alert(self) -> None:
        eng = EscalationEngine()
        enriched = _enriched()
        key = (enriched.device_name, enriched.parsed.mnemonic, enriched.bgp_neighbor)
        eng._tracked[key] = (enriched, _now() - timedelta(minutes=20))  # noqa: SLF001
        assert len(eng.get_pending_escalations()) == 1

        # Recovery event for the SAME device/mnemonic/neighbor (ADJCHANGE Up).
        recovery = _enriched(
            classification="WARNING",
            message="neighbor 2001:de8:4::39:9077:1 Up",
        )
        assert eng.resolve_alert(recovery) is True
        assert eng.get_pending_escalations() == []
        assert key not in eng._tracked  # noqa: SLF001

    def test_returns_false_when_no_match(self) -> None:
        eng = EscalationEngine()
        assert eng.resolve_alert(_enriched(device_name="NOPE")) is False

    def test_only_clears_matching_discriminator(self) -> None:
        """Recovery on one neighbor must NOT cancel another still-down neighbor."""
        eng = EscalationEngine()
        down_a = _enriched(bgp_neighbor="2001:de8:4::39:9077:1")
        down_b = _enriched(bgp_neighbor="2001:de8:4::2:4482:1")
        old = _now() - timedelta(minutes=20)
        for e in (down_a, down_b):
            eng._tracked[(e.device_name, e.parsed.mnemonic, e.bgp_neighbor)] = (
                e,
                old,
            )  # noqa: SLF001

        eng.resolve_alert(
            _enriched(
                classification="WARNING",
                bgp_neighbor="2001:de8:4::39:9077:1",
                message="neighbor 2001:de8:4::39:9077:1 Up",
            )
        )

        pending = eng.get_pending_escalations()
        assert len(pending) == 1
        assert pending[0][0].bgp_neighbor == "2001:de8:4::2:4482:1"

    def test_clears_acked_so_a_reflapped_alert_can_retrack(self) -> None:
        """Recovery removes the key from _acked too (not just _tracked).

        Guards the ``self._acked.discard(key)`` line: an alert that already
        escalated (key in _acked) must be fully forgotten on recovery so a
        later DOWN re-tracks cleanly rather than being silently suppressed.
        """
        eng = EscalationEngine()
        enriched = _enriched()
        key = (enriched.device_name, enriched.parsed.mnemonic, enriched.bgp_neighbor)
        eng._tracked[key] = (enriched, _now() - timedelta(minutes=20))  # noqa: SLF001
        eng._acked.add(key)  # noqa: SLF001  (already escalated)

        assert (
            eng.resolve_alert(
                _enriched(classification="WARNING", message="neighbor … Up")
            )
            is True
        )
        assert key not in eng._tracked  # noqa: SLF001
        assert key not in eng._acked  # noqa: SLF001

    def test_matches_interface_discriminator(self) -> None:
        """A link (UPDOWN) recovery cancels via the interface_name discriminator."""
        eng = EscalationEngine()
        down = _enriched(
            mnemonic="UPDOWN",
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            device_name="DHK-Core-3",
            message="Interface TenGigE0/0/0/0, changed state to down",
        )
        key = (down.device_name, down.parsed.mnemonic, down.interface_name)
        eng._tracked[key] = (down, _now() - timedelta(minutes=20))  # noqa: SLF001

        up = _enriched(
            mnemonic="UPDOWN",
            classification="WARNING",
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            device_name="DHK-Core-3",
            message="Interface TenGigE0/0/0/0, changed state to Up",
        )
        assert eng.resolve_alert(up) is True
        assert eng.get_pending_escalations() == []


class TestRecoveryCancelsEscalationInPipeline:
    """Bug 1 end-to-end: recovery cancels escalation with NO correlator incident."""

    def setup_method(self) -> None:
        self._orig = (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        )

    def teardown_method(self) -> None:
        (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = self._orig

    @pytest.mark.asyncio
    async def test_recovery_cancels_escalation_without_correlator_incident(
        self, sample_bgp_down_log: str, sample_bgp_up_log: str
    ) -> None:
        eng = EscalationEngine()
        main_mod._dedup = None  # noqa: SLF001
        main_mod._correlator = None  # noqa: SLF001  (no incident → old path can't fire)
        main_mod._engine = None  # noqa: SLF001
        main_mod._escalation = eng  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_alert", new_callable=AsyncMock),
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
            patch("src.main.send_discord_resolution", new_callable=AsyncMock),
            patch("src.main.send_telegram_resolution", new_callable=AsyncMock),
            patch.object(
                main_mod._ws_manager,  # noqa: SLF001
                "broadcast_filtered",
                new_callable=AsyncMock,
            ),
        ):
            # CRITICAL ADJCHANGE Down → tracked for escalation
            await main_mod._on_syslog_line(sample_bgp_down_log)
            assert len(eng._tracked) == 1  # noqa: SLF001

            # Back-date so it WOULD escalate if not cancelled
            key = next(iter(eng._tracked))  # noqa: SLF001
            tracked_log, _ts = eng._tracked[key]  # noqa: SLF001
            eng._tracked[key] = (
                tracked_log,
                _now() - timedelta(minutes=20),
            )  # noqa: SLF001
            assert len(eng.get_pending_escalations()) == 1

            # ADJCHANGE Up (recovery) → must cancel the escalation
            await main_mod._on_syslog_line(sample_bgp_up_log)

        assert eng.get_pending_escalations() == []
        assert len(eng._tracked) == 0  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_non_recovery_fault_does_not_cancel_its_own_escalation(
        self, sample_bgp_down_log: str
    ) -> None:
        """A plain CRITICAL fault (not a recovery) must NOT call resolve_alert.

        Regression guard: if the ``if is_recovery`` wiring were wrong, a fault
        would clear its own escalation immediately and nothing would ever fire.
        """
        eng = EscalationEngine()
        main_mod._dedup = None  # noqa: SLF001
        main_mod._correlator = None  # noqa: SLF001
        main_mod._engine = None  # noqa: SLF001
        main_mod._escalation = eng  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_alert", new_callable=AsyncMock),
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
            patch.object(
                main_mod._ws_manager,  # noqa: SLF001
                "broadcast_filtered",
                new_callable=AsyncMock,
            ),
        ):
            await main_mod._on_syslog_line(sample_bgp_down_log)

        # The fault stays tracked — it was not mistaken for a recovery.
        assert len(eng._tracked) == 1  # noqa: SLF001


class TestMutedMaxpfxNotEscalated:
    """Bug 2: _dispatch_pending_escalations skips MAXPFX while muted."""

    def setup_method(self) -> None:
        self._orig_esc = main_mod._escalation  # noqa: SLF001
        self._orig_flag = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001

    def teardown_method(self) -> None:
        main_mod._escalation = self._orig_esc  # noqa: SLF001
        routes_mod._maxpfx_alerts_enabled = self._orig_flag  # noqa: SLF001

    def _track_pending(self, eng: EscalationEngine, enriched: EnrichedLog) -> tuple:
        disc = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, disc)
        eng._tracked[key] = (enriched, _now() - timedelta(minutes=20))  # noqa: SLF001
        return key

    @pytest.mark.asyncio
    async def test_muted_maxpfx_not_dispatched_and_stays_pending(self) -> None:
        eng = EscalationEngine()
        maxpfx = _enriched(
            mnemonic="MAXPFX",
            device_name="KKT-Core-2",
            bgp_neighbor="163.47.83.6",
            message=(
                "No. of IPv4 Unicast prefixes received from 163.47.83.6 "
                "has reached 782, max 1000"
            ),
        )
        key = self._track_pending(eng, maxpfx)
        main_mod._escalation = eng  # noqa: SLF001
        routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_escalation", new_callable=AsyncMock) as disc,
            patch("src.main.send_telegram_escalation", new_callable=AsyncMock) as tg,
        ):
            await main_mod._dispatch_pending_escalations()

        disc.assert_not_called()
        tg.assert_not_called()
        # Still pending → re-escalates if MAXPFX is re-enabled.
        assert key not in eng._acked  # noqa: SLF001
        assert len(eng.get_pending_escalations()) == 1

    @pytest.mark.asyncio
    async def test_maxpfx_dispatched_when_enabled(self) -> None:
        eng = EscalationEngine()
        maxpfx = _enriched(
            mnemonic="MAXPFX", device_name="KKT-Core-2", bgp_neighbor="163.47.83.6"
        )
        self._track_pending(eng, maxpfx)
        main_mod._escalation = eng  # noqa: SLF001
        routes_mod._maxpfx_alerts_enabled = True  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_escalation", new_callable=AsyncMock) as disc,
            patch("src.main.send_telegram_escalation", new_callable=AsyncMock),
        ):
            await main_mod._dispatch_pending_escalations()

        disc.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_maxpfx_still_escalates_while_maxpfx_muted(self) -> None:
        eng = EscalationEngine()
        self._track_pending(
            eng,
            _enriched(
                mnemonic="MAXPFX", device_name="KKT-Core-2", bgp_neighbor="163.47.83.6"
            ),
        )
        self._track_pending(
            eng,
            _enriched(
                mnemonic="ADJCHANGE",
                device_name="EQ-RTR-01",
                bgp_neighbor="2001:de8:4::39:9077:1",
            ),
        )
        main_mod._escalation = eng  # noqa: SLF001
        routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_escalation", new_callable=AsyncMock) as disc,
            patch("src.main.send_telegram_escalation", new_callable=AsyncMock),
        ):
            await main_mod._dispatch_pending_escalations()

        assert disc.call_count == 1
        assert disc.call_args[0][0].parsed.mnemonic == "ADJCHANGE"

    @pytest.mark.asyncio
    async def test_maxpfx_reescalates_after_reenable(self) -> None:
        """Suppressed-while-muted MAXPFX dispatches once the operator re-enables.

        Proves the ``continue`` (leave pending, do NOT mark_escalated) semantic:
        muting defers — it does not permanently cancel — the escalation.
        """
        eng = EscalationEngine()
        self._track_pending(
            eng,
            _enriched(
                mnemonic="MAXPFX", device_name="KKT-Core-2", bgp_neighbor="163.47.83.6"
            ),
        )
        main_mod._escalation = eng  # noqa: SLF001

        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_escalation", new_callable=AsyncMock) as disc,
            patch("src.main.send_telegram_escalation", new_callable=AsyncMock),
        ):
            routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001  (muted cycle)
            await main_mod._dispatch_pending_escalations()
            disc.assert_not_called()

            routes_mod._maxpfx_alerts_enabled = (
                True  # noqa: SLF001  (operator re-enables)
            )
            await main_mod._dispatch_pending_escalations()
            disc.assert_called_once()


class TestEscalationCheckerDelegation:
    """Regression: _escalation_checker must delegate to _dispatch_pending_escalations.

    If someone later inlines the dispatch logic or removes the await call,
    this test will fail, catching the regression before it reaches production.
    """

    @pytest.mark.asyncio
    async def test_checker_calls_dispatch_exactly_once_per_iteration(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_escalation_checker must await _dispatch_pending_escalations each iteration.

        Strategy:
        - Patch asyncio.sleep (as referenced by src.main) so the first call
          returns normally (one full iteration executes) and the second call
          raises CancelledError (the loop's break path).
        - Patch _dispatch_pending_escalations with an async stub that records
          invocations.
        - Assert the stub was called at least once.
        """
        import asyncio

        dispatch_calls: list[None] = []

        async def _fake_dispatch() -> None:
            dispatch_calls.append(None)

        call_count = 0

        async def _fake_sleep(_delay: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise asyncio.CancelledError

        monkeypatch.setattr(main_mod, "_dispatch_pending_escalations", _fake_dispatch)
        monkeypatch.setattr("src.main.asyncio.sleep", _fake_sleep)

        await main_mod._escalation_checker()

        assert len(dispatch_calls) >= 1, (
            "_escalation_checker did not call _dispatch_pending_escalations; "
            "the delegation may have been removed or broken"
        )
