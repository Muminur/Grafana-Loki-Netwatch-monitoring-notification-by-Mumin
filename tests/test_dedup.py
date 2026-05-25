"""Tests for DedupEngine and EscalationEngine.

Written first (TDD RED phase) — implementation does not exist yet.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog

_UTC6 = timezone(timedelta(hours=6))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_parsed_log(
    *,
    source_ip: str = "192.168.203.1",
    hostname: str = "BSCCL-EQ-RTR-01",
    mnemonic: str = "ADJCHANGE",
    message: str = "neighbor 2001:de8:4::39:9077:1 Down",
    facility: str = "ROUTING",
    subfacility: str = "BGP",
    severity_level: int = 5,
    rp_location: str = "RP/0/RP0/CPU0",
    timestamp: datetime | None = None,
    raw: str = "",
) -> ParsedLog:
    ts = timestamp or datetime(2026, 5, 22, 21, 12, 21, tzinfo=_UTC6)
    raw_line = raw or (
        f"May 22 21:12:21 {source_ip} 9238766: {hostname} "
        f"{rp_location}:May 22 21:12:21.651 +06: bgp[1097]: "
        f"%{facility}-{subfacility}-{severity_level}-{mnemonic} : {message}"
    )
    return ParsedLog(
        timestamp=ts,
        source_ip=source_ip,
        hostname=hostname,
        rp_location=rp_location,
        facility=facility,
        subfacility=subfacility,
        severity_level=severity_level,
        mnemonic=mnemonic,
        message=message,
        raw=raw_line,
    )


def _make_enriched(
    *,
    classification: str = "CRITICAL",
    rule_id: str = "bgp_down",
    event_type: str = "BGP Session Down",
    notify: bool = True,
    device_name: str = "Equinix-RTR-1",
    device_location: str = "Singapore Equinix",
    interface_name: str = "",
    interface_description: str = "",
    bundle_parent: str = "",
    client_name: str = "",
    bgp_neighbor: str = "2001:de8:4::39:9077:1",
    as_number: int = 399077,
    as_name: str = "TCLOUD",
    vrf: str = "network",
    parsed: ParsedLog | None = None,
) -> EnrichedLog:
    if parsed is None:
        parsed = _make_parsed_log()
    return EnrichedLog(
        parsed=parsed,
        classification=classification,
        rule_id=rule_id,
        event_type=event_type,
        notify=notify,
        device_name=device_name,
        device_location=device_location,
        interface_name=interface_name,
        interface_description=interface_description,
        bundle_parent=bundle_parent,
        client_name=client_name,
        bgp_neighbor=bgp_neighbor,
        as_number=as_number,
        as_name=as_name,
        vrf=vrf,
    )


# ─────────────────────────────────────────────────────────────────────────────
# DedupEngine tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDedupEngine:
    """Tests for src.core.dedup.DedupEngine."""

    def test_first_event_allowed(self) -> None:
        """A completely new event should return (True, 'new')."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine()
        enriched = _make_enriched()
        allowed, reason = engine.should_notify(enriched)
        assert allowed is True
        assert reason == "new"

    def test_duplicate_within_window_suppressed(self) -> None:
        """Identical (device + mnemonic + neighbor) within 5 min → suppressed."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine(window_seconds=300)
        enriched = _make_enriched()

        first_allowed, _ = engine.should_notify(enriched)
        assert first_allowed is True

        # Same event again immediately (same direction — should be suppressed)
        second_allowed, second_reason = engine.should_notify(enriched)
        assert second_allowed is False
        assert second_reason == "suppressed_duplicate"

    def test_duplicate_after_window_allowed(self) -> None:
        """Same event after window expires → allowed again with reason 'new'."""
        from unittest.mock import patch

        from src.core.dedup import DedupEngine

        engine = DedupEngine(window_seconds=10)
        enriched = _make_enriched()

        # Use a controllable monotonic clock so the test is deterministic and
        # does not require real wall-clock delays (eliminates CI flakiness).
        clock = {"t": 1000.0}
        with patch("src.core.dedup.time.monotonic", side_effect=lambda: clock["t"]):
            engine.should_notify(enriched)  # prime

            # Advance the monotonic clock past the 10-second window
            clock["t"] = 1011.0

            allowed, reason = engine.should_notify(enriched)

        assert allowed is True
        assert reason == "new"

    def test_different_interface_not_suppressed(self) -> None:
        """Same device+mnemonic but different interface → not suppressed."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine()

        parsed_a = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
        )
        enriched_a = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            parsed=parsed_a,
        )

        parsed_b = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/1, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
        )
        enriched_b = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/1",
            parsed=parsed_b,
        )

        engine.should_notify(enriched_a)  # prime with first interface

        allowed, reason = engine.should_notify(enriched_b)
        assert allowed is True
        assert reason == "new"

    def test_bgp_flap_detection(self) -> None:
        """Down→Up→Down within flap_window → third event marked 'flapping'."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine(flap_window=120)

        ts_base = datetime(2026, 5, 22, 21, 0, 0, tzinfo=_UTC6)

        # Down at t=0
        parsed_down1 = _make_parsed_log(
            mnemonic="ADJCHANGE",
            message=("neighbor 2001:de8:4::39:9077:1 Down - BGP Notification received"),
            timestamp=ts_base,
        )
        down1 = _make_enriched(
            rule_id="bgp_down",
            event_type="BGP Session Down",
            bgp_neighbor="2001:de8:4::39:9077:1",
            parsed=parsed_down1,
        )

        # Up at t=30s
        parsed_up = _make_parsed_log(
            mnemonic="ADJCHANGE",
            message="neighbor 2001:de8:4::39:9077:1 Up",
            timestamp=ts_base + timedelta(seconds=30),
        )
        up = _make_enriched(
            rule_id="bgp_up",
            event_type="BGP Session Up",
            classification="WARNING",
            bgp_neighbor="2001:de8:4::39:9077:1",
            parsed=parsed_up,
        )

        # Down again at t=60s
        parsed_down2 = _make_parsed_log(
            mnemonic="ADJCHANGE",
            message=("neighbor 2001:de8:4::39:9077:1 Down - BGP Notification received"),
            timestamp=ts_base + timedelta(seconds=60),
        )
        down2 = _make_enriched(
            rule_id="bgp_down",
            event_type="BGP Session Down",
            bgp_neighbor="2001:de8:4::39:9077:1",
            parsed=parsed_down2,
        )

        r1_allowed, _ = engine.should_notify(down1)
        assert r1_allowed is True

        r2_allowed, _ = engine.should_notify(up)
        assert r2_allowed is True

        r3_allowed, r3_reason = engine.should_notify(down2)
        assert r3_allowed is True
        assert r3_reason == "flapping"

    def test_separate_events_not_flap(self) -> None:
        """Down, then Up after flap_window expires → both allowed, no flap."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine(flap_window=5)  # 5-second flap window

        ts_base = datetime(2026, 5, 22, 21, 0, 0, tzinfo=_UTC6)

        # Down at t=0
        parsed_down = _make_parsed_log(
            mnemonic="ADJCHANGE",
            message="neighbor 10.0.0.1 Down - session closed",
            timestamp=ts_base,
        )
        down = _make_enriched(
            rule_id="bgp_down",
            bgp_neighbor="10.0.0.1",
            parsed=parsed_down,
        )

        # Up at t=300s (well outside 5s flap window)
        parsed_up = _make_parsed_log(
            mnemonic="ADJCHANGE",
            message="neighbor 10.0.0.1 Up",
            timestamp=ts_base + timedelta(seconds=300),
        )
        up = _make_enriched(
            rule_id="bgp_up",
            classification="WARNING",
            bgp_neighbor="10.0.0.1",
            parsed=parsed_up,
        )

        r1_allowed, _ = engine.should_notify(down)
        assert r1_allowed is True

        # Up is outside flap window — treated as separate event
        r2_allowed, r2_reason = engine.should_notify(up)
        assert r2_allowed is True
        assert r2_reason != "flapping"

    def test_bundle_member_grouping(self) -> None:
        """First bundle-member event allowed; subsequent within window suppressed."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine(bundle_window=30)

        ts_base = datetime(2026, 5, 22, 21, 0, 0, tzinfo=_UTC6)

        def make_bundle_event(iface: str, t_offset: int) -> EnrichedLog:
            parsed = _make_parsed_log(
                mnemonic="ACTIVE",
                message=(f"{iface} is no longer Active as part of Bundle-Ether201"),
                facility="L2",
                subfacility="BM",
                timestamp=ts_base + timedelta(seconds=t_offset),
            )
            return _make_enriched(
                rule_id="lacp_expired",
                event_type="LACP Expired",
                interface_name=iface,
                bundle_parent="Bundle-Ether201",
                bgp_neighbor="",
                as_number=0,
                as_name="",
                parsed=parsed,
            )

        # First bundle member event
        e1 = make_bundle_event("TenGigE0/0/1/7", 0)
        r1_allowed, _ = engine.should_notify(e1)
        assert r1_allowed is True

        # Second bundle member for same Bundle-Ether within 30s
        e2 = make_bundle_event("TenGigE0/0/1/8", 10)
        r2_allowed, r2_reason = engine.should_notify(e2)
        assert r2_allowed is False
        assert r2_reason == "bundle_grouped"

        # Third bundle member within 30s
        e3 = make_bundle_event("TenGigE0/0/1/9", 20)
        r3_allowed, r3_reason = engine.should_notify(e3)
        assert r3_allowed is False
        assert r3_reason == "bundle_grouped"

    def test_dedup_key_uses_device_mnemonic_neighbor(self) -> None:
        """DedupEngine._dedup_key includes device, mnemonic, and neighbor."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine()
        enriched = _make_enriched()
        key = engine._dedup_key(enriched)  # noqa: SLF001
        assert "Equinix-RTR-1" in key
        assert "ADJCHANGE" in key
        assert "2001:de8:4::39:9077:1" in key

    def test_dedup_key_uses_interface_when_no_neighbor(self) -> None:
        """DedupEngine._dedup_key uses interface_name when bgp_neighbor is empty."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine()
        enriched = _make_enriched(bgp_neighbor="", interface_name="TenGigE0/0/0/0")
        key = engine._dedup_key(enriched)  # noqa: SLF001
        assert "TenGigE0/0/0/0" in key


# ─────────────────────────────────────────────────────────────────────────────
# DedupEngine eviction tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDedupEviction:
    """Tests for periodic eviction of stale dedup dict entries."""

    def test_eviction_runs_after_interval(self) -> None:
        """Stale entries are pruned after _EVICT_INTERVAL calls."""
        from unittest.mock import patch as mock_patch

        from src.core.dedup import DedupEngine

        # Use a 10-second window so entries expire fast.
        engine = DedupEngine(window_seconds=10)

        ts_old = datetime(2026, 5, 22, 10, 0, 0, tzinfo=_UTC6)
        ts_new = datetime(2026, 5, 22, 11, 0, 0, tzinfo=_UTC6)  # 1 hour later

        # Seed the engine with an old event.
        old_parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts_old,
        )
        old_enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            parsed=old_parsed,
        )
        engine.should_notify(old_enriched)
        assert len(engine._seen) == 1  # noqa: SLF001

        # Set call count just below the eviction interval.
        engine._call_count = engine._EVICT_INTERVAL - 1  # noqa: SLF001

        # Next call triggers eviction; use a new event timestamp far in the
        # future so the old entry is stale (> 2 * window).
        new_parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/1, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts_new,
        )
        new_enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/1",
            parsed=new_parsed,
        )

        # Mock monotonic to ensure the monotonic cutoff is also exceeded.
        import time

        mono_now = time.monotonic()
        with mock_patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.return_value = mono_now + 1000.0
            engine.should_notify(new_enriched)

        # The old entry should have been evicted.
        old_key = engine._dedup_key(old_enriched)  # noqa: SLF001
        assert old_key not in engine._seen  # noqa: SLF001
        assert old_key not in engine._seen_mono  # noqa: SLF001

    def test_eviction_preserves_recent_entries(self) -> None:
        """Entries within the 2x window are not evicted."""
        from unittest.mock import patch as mock_patch

        from src.core.dedup import DedupEngine

        engine = DedupEngine(window_seconds=300)

        ts = datetime(2026, 5, 22, 21, 0, 0, tzinfo=_UTC6)
        parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts,
        )
        enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            parsed=parsed,
        )
        engine.should_notify(enriched)

        # Force eviction with a timestamp only 100s later (within 2*300s).
        engine._call_count = engine._EVICT_INTERVAL - 1  # noqa: SLF001
        ts_soon = ts + timedelta(seconds=100)
        parsed2 = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/1, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts_soon,
        )
        enriched2 = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/1",
            parsed=parsed2,
        )

        import time

        mono_now = time.monotonic()
        with mock_patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.return_value = mono_now + 100.0
            engine.should_notify(enriched2)

        # The original entry should still be present.
        key = engine._dedup_key(enriched)  # noqa: SLF001
        assert key in engine._seen  # noqa: SLF001


# ─────────────────────────────────────────────────────────────────────────────
# DedupEngine input validation tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDedupValidation:
    """Tests for DedupEngine constructor input validation."""

    def test_zero_window_seconds_raises(self) -> None:
        """window_seconds=0 must raise ValueError."""
        import pytest

        from src.core.dedup import DedupEngine

        with pytest.raises(ValueError, match="window_seconds must be positive"):
            DedupEngine(window_seconds=0)

    def test_negative_window_seconds_raises(self) -> None:
        """Negative window_seconds must raise ValueError."""
        import pytest

        from src.core.dedup import DedupEngine

        with pytest.raises(
            ValueError, match="window_seconds must be positive, got -10"
        ):
            DedupEngine(window_seconds=-10)

    def test_positive_window_seconds_accepted(self) -> None:
        """Positive window_seconds should work without error."""
        from src.core.dedup import DedupEngine

        engine = DedupEngine(window_seconds=1)
        assert engine._window_s == 1.0  # noqa: SLF001


# ─────────────────────────────────────────────────────────────────────────────
# DedupEngine eviction logging tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDedupEvictionLogging:
    """Tests that eviction logs purged entry counts at DEBUG level."""

    def test_eviction_logs_purge_count(self) -> None:
        """Eviction of stale entries logs the count at DEBUG level."""
        import logging
        from contextlib import contextmanager
        from unittest.mock import patch as mock_patch

        from src.core.dedup import DedupEngine

        @contextmanager
        def _capture(
            logger_name: str, level: int = logging.DEBUG
        ):  # type: ignore[misc]
            records: list[logging.LogRecord] = []
            handler = logging.Handler()
            handler.emit = lambda r: records.append(r)  # type: ignore[assignment]
            lgr = logging.getLogger(logger_name)
            lgr.addHandler(handler)
            old = lgr.level
            lgr.setLevel(level)
            try:
                yield records
            finally:
                lgr.removeHandler(handler)
                lgr.setLevel(old)

        engine = DedupEngine(window_seconds=10)

        ts_old = datetime(2026, 5, 22, 10, 0, 0, tzinfo=_UTC6)
        ts_new = datetime(2026, 5, 22, 11, 0, 0, tzinfo=_UTC6)

        # Seed with an old event
        old_parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts_old,
        )
        old_enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/0",
            parsed=old_parsed,
        )
        engine.should_notify(old_enriched)

        # Set call count to trigger eviction on next call
        engine._call_count = engine._EVICT_INTERVAL - 1  # noqa: SLF001

        new_parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/1, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
            timestamp=ts_new,
        )
        new_enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/1",
            parsed=new_parsed,
        )

        import time

        mono_now = time.monotonic()
        with (
            _capture("src.core.dedup", logging.DEBUG) as records,
            mock_patch("src.core.dedup.time") as mock_time,
        ):
            mock_time.monotonic.return_value = mono_now + 1000.0
            engine.should_notify(new_enriched)

        # Should have logged the eviction count
        evict_records = [r for r in records if "Evicted" in r.message]
        assert len(evict_records) >= 1
        assert "stale dedup entries" in evict_records[0].message


# ─────────────────────────────────────────────────────────────────────────────
# EscalationEngine tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEscalationEngine:
    """Tests for src.notifications.escalation.EscalationEngine."""

    def test_unacked_after_delay_escalates(self) -> None:
        """After escalation_delay passes, alert appears in pending escalations."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine(escalation_delay=900)
        enriched = _make_enriched()

        engine.track_alert(enriched)

        # Simulate time passage by backdating the tracked_at timestamp
        for key in list(engine._tracked):  # noqa: SLF001
            entry = engine._tracked[key]  # noqa: SLF001
            engine._tracked[key] = (  # noqa: SLF001
                entry[0],
                entry[1] - timedelta(seconds=950),
            )

        pending = engine.get_pending_escalations()
        assert len(pending) >= 1
        assert any(alert.device_name == "Equinix-RTR-1" for alert, _elapsed in pending)

    def test_acked_within_delay_cancels(self) -> None:
        """Acknowledging within escalation_delay → NOT in pending."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine(escalation_delay=900)
        enriched = _make_enriched()

        engine.track_alert(enriched)

        # Acknowledge immediately
        acked = engine.acknowledge(enriched.device_name, enriched.parsed.mnemonic)
        assert acked is True

        # Move time past delay
        for key in list(engine._tracked):  # noqa: SLF001
            entry = engine._tracked[key]  # noqa: SLF001
            engine._tracked[key] = (  # noqa: SLF001
                entry[0],
                entry[1] - timedelta(seconds=950),
            )

        pending = engine.get_pending_escalations()
        assert all(alert.device_name != "Equinix-RTR-1" for alert, _elapsed in pending)

    def test_track_non_critical_ignored(self) -> None:
        """Non-CRITICAL alerts are not tracked for escalation."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine(escalation_delay=900)
        enriched = _make_enriched(classification="WARNING")

        engine.track_alert(enriched)
        assert len(engine._tracked) == 0  # noqa: SLF001

    def test_acknowledge_unknown_returns_false(self) -> None:
        """Acknowledging an unknown alert returns False."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine(escalation_delay=900)
        result = engine.acknowledge("NonExistent-Device", "ADJCHANGE")
        assert result is False

    def test_multiple_devices_tracked_independently(self) -> None:
        """Multiple different device alerts are tracked independently."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine(escalation_delay=900)

        enriched_a = _make_enriched(device_name="Device-A")
        enriched_b = _make_enriched(device_name="Device-B")

        engine.track_alert(enriched_a)
        engine.track_alert(enriched_b)

        assert len(engine._tracked) == 2  # noqa: SLF001

        # Ack only device A
        engine.acknowledge("Device-A", "ADJCHANGE")

        # Move time past delay
        for key in list(engine._tracked):  # noqa: SLF001
            entry = engine._tracked[key]  # noqa: SLF001
            engine._tracked[key] = (  # noqa: SLF001
                entry[0],
                entry[1] - timedelta(seconds=950),
            )

        pending = engine.get_pending_escalations()
        device_names = [alert.device_name for alert, _elapsed in pending]
        assert "Device-A" not in device_names
        assert "Device-B" in device_names
