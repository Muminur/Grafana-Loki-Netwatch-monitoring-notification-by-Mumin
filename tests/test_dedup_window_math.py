"""Tests for DedupEngine window-math hardening.

Covers four specific edge-case scenarios that the original test suite does not
exercise:

  (a) Replayed / historical log whose event timestamp is far behind wall clock.
  (b) Clock stepping backward between two events (simulated via event-ts).
  (c) Exact window boundary: just inside vs. just outside.
  (d) Normal real-time path is unchanged (regression guard).

These tests confirm that the ``max(event_ts_delta, monotonic_delta)`` rule
in DedupEngine.should_notify behaves correctly under all four conditions
documented in the module docstring.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.core.dedup import DedupEngine
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog

_UTC6 = timezone(timedelta(hours=6))

# A fixed "wall-clock" reference that represents "now" for the test suite.
# Using a fixed value means these tests are hermetic and deterministic.
_WALL_REF = datetime(2026, 5, 24, 12, 0, 0, tzinfo=_UTC6)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_parsed(
    *,
    mnemonic: str = "UPDOWN",
    message: str = "Interface TenGigE0/0/0/0, changed state to Down",
    timestamp: datetime | None = None,
    source_ip: str = "192.168.203.1",
) -> ParsedLog:
    ts = timestamp if timestamp is not None else _WALL_REF
    raw = (
        f"May 24 12:00:00 {source_ip} 1: HOST "
        f"RP/0/RP0/CPU0:May 24 12:00:00.000 +06: ifmgr[123]: "
        f"%PKT_INFRA-LINK-3-{mnemonic} : {message}"
    )
    return ParsedLog(
        timestamp=ts,
        source_ip=source_ip,
        hostname="HOST",
        rp_location="RP/0/RP0/CPU0",
        facility="PKT_INFRA",
        subfacility="LINK",
        severity_level=3,
        mnemonic=mnemonic,
        message=message,
        raw=raw,
    )


def _make_enriched(
    *,
    device_name: str = "Test-RTR-1",
    interface_name: str = "TenGigE0/0/0/0",
    mnemonic: str = "UPDOWN",
    message: str = "Interface TenGigE0/0/0/0, changed state to Down",
    timestamp: datetime | None = None,
    bgp_neighbor: str = "",
    bundle_parent: str = "",
) -> EnrichedLog:
    parsed = _make_parsed(
        mnemonic=mnemonic,
        message=message,
        timestamp=timestamp,
    )
    return EnrichedLog(
        parsed=parsed,
        classification="CRITICAL",
        rule_id="LINK_DOWN",
        event_type="Interface Down",
        notify=True,
        device_name=device_name,
        device_location="Dhaka",
        interface_name=interface_name,
        interface_description="Upstream link",
        bundle_parent=bundle_parent,
        client_name="",
        bgp_neighbor=bgp_neighbor,
        as_number=0,
        as_name="",
        vrf="",
    )


# ─────────────────────────────────────────────────────────────────────────────
# (a) Replayed / historical log — event ts far behind wall clock
# ─────────────────────────────────────────────────────────────────────────────


class TestReplayedHistoricalLogs:
    """Edge case (a): event timestamps far behind the wall clock.

    Scenario: two log entries with the same device+mnemonic+interface arrive
    within milliseconds of wall-clock time, but their *event* timestamps are
    more than window_seconds apart.  The engine should treat the second event
    as "new" because the events genuinely occurred at different times.
    """

    def test_replayed_logs_outside_event_window_allowed(self) -> None:
        """Two replayed events with event-ts > window apart → second is 'new'."""
        engine = DedupEngine(window_seconds=300)

        # Both events arrive near-simultaneously (wall-clock), but their
        # event timestamps are 600 s apart (> 300 s window).
        ts_old = _WALL_REF - timedelta(hours=6)  # historical, 6 h ago
        ts_newer = ts_old + timedelta(seconds=600)  # still historical, +600s

        first = _make_enriched(timestamp=ts_old)
        second = _make_enriched(timestamp=ts_newer)

        # Freeze monotonic so wall-clock does NOT advance between calls.
        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.return_value = mono_start
            r1_allowed, r1_reason = engine.should_notify(first)
            # Still same monotonic — wall clock has not advanced
            r2_allowed, r2_reason = engine.should_notify(second)

        assert r1_allowed is True, "first replayed event should be allowed"
        assert r1_reason == "new"
        assert r2_allowed is True, (
            "second replayed event with event-ts 600 s later should be 'new' "
            "because event_ts_delta (600s) > window (300s)"
        )
        assert r2_reason == "new"

    def test_replayed_logs_inside_event_window_suppressed(self) -> None:
        """Two replayed events with event-ts < window apart → second is suppressed."""
        engine = DedupEngine(window_seconds=300)

        ts_old = _WALL_REF - timedelta(hours=6)
        # Only 60 s apart in event time — well inside the 300 s window
        ts_close = ts_old + timedelta(seconds=60)

        first = _make_enriched(timestamp=ts_old)
        second = _make_enriched(timestamp=ts_close)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.return_value = mono_start
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_replay_storm_all_same_event_ts_suppressed(self) -> None:
        """Identical-ts burst: only first event allowed, all duplicates suppressed."""
        engine = DedupEngine(window_seconds=300)

        ts = _WALL_REF - timedelta(hours=3)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.return_value = mono_start
            results = []
            for _ in range(5):
                ev = _make_enriched(timestamp=ts)
                results.append(engine.should_notify(ev))

        allowed_results = [r[0] for r in results]
        reasons = [r[1] for r in results]
        assert allowed_results[0] is True
        assert reasons[0] == "new"
        # All subsequent identical-ts events must be suppressed
        for i in range(1, 5):
            assert allowed_results[i] is False, f"event {i} should be suppressed"
            assert reasons[i] == "suppressed_duplicate"


# ─────────────────────────────────────────────────────────────────────────────
# (b) Clock stepping backward (simulated via event timestamps)
# ─────────────────────────────────────────────────────────────────────────────


class TestBackwardClockStep:
    """Edge case (b): device clock steps backward (NTP correction on the source).

    When a device's NTP clock steps backward, subsequent syslog timestamps
    will appear *earlier* than those already seen.  The engine must NOT
    re-open the suppression window purely because the event timestamp
    moved backward.
    """

    def test_event_ts_backward_step_suppressed(self) -> None:
        """Event with backward event-ts (NTP correction) within window → suppressed."""
        engine = DedupEngine(window_seconds=300)

        ts_before = _WALL_REF
        # Simulate a 30-second NTP backward step on the source device
        ts_after_correction = ts_before - timedelta(seconds=30)

        first = _make_enriched(timestamp=ts_before)
        second = _make_enriched(timestamp=ts_after_correction)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            # Advance monotonic by 2 s (real-time passes, but NOT past window)
            mock_time.monotonic.side_effect = [mono_start, mono_start + 2.0]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        # event_ts_delta = -30 s (backward), mono_delta = 2 s
        # max(-30, 2) = 2 s  < 300 s window → must be suppressed
        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_event_ts_backward_step_but_mono_expired(self) -> None:
        """Backward event-ts but wall-clock elapsed > window → allowed."""
        engine = DedupEngine(window_seconds=5)

        ts_before = _WALL_REF
        # Simulate a 1-second NTP backward step
        ts_after_correction = ts_before - timedelta(seconds=1)

        first = _make_enriched(timestamp=ts_before)
        second = _make_enriched(timestamp=ts_after_correction)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            # Wall clock advances past the 5 s window
            mock_time.monotonic.side_effect = [mono_start, mono_start + 6.0]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        # event_ts_delta = -1 s (backward), mono_delta = 6 s
        # max(-1, 6) = 6 s  > 5 s window → must be allowed
        assert r2_allowed is True
        assert r2_reason == "new"

    def test_ntp_step_forward_large_jump_allowed(self) -> None:
        """Large forward event-ts NTP jump → window expired by event-ts delta."""
        engine = DedupEngine(window_seconds=300)

        ts_before = _WALL_REF
        # NTP step forward by 1 hour (rare but possible on misconfigured device)
        ts_after_step = ts_before + timedelta(hours=1)

        first = _make_enriched(timestamp=ts_before)
        second = _make_enriched(timestamp=ts_after_step)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            # Wall clock barely advances (events arrive close together)
            mock_time.monotonic.side_effect = [mono_start, mono_start + 0.1]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        # event_ts_delta = 3600 s >> 300 s window → allowed
        assert r2_allowed is True
        assert r2_reason == "new"


# ─────────────────────────────────────────────────────────────────────────────
# (c) Exact window boundary
# ─────────────────────────────────────────────────────────────────────────────


class TestExactWindowBoundary:
    """Edge case (c): events at exactly the window boundary.

    Tests "just inside" (should suppress) and "just outside" (should allow).
    The boundary is INCLUSIVE: elapsed == window → still suppressed.
    Elapsed > window → allowed.
    """

    def test_just_inside_boundary_suppressed(self) -> None:
        """elapsed == window_seconds → suppressed (boundary is inclusive)."""
        window = 300
        engine = DedupEngine(window_seconds=window)

        ts_first = _WALL_REF
        # Exactly at the boundary: delta == window
        ts_second = ts_first + timedelta(seconds=window)

        first = _make_enriched(timestamp=ts_first)
        second = _make_enriched(timestamp=ts_second)

        # Controllable monotonic clock via a lambda so the result is independent
        # of how many times should_notify() calls time.monotonic() internally
        # (a fixed side_effect list is fragile to per-path call-count differences).
        clock = {"t": 1000.0}
        with patch("src.core.dedup.time.monotonic", side_effect=lambda: clock["t"]):
            engine.should_notify(first)
            clock["t"] = 1000.0 + float(window)  # advance exactly one window
            r2_allowed, r2_reason = engine.should_notify(second)

        # max(300, 300) = 300 <= 300 → suppressed
        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_one_second_past_boundary_allowed(self) -> None:
        """elapsed == window_seconds + 1 → allowed (window expired)."""
        window = 300
        engine = DedupEngine(window_seconds=window)

        ts_first = _WALL_REF
        # One second past the boundary
        ts_second = ts_first + timedelta(seconds=window + 1)

        first = _make_enriched(timestamp=ts_first)
        second = _make_enriched(timestamp=ts_second)

        clock = {"t": 1000.0}
        with patch("src.core.dedup.time.monotonic", side_effect=lambda: clock["t"]):
            engine.should_notify(first)
            clock["t"] = 1000.0 + float(window + 1)  # one second past the window
            r2_allowed, r2_reason = engine.should_notify(second)

        # max(301, 301) = 301 > 300 → allowed
        assert r2_allowed is True
        assert r2_reason == "new"

    def test_one_millisecond_inside_boundary_suppressed(self) -> None:
        """elapsed == window - 1ms → suppressed (just inside)."""
        window = 300
        engine = DedupEngine(window_seconds=window)

        ts_first = _WALL_REF
        ts_second = ts_first + timedelta(milliseconds=window * 1000 - 1)

        first = _make_enriched(timestamp=ts_first)
        second = _make_enriched(timestamp=ts_second)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            delta = float(window) - 0.001
            mock_time.monotonic.side_effect = [mono_start, mono_start + delta]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_first_event_always_new(self) -> None:
        """First occurrence of any key → always (True, 'new')."""
        engine = DedupEngine(window_seconds=300)
        ev = _make_enriched(timestamp=_WALL_REF)
        allowed, reason = engine.should_notify(ev)
        assert allowed is True
        assert reason == "new"


# ─────────────────────────────────────────────────────────────────────────────
# (d) Normal real-time path unchanged
# ─────────────────────────────────────────────────────────────────────────────


class TestNormalRealtimePath:
    """Edge case (d): verify the normal real-time path is unaffected.

    These are regression tests ensuring that the max(event_ts_delta,
    monotonic_delta) rule produces identical results to the old monotonic-only
    rule when event timestamps and wall clock advance at the same rate.
    """

    def test_realtime_duplicate_suppressed(self) -> None:
        """Identical event submitted twice instantly → second suppressed."""
        engine = DedupEngine(window_seconds=300)
        ev = _make_enriched(timestamp=_WALL_REF)

        r1_allowed, _ = engine.should_notify(ev)
        assert r1_allowed is True

        r2_allowed, r2_reason = engine.should_notify(ev)
        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_realtime_different_keys_independent(self) -> None:
        """Different device+mnemonic+interface keys are independent."""
        engine = DedupEngine(window_seconds=300)

        ev_a = _make_enriched(interface_name="TenGigE0/0/0/0", timestamp=_WALL_REF)
        ev_b = _make_enriched(interface_name="TenGigE0/0/0/1", timestamp=_WALL_REF)

        engine.should_notify(ev_a)
        r_b_allowed, r_b_reason = engine.should_notify(ev_b)

        assert r_b_allowed is True
        assert r_b_reason == "new"

    def test_realtime_event_ts_advances_normally(self) -> None:
        """Events separated by > window in both event-ts and wall-clock → 'new'."""
        engine = DedupEngine(window_seconds=5)

        ts_first = _WALL_REF
        # Both advance by 6 s (> 5 s window)
        ts_second = ts_first + timedelta(seconds=6)

        first = _make_enriched(timestamp=ts_first)
        second = _make_enriched(timestamp=ts_second)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.side_effect = [mono_start, mono_start + 6.0]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        assert r2_allowed is True
        assert r2_reason == "new"

    def test_realtime_event_ts_and_mono_both_inside_window_suppressed(self) -> None:
        """Both event-ts and wall-clock inside window → suppressed."""
        engine = DedupEngine(window_seconds=300)

        ts_first = _WALL_REF
        ts_second = ts_first + timedelta(seconds=30)  # 30 s < 300 s window

        first = _make_enriched(timestamp=ts_first)
        second = _make_enriched(timestamp=ts_second)

        mono_start = time.monotonic()
        with patch("src.core.dedup.time") as mock_time:
            mock_time.monotonic.side_effect = [mono_start, mono_start + 30.0]
            engine.should_notify(first)
            r2_allowed, r2_reason = engine.should_notify(second)

        assert r2_allowed is False
        assert r2_reason == "suppressed_duplicate"

    def test_bgp_flap_normal_path_unchanged(self) -> None:
        """BGP Down→Up→Down within flap_window still detected as flapping."""
        engine = DedupEngine(flap_window=120)

        ts = _WALL_REF

        def _bgp_parsed(msg: str, offset_s: int) -> ParsedLog:
            return ParsedLog(
                timestamp=ts + timedelta(seconds=offset_s),
                source_ip="192.168.203.1",
                hostname="HOST",
                rp_location="RP/0/RP0/CPU0",
                facility="ROUTING",
                subfacility="BGP",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message=msg,
                raw="",
            )

        neighbor = "10.0.0.1"

        def _bgp_ev(msg: str, offset_s: int, rule_id: str) -> EnrichedLog:
            return EnrichedLog(
                parsed=_bgp_parsed(msg, offset_s),
                classification="CRITICAL",
                rule_id=rule_id,
                event_type="BGP",
                notify=True,
                device_name="Test-RTR-1",
                device_location="Dhaka",
                interface_name="",
                interface_description="",
                bundle_parent="",
                client_name="",
                bgp_neighbor=neighbor,
                as_number=0,
                as_name="",
                vrf="",
            )

        down1 = _bgp_ev(f"neighbor {neighbor} Down - closed", 0, "BGP_DOWN")
        up1 = _bgp_ev(f"neighbor {neighbor} Up", 30, "BGP_UP")
        down2 = _bgp_ev(f"neighbor {neighbor} Down - closed", 60, "BGP_DOWN")

        r1_allowed, _ = engine.should_notify(down1)
        r2_allowed, _ = engine.should_notify(up1)
        r3_allowed, r3_reason = engine.should_notify(down2)

        assert r1_allowed is True
        assert r2_allowed is True
        assert r3_allowed is True
        assert r3_reason == "flapping"

    def test_bundle_grouping_normal_path_unchanged(self) -> None:
        """Bundle-member events within group window → all after first suppressed."""
        engine = DedupEngine(bundle_window=30)

        ts = _WALL_REF

        def _bundle_ev(iface: str, offset_s: int) -> EnrichedLog:
            parsed = _make_parsed(
                mnemonic="ACTIVE",
                message=f"{iface} is no longer Active as part of Bundle-Ether10",
                timestamp=ts + timedelta(seconds=offset_s),
            )
            return EnrichedLog(
                parsed=parsed,
                classification="WARNING",
                rule_id="LACP_EXPIRED",
                event_type="LACP Expired",
                notify=True,
                device_name="Test-RTR-1",
                device_location="Dhaka",
                interface_name=iface,
                interface_description="",
                bundle_parent="Bundle-Ether10",
                client_name="",
                bgp_neighbor="",
                as_number=0,
                as_name="",
                vrf="",
            )

        e1 = _bundle_ev("TenGigE0/0/1/0", 0)
        e2 = _bundle_ev("TenGigE0/0/1/1", 5)
        e3 = _bundle_ev("TenGigE0/0/1/2", 10)

        r1_allowed, _ = engine.should_notify(e1)
        r2_allowed, r2_reason = engine.should_notify(e2)
        r3_allowed, r3_reason = engine.should_notify(e3)

        assert r1_allowed is True
        assert r2_allowed is False
        assert r2_reason == "bundle_grouped"
        assert r3_allowed is False
        assert r3_reason == "bundle_grouped"
