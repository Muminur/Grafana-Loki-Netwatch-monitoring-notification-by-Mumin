"""Notification deduplication engine for BSCCL NetWatch.

Implements three distinct suppression strategies:
  1. Sliding-window dedup — same (device + mnemonic + interface/neighbor)
     within ``window_seconds`` (default 300 s / 5 min) → suppress.
  2. BGP flap detection — Down→Up→Down within ``flap_window`` (default
     120 s / 2 min) → mark the second Down as "flapping".
  3. Bundle-member grouping — multiple bundle-member events for the same
     Bundle-Ether parent within ``bundle_window`` (default 30 s) → suppress
     all but the first.

Time-basis semantics
--------------------
All three strategies use **event timestamps** (``EnrichedLog.parsed.timestamp``)
as their primary time source so that replayed / historical logs are handled
deterministically based on when the events *happened*, not when they arrived.

For the standard sliding-window dedup only, a wall-clock monotonic floor is
also tracked and the elapsed time is computed as::

    max(event_ts_delta_seconds, monotonic_delta_seconds)

This ``max`` rule guarantees four safety properties simultaneously:

1. **Replayed / historical logs** — two events whose *event* timestamps are
   more than ``window_seconds`` apart will always be seen as outside the
   window (``event_ts_delta > window``), even if they arrive within
   milliseconds of each other on the wall clock.  This prevents the window
   from being "stuck open" for storms of historical replayed messages.

2. **Same-timestamp events** (e.g. identical ``ParsedLog`` objects submitted
   twice in a test) — because ``event_ts_delta == 0``, the monotonic clock
   component provides the real-time elapsed measurement, so a 1-second window
   correctly expires after 1 real second.  The real-time dedup smoke-test
   (``test_duplicate_after_window_allowed``) depends on this property.

3. **NTP backward clock step** — if the system wall-clock steps backward the
   monotonic clock never decreases, so ``monotonic_delta`` stays positive and
   the window cannot be artificially re-opened.  Likewise, if event timestamps
   step backward (NTP on the source device), the previous higher event-ts
   delta means the new delta is smaller (or negative); the monotonic floor
   prevents incorrect suppression.

4. **Normal real-time path** — for live syslog streams both measures advance
   together so no behaviour change is visible relative to the previous
   implementation.

BGP flap detection and bundle-member grouping use *only* event timestamps
(no monotonic component) because:
  - They are designed to be deterministic across log replays.
  - Their windows (120 s flap, 30 s bundle) are short enough that the
    difference between event-time and wall-time is operationally irrelevant
    for production live streams.
  - The existing tests for these two strategies exercise them with explicit
    event-timestamp sequences and must remain green.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)


def _is_bgp_down(enriched: EnrichedLog) -> bool:
    return enriched.rule_id in ("BGP_DOWN", "BGP_MAXPFX") or (
        "down" in enriched.parsed.message.lower()
        and enriched.parsed.mnemonic == "ADJCHANGE"
    )


def _is_bgp_up(enriched: EnrichedLog) -> bool:
    return enriched.rule_id == "BGP_UP" or (
        " up" in enriched.parsed.message.lower()
        and enriched.parsed.mnemonic == "ADJCHANGE"
        and not _is_bgp_down(enriched)
    )


class DedupEngine:
    """Sliding-window deduplication for notification suppression.

    All three suppression strategies are implemented here:
      - Standard window dedup (5-min)
      - BGP flap detection (2-min)
      - Bundle-member grouping (30-s)

    Parameters
    ----------
    window_seconds:
        How long (seconds) to suppress repeated identical events.
    flap_window:
        Time window (seconds) within which Down→Up→Down is considered a flap.
    bundle_window:
        Time window (seconds) within which multiple bundle-member events for
        the same parent are grouped.
    """

    # Run a full eviction sweep every _EVICT_INTERVAL calls to should_notify().
    _EVICT_INTERVAL: int = 100

    def __init__(
        self,
        window_seconds: int = 300,
        flap_window: int = 120,
        bundle_window: int = 30,
    ) -> None:
        self._window_s: float = float(window_seconds)
        self._flap_window = timedelta(seconds=flap_window)
        self._bundle_window = timedelta(seconds=bundle_window)

        # key → last_seen event timestamp
        self._seen: dict[str, datetime] = {}

        # key → last_seen wall-clock monotonic time (monotonic floor for
        # the max-elapsed rule; never decreases, safe across NTP steps)
        self._seen_mono: dict[str, float] = {}

        # BGP flap state: bgp_key → list of (state, datetime) tuples
        # state is "down" or "up"
        self._bgp_states: dict[str, list[tuple[str, datetime]]] = {}

        # Bundle grouping: bundle_key → first_seen event timestamp
        self._bundle_seen: dict[str, datetime] = {}

        # Counter for periodic eviction of stale entries.
        self._call_count: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def should_notify(self, enriched: EnrichedLog) -> tuple[bool, str]:
        """Check whether a notification should be sent for *enriched*.

        Returns
        -------
        tuple[bool, str]
            ``(should_send, reason)`` where *reason* is one of:

            - ``"new"`` — first occurrence or window expired
            - ``"suppressed_duplicate"`` — same key within dedup window
            - ``"flapping"`` — BGP Down→Up→Down within flap window
            - ``"bundle_grouped"`` — bundle-member event within group window
        """
        event_ts = enriched.parsed.timestamp

        # Periodic eviction: prune stale entries every _EVICT_INTERVAL calls.
        self._call_count += 1
        if self._call_count >= self._EVICT_INTERVAL:
            self._evict_stale(event_ts)
            self._call_count = 0

        # 1. Bundle grouping check (before general dedup)
        # Uses event timestamps exclusively — deterministic for log replays.
        if enriched.bundle_parent:
            bundle_key = self._bundle_key(enriched)
            last_bundle = self._bundle_seen.get(bundle_key)
            elapsed = event_ts - last_bundle if last_bundle is not None else None
            if elapsed is not None and elapsed <= self._bundle_window:
                _log.debug("Bundle-grouped: %s", bundle_key)
                return False, "bundle_grouped"
            self._bundle_seen[bundle_key] = event_ts

        # 2. BGP flap detection — run the flap state machine for all BGP
        #    ADJCHANGE events.  If a confirmed flap is detected, return it.
        #    For BGP events that are a *state change* (Down→Up or Up→Down),
        #    bypass standard dedup so that each direction is forwarded.
        #    For repeated events in the *same* direction (Down→Down, Up→Up),
        #    fall through to standard dedup so duplicates are suppressed.
        if enriched.bgp_neighbor and enriched.parsed.mnemonic == "ADJCHANGE":
            flap_result, is_state_change = self._check_flap_with_direction(
                enriched, event_ts
            )
            if flap_result is not None:
                return flap_result
            if is_state_change:
                # Direction changed (e.g. Down→Up) — always forward as new.
                # Record both event-ts and monotonic so subsequent same-direction
                # events are correctly suppressed by standard dedup.
                key = self._dedup_key(enriched)
                self._seen[key] = event_ts
                self._seen_mono[key] = time.monotonic()
                return True, "new"
            # Same direction repeated — fall through to standard dedup

        # 3. Standard window dedup (non-BGP events and repeated BGP same-state)
        #
        # Elapsed time = max(event_ts_delta_s, monotonic_delta_s).
        # See module docstring for the four safety properties this satisfies.
        key = self._dedup_key(enriched)
        now_mono = time.monotonic()
        last_event_ts = self._seen.get(key)
        last_mono = self._seen_mono.get(key)

        if last_event_ts is not None and last_mono is not None:
            # Event-timestamp elapsed (may be negative if device clock stepped back)
            event_ts_elapsed = (event_ts - last_event_ts).total_seconds()
            # Monotonic elapsed (always non-negative)
            mono_elapsed = now_mono - last_mono
            # Use the larger of the two: whichever dimension shows more time
            # has passed determines whether the window has expired.
            elapsed_s = max(event_ts_elapsed, mono_elapsed)
            if elapsed_s <= self._window_s:
                _log.debug("Suppressed duplicate: %s", key)
                return False, "suppressed_duplicate"

        self._seen[key] = event_ts
        self._seen_mono[key] = now_mono
        return True, "new"

    def _dedup_key(self, enriched: EnrichedLog) -> str:
        """Generate a dedup key: ``device:mnemonic:interface_or_neighbor``."""
        discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
        return f"{enriched.device_name}:{enriched.parsed.mnemonic}:{discriminator}"

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _evict_stale(self, now_event_ts: datetime) -> None:
        """Remove entries older than ``2 * window`` from all tracking dicts.

        Called periodically (every ``_EVICT_INTERVAL`` calls) to prevent
        unbounded memory growth in long-running processes.
        """
        # Standard dedup: prune _seen / _seen_mono
        dedup_cutoff = now_event_ts - timedelta(seconds=2 * self._window_s)
        mono_now = time.monotonic()
        mono_cutoff = 2 * self._window_s

        stale_keys = [
            k
            for k, ts in self._seen.items()
            if ts < dedup_cutoff
            and (mono_now - self._seen_mono.get(k, 0.0)) > mono_cutoff
        ]
        for k in stale_keys:
            del self._seen[k]
            self._seen_mono.pop(k, None)

        # Bundle grouping: prune _bundle_seen
        bundle_cutoff = now_event_ts - (2 * self._bundle_window)
        stale_bundles = [k for k, ts in self._bundle_seen.items() if ts < bundle_cutoff]
        for k in stale_bundles:
            del self._bundle_seen[k]

        # BGP flap state: prune _bgp_states (remove empty histories)
        flap_cutoff = now_event_ts - (2 * self._flap_window)
        stale_bgp = []
        for k, history in self._bgp_states.items():
            history[:] = [(s, t) for s, t in history if t >= flap_cutoff]
            if not history:
                stale_bgp.append(k)
        for k in stale_bgp:
            del self._bgp_states[k]

        evicted = len(stale_keys) + len(stale_bundles) + len(stale_bgp)
        if evicted > 0:
            _log.debug("Evicted %d stale entries from dedup dicts", evicted)

    def _bundle_key(self, enriched: EnrichedLog) -> str:
        """Key for bundle-grouping: ``device:bundle_parent``."""
        return f"{enriched.device_name}:{enriched.bundle_parent}"

    def _bgp_key(self, enriched: EnrichedLog) -> str:
        """Key for BGP flap tracking: ``device:neighbor``."""
        return f"{enriched.device_name}:{enriched.bgp_neighbor}"

    def _check_flap_with_direction(
        self, enriched: EnrichedLog, event_ts: datetime
    ) -> tuple[tuple[bool, str] | None, bool]:
        """Detect BGP flapping and report whether this event changes state.

        Returns
        -------
        tuple[tuple[bool, str] | None, bool]
            - First element: ``(True, 'flapping')`` if a flap is detected,
              ``None`` otherwise.
            - Second element: ``True`` if this event is a *state change*
              (direction differs from last recorded state for this neighbor),
              ``False`` if same direction as the last event (repeat).
        """
        bgp_key = self._bgp_key(enriched)

        if _is_bgp_down(enriched):
            state = "down"
        elif _is_bgp_up(enriched):
            state = "up"
        else:
            return None, False

        history = self._bgp_states.setdefault(bgp_key, [])

        # Prune history entries outside the flap_window (using event timestamps)
        cutoff = event_ts - self._flap_window
        history[:] = [(s, t) for s, t in history if t >= cutoff]

        # Determine if this is a state change vs. repeat in same direction
        is_state_change = not history or history[-1][0] != state

        # Check for Down→Up→Down pattern (flap)
        if (
            state == "down"
            and len(history) >= 2
            and history[-1][0] == "up"
            and history[-2][0] == "down"
        ):
            history.append((state, event_ts))
            _log.debug("BGP flap detected on %s", bgp_key)
            return (True, "flapping"), True

        history.append((state, event_ts))
        return None, is_state_change
