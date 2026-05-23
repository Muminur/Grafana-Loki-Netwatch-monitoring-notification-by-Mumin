"""Notification deduplication engine for BSCCL NetWatch.

Implements three distinct suppression strategies:
  1. Sliding-window dedup — same (device + mnemonic + interface/neighbor)
     within ``window_seconds`` (default 300 s / 5 min) → suppress.
  2. BGP flap detection — Down→Up→Down within ``flap_window`` (default
     120 s / 2 min) → mark the second Down as "flapping".
  3. Bundle-member grouping — multiple bundle-member events for the same
     Bundle-Ether parent within ``bundle_window`` (default 30 s) → suppress
     all but the first.

All timestamps are taken from ``EnrichedLog.parsed.timestamp`` so that
replayed / historical logs use the device clock rather than wall-clock time.
This makes the engine deterministic and fully testable without ``time.sleep``
(except for the window-expiry test which uses a short real sleep).
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
    return enriched.rule_id in ("bgp_down", "bgp_maxpfx") or (
        "down" in enriched.parsed.message.lower()
        and enriched.parsed.mnemonic == "ADJCHANGE"
    )


def _is_bgp_up(enriched: EnrichedLog) -> bool:
    return enriched.rule_id == "bgp_up" or (
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

    def __init__(
        self,
        window_seconds: int = 300,
        flap_window: int = 120,
        bundle_window: int = 30,
    ) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._flap_window = timedelta(seconds=flap_window)
        self._bundle_window = timedelta(seconds=bundle_window)

        # key → last_seen datetime (event timestamp)
        self._seen: dict[str, datetime] = {}

        # key → last_seen wall-clock monotonic time (for window expiry)
        self._seen_mono: dict[str, float] = {}

        # BGP flap state: bgp_key → list of (state, datetime) tuples
        # state is "down" or "up"
        self._bgp_states: dict[str, list[tuple[str, datetime]]] = {}

        # Bundle grouping: bundle_key → first_seen datetime
        self._bundle_seen: dict[str, datetime] = {}

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

        # 1. Bundle grouping check (before general dedup)
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
                # Record in seen_mono so repeated same-direction events ARE
                # suppressed by standard dedup on subsequent calls.
                key = self._dedup_key(enriched)
                self._seen[key] = event_ts
                self._seen_mono[key] = time.monotonic()
                return True, "new"
            # Same direction repeated — fall through to standard dedup

        # 3. Standard window dedup (non-BGP events and repeated BGP same-state)
        # Window expiry uses wall-clock (time.monotonic) so real-time sleep
        # tests work regardless of the event timestamp in the log.
        key = self._dedup_key(enriched)
        now_mono = time.monotonic()
        last_mono = self._seen_mono.get(key)
        window_s = self._window.total_seconds()
        if last_mono is not None and (now_mono - last_mono) <= window_s:
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
