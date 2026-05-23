"""Escalation engine for BSCCL NetWatch.

Tracks CRITICAL alerts that have not been acknowledged and surfaces them
as pending escalations after a configurable delay (default 15 minutes).

Only CRITICAL-classified events are tracked.  Non-critical events passed to
``track_alert`` are silently ignored.

This is a purely in-memory implementation — escalation state is lost on
restart.  A database-backed implementation is planned for a later milestone.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)

_UTC6 = timezone(timedelta(hours=6))


class EscalationEngine:
    """Escalation pipeline for unacknowledged CRITICAL alerts.

    Parameters
    ----------
    escalation_delay:
        Seconds to wait before an unacknowledged CRITICAL alert is surfaced
        as a pending escalation.  Defaults to 900 (15 minutes).
    """

    def __init__(self, escalation_delay: int = 900) -> None:
        self._delay = timedelta(seconds=escalation_delay)

        # (device_name, mnemonic, discriminator) → (EnrichedLog, tracked_at datetime)
        self._tracked: dict[tuple[str, str, str], tuple[EnrichedLog, datetime]] = {}

        # Set of keys that have been acknowledged
        self._acked: set[tuple[str, str, str]] = set()

    # ── Public API ────────────────────────────────────────────────────────────

    def track_alert(self, enriched: EnrichedLog) -> None:
        """Track a CRITICAL alert for potential escalation.

        Non-CRITICAL alerts are silently ignored.

        Parameters
        ----------
        enriched:
            The fully enriched syslog event.
        """
        if enriched.classification != "CRITICAL":
            _log.debug(
                "Skipping escalation tracking for non-CRITICAL event: %s/%s",
                enriched.device_name,
                enriched.parsed.mnemonic,
            )
            return

        discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, discriminator)
        tracked_at = datetime.now(_UTC6)
        self._tracked[key] = (enriched, tracked_at)
        self._acked.discard(key)
        _log.debug(
            "Tracking CRITICAL alert for escalation: %s/%s",
            enriched.device_name,
            enriched.parsed.mnemonic,
        )

    def acknowledge(self, device_name: str, mnemonic: str) -> bool:
        """Acknowledge an alert, cancelling its escalation.

        Parameters
        ----------
        device_name:
            The device name as stored in ``EnrichedLog.device_name``.
        mnemonic:
            The syslog mnemonic as stored in ``EnrichedLog.parsed.mnemonic``.

        Returns
        -------
        bool
            ``True`` if the alert was found and acknowledged,
            ``False`` if no matching tracked alert was found.
        """
        # Match all tracked alerts for (device, mnemonic) regardless of discriminator.
        # The caller doesn't know the discriminator, so we acknowledge every match.
        matching_keys = [
            k for k in self._tracked if k[0] == device_name and k[1] == mnemonic
        ]
        if not matching_keys:
            _log.debug("Acknowledge: no tracked alert for %s/%s", device_name, mnemonic)
            return False

        for key in matching_keys:
            self._acked.add(key)
        _log.debug("Alert acknowledged: %s/%s", device_name, mnemonic)
        return True

    def get_pending_escalations(self) -> list[EnrichedLog]:
        """Return alerts that need escalation (unacknowledged after delay).

        Returns
        -------
        list[EnrichedLog]
            All tracked CRITICAL alerts whose ``tracked_at`` time is older
            than ``escalation_delay`` and have not been acknowledged.
        """
        now = datetime.now(_UTC6)
        pending: list[EnrichedLog] = []

        for key, (enriched, tracked_at) in self._tracked.items():
            if key in self._acked:
                continue
            elapsed = now - tracked_at
            if elapsed >= self._delay:
                pending.append(enriched)
                _log.debug(
                    "Pending escalation: %s/%s (elapsed %.0fs)",
                    enriched.device_name,
                    enriched.parsed.mnemonic,
                    elapsed.total_seconds(),
                )

        return pending
