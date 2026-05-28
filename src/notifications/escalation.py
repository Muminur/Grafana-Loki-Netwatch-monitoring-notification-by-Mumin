"""Escalation engine for BSCCL NetWatch.

Tracks CRITICAL alerts that have not been acknowledged and surfaces them
as pending escalations after a configurable delay (default 15 minutes).

Only CRITICAL-classified events are tracked.  Non-critical events passed to
``track_alert`` are silently ignored.

In-flight escalation state (unresolved, unacknowledged CRITICAL alerts) is
reconstructed from the ``AlertLog`` database table on application startup via
:meth:`EscalationEngine.restore`, preserving the original escalation clock
across restarts.
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

    @property
    def escalation_delay_seconds(self) -> float:
        """Return the escalation delay in seconds."""
        return self._delay.total_seconds()

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

    def restore(
        self,
        enriched: EnrichedLog,
        tracked_at: datetime,
        acknowledged: bool,
    ) -> None:
        """Restore a previously tracked alert from persisted state.

        Repopulates ``_tracked`` (and optionally ``_acked``) exactly as
        ``track_alert`` would, but uses the supplied ``tracked_at`` timestamp
        so the original escalation clock is preserved across restarts.

        Non-CRITICAL alerts are silently ignored (same guard as
        ``track_alert``).

        Parameters
        ----------
        enriched:
            The fully enriched syslog event.
        tracked_at:
            The original wall-clock time at which the alert was first tracked.
            Preserving this value ensures that an alert tracked 14 minutes
            before a restart remains 14 minutes into its escalation window
            after the restart, rather than restarting the clock from zero.
        acknowledged:
            If ``True`` the key is added to ``_acked`` so the alert is not
            re-escalated.  If ``False`` the key is discarded from ``_acked``
            (same behaviour as a fresh ``track_alert`` call).
        """
        if enriched.classification != "CRITICAL":
            _log.debug(
                "restore: skipping non-CRITICAL event: %s/%s",
                enriched.device_name,
                enriched.parsed.mnemonic,
            )
            return

        discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, discriminator)
        self._tracked[key] = (enriched, tracked_at)
        if acknowledged:
            self._acked.add(key)
        else:
            self._acked.discard(key)
        _log.debug(
            "Restored escalation tracking: %s/%s (tracked_at=%s acknowledged=%s)",
            enriched.device_name,
            enriched.parsed.mnemonic,
            tracked_at.isoformat(),
            acknowledged,
        )

    def clear_incident(self, device_name: str) -> int:
        """Remove all tracked and acknowledged entries for *device_name*.

        Called when an incident for the device is resolved, so that stale
        escalation entries do not fire after the issue is already cleared.

        Parameters
        ----------
        device_name:
            The device name as stored in ``EnrichedLog.device_name``.

        Returns
        -------
        int
            The number of entries removed from ``_tracked``.
        """
        matching_keys = [k for k in self._tracked if k[0] == device_name]
        if not matching_keys:
            _log.debug("clear_incident: no tracked entries for %s", device_name)
            return 0

        for key in matching_keys:
            del self._tracked[key]
            self._acked.discard(key)
        _log.debug(
            "Cleared %d escalation entries for device %s",
            len(matching_keys),
            device_name,
        )
        return len(matching_keys)

    def get_pending_escalations(self) -> list[tuple[EnrichedLog, int]]:
        """Return alerts that need escalation (unacknowledged after delay).

        Returns
        -------
        list[tuple[EnrichedLog, int]]
            All tracked CRITICAL alerts whose ``tracked_at`` time is older
            than ``escalation_delay`` and have not been acknowledged.
            Each tuple contains (enriched_log, elapsed_minutes).
        """
        now = datetime.now(_UTC6)
        pending: list[tuple[EnrichedLog, int]] = []

        for key, (enriched, tracked_at) in self._tracked.items():
            if key in self._acked:
                continue
            elapsed = now - tracked_at
            if elapsed >= self._delay:
                elapsed_minutes = int(elapsed.total_seconds() / 60)
                pending.append((enriched, elapsed_minutes))
                _log.debug(
                    "Pending escalation: %s/%s (elapsed %.0fs)",
                    enriched.device_name,
                    enriched.parsed.mnemonic,
                    elapsed.total_seconds(),
                )

        return pending

    def mark_escalated(self, device_name: str, mnemonic: str) -> bool:
        """Mark an alert as escalated so it is not re-sent every check cycle.

        Adds the matching keys to ``_acked`` so they are excluded from future
        ``get_pending_escalations()`` calls.  This is distinct from
        ``acknowledge()``, which represents human acknowledgement — here we
        use the same underlying set to suppress repeat escalation dispatches.

        Parameters
        ----------
        device_name:
            The device name as stored in ``EnrichedLog.device_name``.
        mnemonic:
            The syslog mnemonic as stored in ``EnrichedLog.parsed.mnemonic``.

        Returns
        -------
        bool
            ``True`` if at least one matching tracked alert was found,
            ``False`` otherwise.
        """
        matching_keys = [
            k for k in self._tracked if k[0] == device_name and k[1] == mnemonic
        ]
        if not matching_keys:
            _log.debug(
                "mark_escalated: no tracked alert for %s/%s", device_name, mnemonic
            )
            return False

        for key in matching_keys:
            self._acked.add(key)
        _log.debug("Alert marked as escalated: %s/%s", device_name, mnemonic)
        return True
