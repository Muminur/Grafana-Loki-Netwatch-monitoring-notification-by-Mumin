"""Correlation engine for BSCCL NetWatch.

Takes an :class:`~src.core.enricher.EnrichedLog` and correlates it against
recent events to detect:

  - SYMPTOM: event is a downstream consequence of a known backhaul failure
  - FLAPPING: same device+neighbor/interface has ≥3 state changes in 5 min
  - MASS_EVENT: ≥5 BGP peers down on the same device within 60 s (mass outage)
  - INDEPENDENT: none of the above — standalone event

The engine is intentionally synchronous — it operates on an in-memory ring
buffer and requires no async I/O.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

from src.data.topology import get_downstream_devices, is_backhaul_member

if TYPE_CHECKING:
    from src.core.enricher import EnrichedLog

_UTC6 = timezone(timedelta(hours=6))


# ---------------------------------------------------------------------------
# CorrelatedEvent
# ---------------------------------------------------------------------------


@dataclass
class CorrelatedEvent:
    """A single syslog event annotated with correlation context.

    Attributes
    ----------
    enriched:
        The original :class:`~src.core.enricher.EnrichedLog`.
    is_symptom:
        True when the event is a downstream consequence of a known backhaul
        failure within the correlation window.
    is_independent:
        True when no correlation context applies.
    is_flapping:
        True when the same device+key has ≥ FLAP_THRESHOLD state changes
        within FLAP_WINDOW seconds.
    is_root_cause:
        True when this event opened a new incident (backhaul member down, or
        triggered a mass BGP event).
    incident_id:
        INC-YYYYMMDD-NNN identifier when this event is part of an incident.
    flap_count:
        Number of state changes observed within the flap window.
    suppress_notification:
        True when a notification should be suppressed (part of active incident
        and not the root cause).
    related_events:
        Other :class:`~src.core.enricher.EnrichedLog` entries that belong to
        the same incident.
    """

    enriched: EnrichedLog
    is_symptom: bool = False
    is_independent: bool = False
    is_flapping: bool = False
    is_root_cause: bool = False
    incident_id: str | None = None
    flap_count: int = 0
    suppress_notification: bool = False
    related_events: list[EnrichedLog] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------


class CorrelationEngine:
    """Stateful in-memory event correlation engine.

    Maintains a sliding window of recent events and produces a
    :class:`CorrelatedEvent` for each incoming :class:`~src.core.enricher.EnrichedLog`.

    All time windows are configurable via class attributes.

    Parameters
    ----------
    None — instantiate with defaults for normal use.
    """

    CORRELATION_WINDOW: int = 60  # seconds — backhaul / mass-event window
    FLAP_THRESHOLD: int = 3  # min state changes to declare flapping
    FLAP_WINDOW: int = 300  # seconds — flap detection window
    MASS_BGP_THRESHOLD: int = 5  # min BGP peer downs to declare a mass event

    def __init__(self) -> None:
        # Recent events: list of (timestamp, EnrichedLog)
        self._recent: list[tuple[datetime, EnrichedLog]] = []

        # Incident registry: incident_id → list[EnrichedLog]
        self._incidents: dict[str, list[EnrichedLog]] = {}

        # Incident counter (monotonically increasing per day, resets on date change)
        self._incident_counter: dict[str, int] = {}  # date_str → counter

        # Active incidents per device: device_ip → incident_id
        self._device_incident: dict[str, str] = {}

        # Active backhaul failures: (device_ip, bundle_name) → timestamp
        self._backhaul_failures: dict[tuple[str, str], datetime] = {}

        # Flap tracking: (device_ip, neighbor_or_interface) → list of timestamps
        self._flap_history: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, enriched: EnrichedLog) -> CorrelatedEvent:
        """Correlate *enriched* against recent events.

        Steps:
        1. Purge stale entries from all sliding windows.
        2. Check flapping for same device + key.
        3. Check if a backhaul member is down → register backhaul failure.
        4. Check if a BGP/interface event is downstream of a known backhaul failure.
        5. Check for mass BGP event.
        6. If none of the above → INDEPENDENT.

        Parameters
        ----------
        enriched:
            An :class:`~src.core.enricher.EnrichedLog` to correlate.

        Returns
        -------
        CorrelatedEvent
        """
        now = enriched.parsed.timestamp
        self._purge_stale(now)

        # Record this event in the recent list
        self._recent.append((now, enriched))

        device_ip = enriched.parsed.source_ip

        # ── Flap detection ─────────────────────────────────────────────────
        flap_count = self._check_flap(enriched)

        # ── Symptom check (backhaul already down BEFORE this event) ────────
        # Must run BEFORE we register any new backhaul failure from this event,
        # so that a member-down event is never treated as its own symptom.
        incident_id = self._find_root_cause(enriched)

        # ── Backhaul member event ───────────────────────────────────────────
        # If this is a physical member of a backhaul bundle going down/up,
        # register it so later events can be correlated against it.
        if enriched.interface_name and enriched.bundle_parent:
            is_member, bundle_name = is_backhaul_member(
                device_ip, enriched.interface_name
            )
            if is_member and enriched.classification in ("CRITICAL", "WARNING"):
                # Register or clear the backhaul failure
                bh_key = (device_ip, bundle_name)
                if "Down" in enriched.event_type or "Fault" in enriched.event_type:
                    self._backhaul_failures[bh_key] = now
                elif "Up" in enriched.event_type or "Clear" in enriched.event_type:
                    self._backhaul_failures.pop(bh_key, None)
        if incident_id is not None:
            # This event is downstream of a backhaul failure
            correlated = CorrelatedEvent(
                enriched=enriched,
                is_symptom=True,
                incident_id=incident_id,
                flap_count=flap_count,
                is_flapping=flap_count >= self.FLAP_THRESHOLD,
                suppress_notification=True,
                related_events=list(self._incidents.get(incident_id, [])),
            )
            if incident_id in self._incidents:
                self._incidents[incident_id].append(enriched)
            return correlated

        # ── Mass BGP event detection ────────────────────────────────────────
        mass_events = self._check_mass_event(enriched)
        if len(mass_events) >= self.MASS_BGP_THRESHOLD - 1:
            # We have reached the threshold (current event + prior events)
            existing_incident = self._device_incident.get(device_ip)
            if existing_incident is None:
                # Open a new mass-event incident
                new_id = self._generate_incident_id()
                self._incidents[new_id] = mass_events + [enriched]
                self._device_incident[device_ip] = new_id
                correlated = CorrelatedEvent(
                    enriched=enriched,
                    is_root_cause=True,
                    incident_id=new_id,
                    flap_count=flap_count,
                    is_flapping=flap_count >= self.FLAP_THRESHOLD,
                    related_events=list(mass_events),
                )
            else:
                # Add to existing incident, suppress notification
                self._incidents[existing_incident].append(enriched)
                correlated = CorrelatedEvent(
                    enriched=enriched,
                    is_symptom=True,
                    incident_id=existing_incident,
                    flap_count=flap_count,
                    is_flapping=flap_count >= self.FLAP_THRESHOLD,
                    suppress_notification=True,
                    related_events=list(self._incidents[existing_incident]),
                )
            return correlated

        # Check if a device incident already exists (threshold already crossed)
        existing_incident = self._device_incident.get(device_ip)
        if existing_incident is not None:
            self._incidents[existing_incident].append(enriched)
            return CorrelatedEvent(
                enriched=enriched,
                is_symptom=True,
                incident_id=existing_incident,
                flap_count=flap_count,
                is_flapping=flap_count >= self.FLAP_THRESHOLD,
                suppress_notification=True,
                related_events=list(self._incidents[existing_incident]),
            )

        # ── Flapping-only (no other correlation) ───────────────────────────
        if flap_count >= self.FLAP_THRESHOLD:
            return CorrelatedEvent(
                enriched=enriched,
                is_independent=False,
                is_flapping=True,
                flap_count=flap_count,
            )

        # ── Independent event ──────────────────────────────────────────────
        return CorrelatedEvent(
            enriched=enriched,
            is_independent=True,
            flap_count=flap_count,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_incident_id(self) -> str:
        """Generate a unique incident ID in INC-YYYYMMDD-NNN format.

        The counter resets at midnight; two calls in the same session with
        the same date produce INC-20260523-001, INC-20260523-002, etc.

        Returns
        -------
        str
            Incident ID string.
        """
        today = datetime.now(tz=UTC).strftime("%Y%m%d")
        count = self._incident_counter.get(today, 0) + 1
        self._incident_counter[today] = count
        return f"INC-{today}-{count:03d}"

    def _find_root_cause(self, enriched: EnrichedLog) -> str | None:
        """Check if *enriched* is downstream of a known backhaul failure.

        Checks two cases:
        1. Same-device: the event's device IP matches the device that has an
           active backhaul failure (e.g. a BGP peer failing on EQ-RTR-01 after
           a BE500 member went down on EQ-RTR-01).
        2. Cross-device: the event's device IP is a downstream device of any
           active backhaul failure (e.g. BGP peers failing on KKT-Core-01 after
           EQ-RTR-01's BE500 bundle degraded).

        Parameters
        ----------
        enriched:
            Event to check.

        Returns
        -------
        str | None
            The incident ID of the root cause if found, otherwise ``None``.
        """
        device_ip = enriched.parsed.source_ip
        now = enriched.parsed.timestamp

        for (bh_device, bundle_name), failure_ts in list(
            self._backhaul_failures.items()
        ):
            age = (now - failure_ts).total_seconds()
            if age > self.CORRELATION_WINDOW:
                continue

            # Case 1: same device as the backhaul failure
            same_device = bh_device == device_ip

            # Case 2: this event's device is downstream of the failing bundle
            downstream_ips = get_downstream_devices(bh_device, bundle_name)
            is_downstream = device_ip in downstream_ips

            if same_device or is_downstream:
                # Create or reuse an incident for this backhaul event
                bh_incident_key = f"{bh_device}:{bundle_name}"
                if bh_incident_key not in self._device_incident:
                    inc_id = self._generate_incident_id()
                    self._incidents[inc_id] = []
                    self._device_incident[bh_incident_key] = inc_id
                return self._device_incident[bh_incident_key]

        return None

    def _check_flap(self, enriched: EnrichedLog) -> int:
        """Count state changes for same device + key within FLAP_WINDOW seconds.

        Parameters
        ----------
        enriched:
            Event to check.

        Returns
        -------
        int
            Number of state changes (including this event) in the flap window.
        """
        now = enriched.parsed.timestamp
        key = self._flap_key(enriched)

        # Record this event
        self._flap_history[key].append(now)

        # Count events within the flap window
        cutoff = now - timedelta(seconds=self.FLAP_WINDOW)
        window_events = [ts for ts in self._flap_history[key] if ts >= cutoff]

        # Update the history to only keep events within the window
        self._flap_history[key] = window_events

        return len(window_events)

    def _check_mass_event(self, enriched: EnrichedLog) -> list[EnrichedLog]:
        """Find simultaneous BGP peer down events on the same device.

        Searches within CORRELATION_WINDOW seconds for other BGP peer down
        events on the same device (excluding *enriched* itself).

        Parameters
        ----------
        enriched:
            The current event.

        Returns
        -------
        list[EnrichedLog]
            Other BGP peer down events on the same device within the window
            (not including *enriched* itself).
        """
        device_ip = enriched.parsed.source_ip
        now = enriched.parsed.timestamp
        cutoff = now - timedelta(seconds=self.CORRELATION_WINDOW)

        return [
            ev
            for ts, ev in self._recent
            if (
                ev is not enriched
                and ev.parsed.source_ip == device_ip
                and ts >= cutoff
                and ev.event_type in ("BGP Peer Down", "BGP Down", "Max Prefix")
                and ev.classification in ("CRITICAL", "WARNING")
            )
        ]

    def _flap_key(self, enriched: EnrichedLog) -> tuple[str, str]:
        """Derive a stable key for flap tracking.

        Uses BGP neighbor IP if available, otherwise falls back to the
        interface name, then the mnemonic.

        Parameters
        ----------
        enriched:
            Event to derive the key for.

        Returns
        -------
        tuple[str, str]
            ``(device_ip, neighbor_or_interface_or_mnemonic)``
        """
        device_ip = enriched.parsed.source_ip
        if enriched.bgp_neighbor:
            return (device_ip, enriched.bgp_neighbor)
        if enriched.interface_name:
            return (device_ip, enriched.interface_name)
        return (device_ip, enriched.parsed.mnemonic)

    def _purge_stale(self, now: datetime) -> None:
        """Remove events older than the longest window from all sliding caches.

        Parameters
        ----------
        now:
            Current event timestamp to use as the reference point.
        """
        # The flap window is the longest (300 s); use it as the purge cutoff.
        cutoff = now - timedelta(seconds=self.FLAP_WINDOW)
        self._recent = [(ts, ev) for ts, ev in self._recent if ts >= cutoff]

        # Purge stale backhaul failures (older than correlation window)
        bh_cutoff = now - timedelta(seconds=self.CORRELATION_WINDOW)
        for key in list(self._backhaul_failures.keys()):
            if self._backhaul_failures[key] < bh_cutoff:
                del self._backhaul_failures[key]
