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

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

from src.data.topology import get_downstream_devices, is_backhaul_member

_log = logging.getLogger(__name__)

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
    max_incidents:
        Upper bound on the number of incidents held in memory.  When a new
        incident would exceed this limit the oldest incident (by creation
        order) is evicted and a warning is logged.  Defaults to ``10_000``.
    """

    CORRELATION_WINDOW: int = 60  # seconds — backhaul / mass-event window
    FLAP_THRESHOLD: int = 3  # min state changes to declare flapping
    FLAP_WINDOW: int = 300  # seconds — flap detection window
    MASS_BGP_THRESHOLD: int = 5  # min BGP peer downs to declare a mass event

    def __init__(self, max_incidents: int = 10_000) -> None:
        self._max_incidents = max_incidents

        # Recent events: list of (timestamp, EnrichedLog)
        self._recent: list[tuple[datetime, EnrichedLog]] = []

        # Incident registry: incident_id → list[EnrichedLog]
        self._incidents: dict[str, list[EnrichedLog]] = {}

        # Process-monotonic sequence counter.  Incremented on every call to
        # _generate_incident_id and never reset during the lifetime of this engine
        # instance.  It is used to derive a per-day display counter that remains
        # strictly increasing even across a UTC-midnight rollover, so IDs generated
        # just before midnight (e.g. INC-20260523-003) are never reissued as the
        # first ID of the next day (INC-20260524-001 would collide if the counter
        # had reset to 1).  The per-day counter is computed as
        #   ``_incident_seq - _seq_day_offset``
        # where ``_seq_day_offset`` is the value of ``_incident_seq`` at the
        # start of the current calendar day and is updated whenever the UTC date
        # advances.  This guarantees:
        #   • The formatted NNN part stays ≤ 999 for any realistic incident rate
        #     (network incidents per day are orders of magnitude below that limit).
        #   • The sequence never repeats within a single engine-instance lifetime.
        self._incident_seq: int = 0  # global monotonic counter, never reset
        self._seq_day_offset: int = 0  # value of _incident_seq at start of current day
        self._seq_current_date: str = ""  # UTC date for which offset was last set

        # Active incidents per device: device_ip → list of incident_ids
        # (a device can host multiple overlapping incidents, e.g. a backhaul
        # failure AND a mass BGP event at the same time)
        self._device_incidents: dict[str, list[str]] = defaultdict(list)

        # Set of incident IDs that are backhaul-type (as opposed to
        # mass-event-type).  Used by _find_mass_incident to distinguish
        # the two kinds without relying on key-format heuristics.
        self._backhaul_incident_ids: set[str] = set()

        # Active backhaul failures: (device_ip, bundle_name) → timestamp
        self._backhaul_failures: dict[tuple[str, str], datetime] = {}

        # Flap tracking: (device_ip, neighbor_or_interface) → list of timestamps
        self._flap_history: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed_sequence(self, max_seq_for_today: int) -> None:
        """Seed the incident-ID sequence to avoid restart collisions.

        Call once at startup after querying the maximum incident sequence
        number already stored in the database for the current UTC day.
        This ensures that the first new incident ID generated after a
        restart is always higher than any existing ID in the DB, closing
        the same-day collision gap.

        The method is a no-op when *max_seq_for_today* is 0 or negative,
        and it never *decreases* the current sequence (safe to call even
        when the in-memory counter is already ahead of the DB).

        Parameters
        ----------
        max_seq_for_today:
            The highest per-day sequence number (the NNN part of an
            ``INC-YYYYMMDD-NNN`` id) already present in the DB for the
            current UTC date.  Pass 0 when the DB is empty or has no
            entries for today.

        Examples
        --------
        >>> engine = CorrelationEngine()
        >>> engine.seed_sequence(5)   # DB has INC-20260524-001..005
        >>> engine._generate_incident_id()
        'INC-20260524-006'
        """
        if max_seq_for_today <= 0:
            return
        today = datetime.now(tz=UTC).strftime("%Y%m%d")
        # Initialise the day offset if we haven't generated any IDs yet
        if today != self._seq_current_date:
            self._seq_day_offset = self._incident_seq
            self._seq_current_date = today
        # Only advance — never go backward
        desired_global = self._seq_day_offset + max_seq_for_today
        if desired_global > self._incident_seq:
            self._incident_seq = desired_global

    def resolve_incident(self, incident_id: str) -> str | None:
        """Remove a resolved incident from the in-memory registries.

        Deletes the incident from ``_incidents`` and removes matching entries
        from ``_device_incidents`` lists.

        Parameters
        ----------
        incident_id:
            The ``INC-YYYYMMDD-NNN`` identifier of the incident to resolve.

        Returns
        -------
        str | None
            The *incident_id* if it was found and removed, ``None`` if the
            incident was not in the registry (already resolved or expired).
        """
        if incident_id not in self._incidents:
            _log.debug("resolve_incident: %s not in registry", incident_id)
            return None

        del self._incidents[incident_id]
        self._backhaul_incident_ids.discard(incident_id)

        # Remove this incident ID from all device lists
        for key in list(self._device_incidents.keys()):
            self._device_incidents[key] = [
                iid for iid in self._device_incidents[key] if iid != incident_id
            ]
            if not self._device_incidents[key]:
                del self._device_incidents[key]

        _log.info("Incident %s resolved and removed from registry", incident_id)
        return incident_id

    def correlate(self, enriched: EnrichedLog) -> CorrelatedEvent:
        """Correlate *enriched* against recent events.

        Steps:
        1. Purge stale entries from all sliding windows.
        2. Purge incidents older than 24 hours from the incident registry.
        3. Check flapping for same device + key.
        4. Check if a backhaul member is down → register backhaul failure.
        5. Check if a BGP/interface event is downstream of a known backhaul failure.
        6. Check for mass BGP event.
        7. If none of the above → INDEPENDENT.

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
        self._purge_stale_incidents(now)

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
        backhaul_root_cause = False
        bundle_name = ""
        if enriched.interface_name and enriched.bundle_parent:
            is_member, bundle_name = is_backhaul_member(
                device_ip, enriched.interface_name
            )
            if is_member and enriched.classification in ("CRITICAL", "WARNING"):
                # Register or clear the backhaul failure
                bh_key = (device_ip, bundle_name)
                if "Down" in enriched.event_type or "Fault" in enriched.event_type:
                    is_new_failure = bh_key not in self._backhaul_failures
                    self._backhaul_failures[bh_key] = now
                    if is_new_failure:
                        backhaul_root_cause = True
                elif "Up" in enriched.event_type or "Clear" in enriched.event_type:
                    self._backhaul_failures.pop(bh_key, None)
        # ── Mass BGP event detection (runs before symptom return) ──────────
        # Mass-event detection runs early so that a device can host both a
        # backhaul incident AND a mass BGP incident simultaneously. ────────────────────────────────────────
        mass_events = self._check_mass_event(enriched)
        mass_incident_result: CorrelatedEvent | None = None
        if len(mass_events) >= self.MASS_BGP_THRESHOLD - 1:
            # We have reached the threshold (current event + prior events).
            # Look for an existing *mass-event* incident on this device.
            existing_mass_id = self._find_mass_incident(device_ip)
            if existing_mass_id is None:
                # Open a new mass-event incident
                self._enforce_incident_cap()
                new_id = self._generate_incident_id()
                self._incidents[new_id] = mass_events + [enriched]
                self._device_incidents[device_ip].append(new_id)
                mass_incident_result = CorrelatedEvent(
                    enriched=enriched,
                    is_root_cause=True,
                    incident_id=new_id,
                    flap_count=flap_count,
                    is_flapping=flap_count >= self.FLAP_THRESHOLD,
                    related_events=list(mass_events),
                )
            else:
                # Add to existing incident, suppress notification.
                # Guard against stale reference after eviction.
                if existing_mass_id in self._incidents:
                    self._incidents[existing_mass_id].append(enriched)
                mass_incident_result = CorrelatedEvent(
                    enriched=enriched,
                    is_symptom=True,
                    incident_id=existing_mass_id,
                    flap_count=flap_count,
                    is_flapping=flap_count >= self.FLAP_THRESHOLD,
                    suppress_notification=True,
                    related_events=list(
                        self._incidents.get(existing_mass_id, [])
                    ),
                )

        if incident_id is not None:
            # This event is downstream of a backhaul failure.
            # If a mass-event incident was ALSO created by this event,
            # return the mass-event result (it carries more context).
            if mass_incident_result is not None:
                if incident_id in self._incidents:
                    self._incidents[incident_id].append(enriched)
                return mass_incident_result
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

        # ── Backhaul root-cause event (first member failure opens incident) ─
        if backhaul_root_cause:
            bh_inc_key = f"{device_ip}:{bundle_name}"
            self._enforce_incident_cap()
            new_id = self._generate_incident_id()
            self._incidents[new_id] = [enriched]
            self._backhaul_incident_ids.add(new_id)
            self._device_incidents[bh_inc_key].append(new_id)
            self._device_incidents[device_ip].append(new_id)
            return CorrelatedEvent(
                enriched=enriched,
                is_root_cause=True,
                incident_id=new_id,
                flap_count=flap_count,
                is_flapping=flap_count >= self.FLAP_THRESHOLD,
            )

        # ── Mass BGP event result (no backhaul symptom overlay) ────────────
        if mass_incident_result is not None:
            return mass_incident_result

        # Check if a mass-event incident already exists (threshold crossed)
        existing_mass_id = self._find_mass_incident(device_ip)
        if existing_mass_id is not None:
            if existing_mass_id in self._incidents:
                self._incidents[existing_mass_id].append(enriched)
            return CorrelatedEvent(
                enriched=enriched,
                is_symptom=True,
                incident_id=existing_mass_id,
                flap_count=flap_count,
                is_flapping=flap_count >= self.FLAP_THRESHOLD,
                suppress_notification=True,
                related_events=list(
                    self._incidents.get(existing_mass_id, [])
                ),
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

    def _enforce_incident_cap(self) -> None:
        """Evict the oldest incident if the cache has reached *max_incidents*.

        The oldest incident is determined by insertion order (Python 3.7+ dicts
        preserve insertion order).  A warning is logged on every eviction so
        operators can tune the cap or purge interval if it fires frequently.
        """
        while len(self._incidents) >= self._max_incidents:
            oldest_id = next(iter(self._incidents))
            _log.warning(
                "Incident cache full (%d), evicting oldest incident %s",
                self._max_incidents,
                oldest_id,
            )
            del self._incidents[oldest_id]
            self._backhaul_incident_ids.discard(oldest_id)
            # Clean up reverse-map entries pointing to the evicted incident
            for key in list(self._device_incidents.keys()):
                self._device_incidents[key] = [
                    iid for iid in self._device_incidents[key] if iid != oldest_id
                ]
                if not self._device_incidents[key]:
                    del self._device_incidents[key]

    def _generate_incident_id(self) -> str:
        """Generate a unique incident ID in INC-YYYYMMDD-NNN format.

        Uses a process-monotonic global counter (``_incident_seq``) paired with
        a per-day offset (``_seq_day_offset``) to produce a three-digit display
        counter that restarts at 001 each UTC calendar day while remaining
        strictly increasing within the current day across any midnight rollover.

        Concretely:

        * ``_incident_seq`` is **never reset** — it increases by one on every
          call for the lifetime of this engine instance.
        * ``_seq_day_offset`` records the value of ``_incident_seq`` at the
          beginning of each new UTC calendar day.  When the UTC date advances,
          the offset is updated so the next day's first ID is always ``001``.
        * The three-digit component is ``_incident_seq - _seq_day_offset``,
          ensuring that:

          - No two IDs within the same process run share both a date **and** a
            sequence number (uniqueness guarantee for the process lifetime).
          - The formatted ``NNN`` part stays within three digits for any
            realistic NOC incident rate (thousands per day would be required to
            overflow — and such a scenario would indicate a far graver issue).

        Returns
        -------
        str
            Incident ID string matching ``INC-YYYYMMDD-NNN``.
        """
        today = datetime.now(tz=UTC).strftime("%Y%m%d")
        # Detect UTC date advance and update the per-day offset
        if today != self._seq_current_date:
            self._seq_day_offset = self._incident_seq
            self._seq_current_date = today
        self._incident_seq += 1
        day_seq = self._incident_seq - self._seq_day_offset
        return f"INC-{today}-{day_seq:03d}"

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
                existing_ids = self._device_incidents.get(bh_incident_key)
                if not existing_ids:
                    self._enforce_incident_cap()
                    inc_id = self._generate_incident_id()
                    self._incidents[inc_id] = []
                    self._backhaul_incident_ids.add(inc_id)
                    self._device_incidents[bh_incident_key].append(inc_id)
                    self._device_incidents[bh_device].append(inc_id)
                    return inc_id
                return existing_ids[-1]

        return None

    def _find_mass_incident(self, device_ip: str) -> str | None:
        """Find an existing mass-event incident for *device_ip*.

        Returns the most recently added non-backhaul incident ID,
        or ``None`` if none exists.
        """
        device_ids = self._device_incidents.get(device_ip)
        if not device_ids:
            return None

        # Return the most recent non-backhaul incident (mass-event incident)
        # using the explicit _backhaul_incident_ids set.
        for iid in reversed(device_ids):
            if iid not in self._backhaul_incident_ids and iid in self._incidents:
                return iid
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

    def _purge_stale_incidents(self, now: datetime) -> None:
        """Remove incidents older than 24 hours from the in-memory registry.

        Incidents that have been open for more than 24 hours without new activity
        are unlikely to receive new correlated events and would cause unbounded
        memory growth if never evicted.  This method removes such incidents from
        ``_incidents`` and clears the matching entries in ``_device_incidents``.

        Parameters
        ----------
        now:
            Current event timestamp used as the reference point.
        """
        cutoff = now - timedelta(hours=24)

        stale_ids: set[str] = set()
        for inc_id, events in list(self._incidents.items()):
            if not events:
                stale_ids.add(inc_id)
                continue
            # Use the timestamp of the most-recent correlated event as the
            # last-activity marker for the incident.
            last_ts = max(
                (ev.parsed.timestamp for ev in events),
                default=datetime.min.replace(tzinfo=UTC),
            )
            if last_ts < cutoff:
                stale_ids.add(inc_id)

        for inc_id in stale_ids:
            del self._incidents[inc_id]
            self._backhaul_incident_ids.discard(inc_id)

        # Remove reverse-map entries that pointed to purged incidents
        for key in list(self._device_incidents.keys()):
            self._device_incidents[key] = [
                iid for iid in self._device_incidents[key] if iid not in stale_ids
            ]
            if not self._device_incidents[key]:
                del self._device_incidents[key]
