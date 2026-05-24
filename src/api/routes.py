"""REST API routes for BSCCL NetWatch.

Milestone 6: minimal health endpoint.
Milestone 7: expanded alert, incident, device, topology, stats, BGP endpoints.
Milestone 6/7 audit: monthly/yearly stats, maintenance window endpoints.
Milestone 8: DB-backed /api/alerts with period filter; /api/alerts/count.
"""

from __future__ import annotations

import re
import time
from collections import deque
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, cast

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, model_validator

from src.data.bgp_bundle_map import lookup_bundle_for_bgp_peer
from src.data.device_map import DEVICE_MAP
from src.data.topology import NETWORK_TOPOLOGY

router = APIRouter()

# Application start time (module-level; set when the module is first imported)
_APP_START: float = time.monotonic()

# Shared counters updated by the ingestion pipeline
_alerts_processed: int = 0
_active_connections: int = 0

# In-memory stores — capped to prevent unbounded memory growth
_alerts_store: deque[dict[str, Any]] = deque(maxlen=10000)
_incidents_store: list[dict[str, Any]] = []
_maintenance_store: list[dict[str, Any]] = []
_maintenance_id_counter: int = 0

# DB engine — set during lifespan startup via set_db_engine()
_db_engine: object = None


_RECOVERY_RULE_IDS = frozenset(
    {
        "BGP_UP",
        "INTF_UP",
        "LINEPROTO_UP",
        "LACP_ACTIVE",
        "SFP_ALARM_CLEAR",
        "BER_CLEAR",
    }
)

_RECOVERY_MNEMONICS_WITH_UP = frozenset(
    {
        "ADJCHANGE",
        "UPDOWN",
    }
)

_RECOVERY_MNEMONICS_ALWAYS = frozenset(
    {
        "ACTIVE",
    }
)

_SILENT_FAULT_MNEMONICS = frozenset({"RX_FAULT", "SIGNAL", "RFI"})

# Runtime toggle: treat hardware defects (RX_FAULT/SIGNAL/RFI) on backbone
# bundle members as NOISE rather than CRITICAL incidents. Default ON.
_hardware_defects_as_noise: bool = True


def _is_recovery_event(mnemonic: str, message: str, rule_id: str = "") -> bool:
    if rule_id and rule_id in _RECOVERY_RULE_IDS:
        return True
    if mnemonic in _RECOVERY_MNEMONICS_ALWAYS and "no longer" not in message:
        return True
    return mnemonic in _RECOVERY_MNEMONICS_WITH_UP and bool(
        re.search(r"\bUp\b", message)
    )


_IFACE_RE = re.compile(
    r"((?:TwentyFiveGigE|HundredGigE|FiftyGigE|FortyGigE|TenGigE|GigabitEthernet|GigE|Bundle-Ether)"
    r"[\d/.]+)"
)


def _extract_iface_from_msg(message: str) -> str:
    m = _IFACE_RE.search(message)
    return m.group(1) if m else ""


_IFACE_SHORT = [
    ("TenGigE", "TGE"),
    ("HundredGigE", "HGE"),
    ("FortyGigE", "FGE"),
    ("GigabitEthernet", "GE"),
    ("Bundle-Ether", "BE"),
]


def _shorten_iface(name: str) -> str:
    for long, short in _IFACE_SHORT:
        name = name.replace(long, short)
    return name


def _extract_bundle_from_msg(message: str) -> str:
    m = re.search(r"Bundle-Ether(\d+)", message)
    return f"BE{m.group(1)}" if m else ""


def _extract_bgp_state(message: str) -> str:
    if "Interface flap" in message or "Flap" in message:
        return "Flap"
    if re.search(r"\bDown\b", message):
        return "DOWN"
    if re.search(r"\bUp\b", message):
        return "UP"
    return ""


def _extract_fault_type(message: str) -> str:
    if "Local Fault" in message and "Remote Fault" in message:
        return "Local+Remote Fault"
    if "Local Fault" in message:
        return "Local Fault"
    if "Remote Fault" in message:
        return "Remote Fault"
    return "Fault"


def build_incident_title(
    mnemonic: str,
    device_name: str,
    message: str,
    interface_name: str = "",
    as_name: str = "",
) -> str:
    """Build a rich incident title from alert fields.

    Examples:
        Bundle ACTIVE — KKT-Core-2, TGE0/0/1/7, BE201
        ADJCHANGE — KKT-Core-3 DOWN - Orange
        RXFault-KKT-Core-1 - TGE0/0/0/2 - Local Fault
    """
    iface_short = _shorten_iface(interface_name) if interface_name else ""

    if mnemonic == "ACTIVE":
        bundle = _extract_bundle_from_msg(message)
        is_down = "no longer" in message
        label = "Bundle DOWN" if is_down else "Bundle ACTIVE"
        parts = [f"{label} — {device_name}"]
        if iface_short:
            parts.append(iface_short)
        if bundle:
            parts.append(bundle)
        return ", ".join(parts)

    if mnemonic == "ADJCHANGE":
        state = _extract_bgp_state(message)
        title = f"ADJCHANGE — {device_name}"
        if state:
            title += f" {state}"
        if as_name:
            title += f" - {as_name}"
        return title

    if mnemonic in ("RFI", "RX_FAULT"):
        fault = _extract_fault_type(message)
        title = f"RXFault-{device_name}"
        if iface_short:
            title += f" - {iface_short}"
        title += f" - {fault}"
        return title

    if mnemonic in ("UPDOWN", "LINEPROTO"):
        state = "Down" if "Down" in message else "Up" if "Up" in message else ""
        title = f"{mnemonic} — {device_name}"
        if state:
            title += f" {state}"
        if iface_short:
            title += f" - {iface_short}"
        return title

    parts = [f"{mnemonic} — {device_name}"]
    if iface_short:
        parts.append(iface_short)
    return ", ".join(parts)


def set_db_engine(engine: object) -> None:
    """Register the async DB engine for use by /api/alerts.

    Called from ``main.py`` lifespan after the engine is created.
    """
    global _db_engine  # noqa: PLW0603
    _db_engine = engine


def get_maintenance_store() -> list[dict[str, Any]]:
    """Return the in-memory maintenance window list (read-only access)."""
    return _maintenance_store


async def resolve_silent_faults_in_db(
    engine: object,
    device_name: str,
    bundle_members: set[str],
) -> int:
    """Mark silent-fault alerts as resolved in the database.

    Only resolves alerts from the last 24 hours to bound blast radius.
    Returns the number of rows updated.
    """
    from sqlalchemy import CursorResult, update  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=24)
    async with AsyncSession(engine) as session:  # type: ignore[arg-type]
        stmt = (
            update(AlertLog)
            .where(AlertLog.device_name == device_name)
            .where(AlertLog.mnemonic.in_(sorted(_SILENT_FAULT_MNEMONICS)))
            .where(AlertLog.interface_name.in_(sorted(bundle_members)))
            .where(AlertLog.resolved_at.is_(None))
            .where(AlertLog.timestamp >= cutoff)
            .values(resolved_at=now, resolution_reason="bgp_up_inferred")
        )
        result = cast("CursorResult[Any]", await session.execute(stmt))
        await session.commit()
        return result.rowcount


class MaintenanceWindowCreate(BaseModel):
    """Request body for creating a maintenance window."""

    device_name: str = Field(..., max_length=100)
    start_time: datetime
    end_time: datetime
    reason: str = Field(default="", max_length=1000)
    created_by: str = Field(default="", max_length=100)

    @model_validator(mode="after")
    def end_after_start(self) -> MaintenanceWindowCreate:
        """Validate that end_time is after start_time."""
        if self.end_time <= self.start_time:
            msg = "end_time must be after start_time"
            raise ValueError(msg)
        return self


def increment_alerts_processed() -> None:
    """Increment the global alert counter (called by the ingestion pipeline)."""
    global _alerts_processed  # noqa: PLW0603
    _alerts_processed += 1


def _set_alerts_processed(count: int) -> None:
    """Set the alert counter (restore from DB on startup)."""
    global _alerts_processed  # noqa: PLW0603
    _alerts_processed = count


def set_active_connections(count: int) -> None:
    """Update the WebSocket connection count (called by WebSocketManager)."""
    global _active_connections  # noqa: PLW0603
    _active_connections = count


def add_alert(alert: dict[str, Any]) -> None:
    """Append an alert to the in-memory store (called by the ingestion pipeline)."""
    _alerts_store.append(alert)


def add_alert_to_store(enriched: Any, correlated: Any) -> None:
    """Append a fully enriched + correlated alert to the in-memory store.

    Converts the EnrichedLog + CorrelatedEvent into the dict format expected
    by the REST API endpoints.

    Parameters
    ----------
    enriched:
        An ``EnrichedLog`` instance from the enricher.
    correlated:
        A ``CorrelatedEvent`` instance from the correlator.
    """
    alert: dict[str, Any] = {
        "id": len(_alerts_store) + 1,
        "timestamp": enriched.parsed.timestamp.isoformat(),
        "source_ip": enriched.parsed.source_ip,
        "device": enriched.device_name,
        "hostname": enriched.parsed.hostname,
        "facility": enriched.parsed.facility,
        "mnemonic": enriched.parsed.mnemonic,
        "message": enriched.parsed.message,
        "classification": enriched.classification,
        "event_type": enriched.event_type,
        "interface": enriched.interface_name,
        "interface_description": enriched.interface_description,
        "client": enriched.client_name,
        "neighbor": enriched.bgp_neighbor,
        "as_number": enriched.as_number,
        "as_name": enriched.as_name,
        "vrf": enriched.vrf,
        "incident_id": correlated.incident_id or "",
        "is_symptom": correlated.is_symptom,
        "suppress_notification": correlated.suppress_notification,
    }

    # Hardware-defects-as-noise: reclassify silent faults on backbone members
    if (
        _hardware_defects_as_noise
        and enriched.parsed.mnemonic in _SILENT_FAULT_MNEMONICS
    ):
        from src.data.topology import is_backhaul_member as _is_bh  # noqa: PLC0415

        _is_member, _ = _is_bh(enriched.parsed.source_ip, enriched.interface_name)
        if _is_member:
            alert["classification"] = "NOISE"

    _alerts_store.append(alert)

    # Track CRITICAL fault alerts as incidents (skip recovery events like Up/Active)
    is_recovery = _is_recovery_event(
        enriched.parsed.mnemonic,
        enriched.parsed.message,
        enriched.rule_id,
    )

    # When a recovery event arrives, resolve matching DOWN incidents
    if is_recovery:
        dev = enriched.device_name
        iface = enriched.interface_name or _extract_iface_from_msg(
            enriched.parsed.message
        )
        neighbor = enriched.bgp_neighbor
        as_num = enriched.as_number
        resolved = []
        for i, inc in enumerate(_incidents_store):
            if inc["device"] != dev:
                continue
            inc_iface = inc.get("interface") or _extract_iface_from_msg(
                inc.get("message", "")
            )
            if iface and inc_iface == iface:
                resolved.append(i)
            elif neighbor and as_num and inc.get("mnemonic") == "ADJCHANGE":
                inc_msg = inc.get("message", "")
                if str(as_num) in inc_msg or neighbor in inc_msg:
                    resolved.append(i)
        for idx in reversed(resolved):
            _incidents_store.pop(idx)

    # BGP-UP auto-resolution for silent hardware faults.
    # IOS-XR never sends clear messages for RX_FAULT/SIGNAL/RFI — but if a
    # BGP session comes UP on a backbone P2P bundle, the physical links work.
    # Guard: only BGP ADJCHANGE UP events trigger this, not other recovery types.
    if (
        is_recovery
        and enriched.parsed.mnemonic == "ADJCHANGE"
        and not getattr(correlated, "is_flapping", False)
    ):
        neighbor_ip = enriched.bgp_neighbor
        device_source_ip = enriched.parsed.source_ip
        bundle_name = lookup_bundle_for_bgp_peer(device_source_ip, neighbor_ip)
        if bundle_name:
            topo = NETWORK_TOPOLOGY.get(device_source_ip)
            if topo and bundle_name in topo.upstreams:
                members = set(topo.upstreams[bundle_name].members)
                dev = enriched.device_name
                bgp_resolved = []
                for i, inc in enumerate(_incidents_store):
                    if inc["device"] != dev:
                        continue
                    if inc.get("mnemonic") not in _SILENT_FAULT_MNEMONICS:
                        continue
                    inc_iface = inc.get("interface") or _extract_iface_from_msg(
                        inc.get("message", "")
                    )
                    if inc_iface in members:
                        bgp_resolved.append(i)
                for idx in reversed(bgp_resolved):
                    _incidents_store.pop(idx)
                if bgp_resolved and _db_engine is not None:
                    import asyncio  # noqa: PLC0415
                    import logging  # noqa: PLC0415

                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        pass
                    else:
                        _bgp_log = logging.getLogger(__name__)
                        _dev_capture = dev
                        _bundle_capture = bundle_name
                        _members_capture = members

                        async def _resolve_with_logging() -> None:
                            try:
                                await resolve_silent_faults_in_db(
                                    _db_engine, _dev_capture, _members_capture
                                )
                            except Exception:
                                _bgp_log.exception(
                                    "Failed to persist BGP-UP resolution for %s/%s",
                                    _dev_capture,
                                    _bundle_capture,
                                )

                        loop.create_task(_resolve_with_logging())

    if not is_recovery and (
        alert["classification"] == "CRITICAL"
        or (correlated.incident_id and not correlated.is_symptom)
    ):
        inc_id = correlated.incident_id or f"ALERT-{alert['id']}"
        existing = next((i for i in _incidents_store if i["id"] == inc_id), None)
        if existing:
            existing["alert_count"] = existing.get("alert_count", 0) + 1
            existing["last_alert"] = alert["timestamp"]
        else:
            _incidents_store.append(
                {
                    "id": inc_id,
                    "title": build_incident_title(
                        mnemonic=enriched.parsed.mnemonic,
                        device_name=enriched.device_name,
                        message=enriched.parsed.message,
                        interface_name=enriched.interface_name,
                        as_name=enriched.as_name,
                    ),
                    "severity": enriched.classification,
                    "device": enriched.device_name,
                    "mnemonic": enriched.parsed.mnemonic,
                    "message": enriched.parsed.message[:200],
                    "status": "active",
                    "alert_count": 1,
                    "started_at": alert["timestamp"],
                    "last_alert": alert["timestamp"],
                    "interface": enriched.interface_name,
                    "client": enriched.client_name,
                    "as_name": enriched.as_name,
                }
            )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint.

    Returns
    -------
    dict
        ``status``, ``version``, ``uptime_seconds``, ``alerts_processed``,
        and ``active_connections``.
    """
    uptime = time.monotonic() - _APP_START
    return {
        "status": "ok",
        "version": "0.1.0",
        "uptime_seconds": round(uptime, 1),
        "alerts_processed": _alerts_processed,
        "active_connections": _active_connections,
    }


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


_BDT = timezone(timedelta(hours=6))


def _period_to_time_range(
    period: str | None,
) -> tuple[datetime | None, datetime | None]:
    """Convert a period string into (start, end) naive datetime bounds.

    SQLite stores timestamps as naive strings (timezone stripped on write).
    The parser creates BDT-aware datetimes (UTC+6) which SQLite persists
    as their face-value date/time without the offset. We produce naive
    BDT datetimes here so the comparison matches what's in the DB.

    Returns (None, None) when the period is "all" or unrecognised.
    """
    if not period or period == "all":
        return None, None

    now = datetime.now(_BDT).replace(tzinfo=None)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    if period == "today":
        return today_start, None
    if period == "yesterday":
        yesterday_start = today_start - timedelta(days=1)
        return yesterday_start, today_start
    if period == "7d":
        return now - timedelta(days=7), None
    if period == "30d":
        return now - timedelta(days=30), None
    if period == "1y":
        return now - timedelta(days=365), None

    return None, None


@router.get("/api/alerts")
async def get_alerts(
    severity: str | None = Query(default=None, description="Filter by severity"),
    device: str | None = Query(default=None, description="Filter by device name"),
    period: str | None = Query(
        default=None,
        description="Time filter: today, yesterday, 7d, 30d, 1y, all",
    ),
    limit: int = Query(default=200, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    """Return a paginated list of alerts from SQLite, newest-first.

    Falls back to the in-memory store when the DB engine is not yet
    available (e.g. during tests that do not start the lifespan).

    Parameters
    ----------
    severity:
        Optional severity filter (CRITICAL, WARNING, INFO, NOISE, USER_LOGIN).
    device:
        Optional device name filter.
    period:
        Optional time filter: today, yesterday, 7d, 30d, 1y, all.
    limit:
        Maximum number of alerts to return (1-5000, default 200).
    offset:
        Number of alerts to skip (for pagination).

    Returns
    -------
    list[dict]
        List of alert dicts ordered newest-first.
    """
    if _db_engine is None:
        # Fallback: serve from in-memory store (no period filter applied)
        results = list(_alerts_store)
        if severity is not None:
            sev_upper = severity.upper()
            results = [a for a in results if a.get("classification") == sev_upper]
        if device is not None:
            results = [a for a in results if a.get("device") == device]
        return results[offset : offset + limit]

    from sqlalchemy import desc, select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    start, end = _period_to_time_range(period)

    async with AsyncSession(_db_engine) as session:  # type: ignore[arg-type]
        stmt = select(AlertLog).order_by(desc(AlertLog.timestamp))

        if severity:
            stmt = stmt.where(AlertLog.classification == severity.upper())
        if device:
            stmt = stmt.where(AlertLog.device_name == device)
        if start is not None:
            stmt = stmt.where(AlertLog.timestamp >= start)
        if end is not None:
            stmt = stmt.where(AlertLog.timestamp < end)

        stmt = stmt.offset(offset).limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

    return [
        {
            "id": str(row.id),
            "timestamp": row.timestamp.isoformat() if row.timestamp else "",
            "classification": row.classification,
            "device": row.device_name,
            "hostname": row.hostname,
            "mnemonic": row.mnemonic,
            "message": row.message,
            "facility": row.facility,
            "severity_level": row.severity_level,
            "interface_name": row.interface_name,
            "interface_description": row.interface_description,
            "client_name": row.client_name,
            "neighbor": row.bgp_neighbor,
            "as_number": row.as_number,
            "as_name": row.as_name,
            "incident_id": row.incident_id or "",
            "notification_sent": row.notification_sent,
            "source_ip": row.source_ip,
        }
        for row in rows
    ]


@router.get("/api/alerts/count")
async def get_alerts_count(
    period: str | None = Query(default="today"),
) -> dict[str, Any]:
    """Return alert counts grouped by classification for the given period.

    Parameters
    ----------
    period:
        Time filter: today (default), yesterday, 7d, 30d, 1y, all.

    Returns
    -------
    dict
        ``counts`` mapping classification → int, ``total`` int, ``period`` str.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    zero_counts: dict[str, int] = dict.fromkeys(classifications, 0)

    if _db_engine is None:
        # Fallback: count from in-memory store
        for alert in _alerts_store:
            cls = alert.get("classification", "")
            if cls in zero_counts:
                zero_counts[cls] += 1
        return {
            "period": period or "all",
            "counts": zero_counts,
            "total": sum(zero_counts.values()),
        }

    from sqlalchemy import func, select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    start, end = _period_to_time_range(period)

    async with AsyncSession(_db_engine) as session:  # type: ignore[arg-type]
        stmt = select(AlertLog.classification, func.count(AlertLog.id)).group_by(
            AlertLog.classification
        )
        if start is not None:
            stmt = stmt.where(AlertLog.timestamp >= start)
        if end is not None:
            stmt = stmt.where(AlertLog.timestamp < end)

        result = await session.execute(stmt)
        rows = result.all()

    counts: dict[str, int] = dict.fromkeys(classifications, 0)
    for cls, cnt in rows:
        if cls in counts:
            counts[cls] = cnt

    return {
        "period": period or "all",
        "counts": counts,
        "total": sum(counts.values()),
    }


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict[str, Any]:
    """Return a single alert by ID.

    Parameters
    ----------
    alert_id:
        Unique alert identifier.

    Raises
    ------
    HTTPException
        404 if the alert is not found.
    """
    for alert in _alerts_store:
        if str(alert.get("id")) == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/api/incidents")
async def get_incidents() -> list[dict[str, Any]]:
    """Return all active incidents.

    Returns from in-memory store. If empty but DB has recent CRITICAL
    alerts, synthesises incidents from DB so the panel is useful after
    a restart.
    """
    if _incidents_store:
        return list(_incidents_store)

    if _db_engine is None:
        return []

    from sqlalchemy import desc, select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    async with AsyncSession(_db_engine) as session:  # type: ignore[arg-type]
        stmt = (
            select(AlertLog)
            .where(AlertLog.classification == "CRITICAL")
            .where(AlertLog.resolved_at.is_(None))
            .order_by(desc(AlertLog.timestamp))
            .limit(50)
        )
        if _hardware_defects_as_noise:
            stmt = stmt.where(~AlertLog.mnemonic.in_(sorted(_SILENT_FAULT_MNEMONICS)))
        result = await session.execute(stmt)
        rows = result.scalars().all()

    # First pass: collect resolved device+interface pairs and BGP sessions.
    # Resolution is DEVICE-SPECIFIC: the same interface name on different
    # routers connects to different far-end equipment (e.g., KKT-Core-1
    # TGE0/0/1/7 → Equinix vs KKT-Core-2 TGE0/0/1/7 → F@H-IPT-02).
    resolved: set[str] = set()
    for row in rows:
        if not _is_recovery_event(row.mnemonic, row.message or ""):
            continue
        iface = row.interface_name or _extract_iface_from_msg(row.message or "")
        if row.mnemonic == "ADJCHANGE" and row.as_number:
            resolved.add(f"{row.device_name}:BGP:{row.as_number}")
        elif iface:
            resolved.add(f"{row.device_name}:{iface}")

    incidents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if _is_recovery_event(row.mnemonic, row.message or ""):
            continue
        iface = row.interface_name or _extract_iface_from_msg(row.message or "")
        if row.mnemonic == "ADJCHANGE" and row.as_number:
            if f"{row.device_name}:BGP:{row.as_number}" in resolved:
                continue
            discriminator = str(row.as_number)
        else:
            if iface and f"{row.device_name}:{iface}" in resolved:
                continue
            discriminator = row.bgp_neighbor or iface or ""
        key = f"{row.device_name}:{row.mnemonic}:{discriminator}"
        if key in seen:
            for inc in incidents:
                if inc.get("_key") == key:
                    inc["alert_count"] = inc.get("alert_count", 0) + 1
            continue
        seen.add(key)
        incidents.append(
            {
                "id": f"ALERT-{row.id}",
                "title": build_incident_title(
                    mnemonic=row.mnemonic,
                    device_name=row.device_name,
                    message=row.message or "",
                    interface_name=row.interface_name or "",
                    as_name=row.as_name or "",
                ),
                "severity": "CRITICAL",
                "device": row.device_name,
                "mnemonic": row.mnemonic,
                "message": (row.message or "")[:200],
                "status": "active",
                "alert_count": 1,
                "started_at": row.timestamp.isoformat() if row.timestamp else "",
                "last_alert": row.timestamp.isoformat() if row.timestamp else "",
                "interface": row.interface_name or "",
                "client": row.client_name or "",
                "as_name": row.as_name or "",
                "_key": key,
            }
        )
    return incidents


@router.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    """Return a single incident by ID.

    Parameters
    ----------
    incident_id:
        Unique incident identifier.

    Raises
    ------
    HTTPException
        404 if the incident is not found.
    """
    for incident in _incidents_store:
        if str(incident.get("id")) == incident_id:
            return incident
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@router.post("/api/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str) -> dict[str, Any]:
    """Acknowledge an active incident.

    Parameters
    ----------
    incident_id:
        Unique incident identifier.

    Raises
    ------
    HTTPException
        404 if the incident is not found.
    """
    for incident in _incidents_store:
        if str(incident.get("id")) == incident_id:
            incident["acknowledged"] = True
            return {"status": "acknowledged", "incident_id": incident_id}
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@router.get("/api/stats/daily")
async def get_stats_daily() -> dict[str, Any]:
    """Return daily aggregated statistics.

    Returns a dict with alert counts by classification for today.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    counts: dict[str, int] = dict.fromkeys(classifications, 0)
    for alert in _alerts_store:
        cls = alert.get("classification", "")
        if cls in counts:
            counts[cls] += 1
    return {
        "period": "daily",
        "counts": counts,
        "total": sum(counts.values()),
    }


@router.get("/api/stats/weekly")
async def get_stats_weekly() -> dict[str, Any]:
    """Return weekly aggregated statistics.

    Returns a dict with alert counts by classification for the past 7 days.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    counts: dict[str, int] = dict.fromkeys(classifications, 0)
    for alert in _alerts_store:
        cls = alert.get("classification", "")
        if cls in counts:
            counts[cls] += 1
    return {
        "period": "weekly",
        "counts": counts,
        "total": sum(counts.values()),
    }


@router.get("/api/stats/monthly")
async def get_stats_monthly() -> dict[str, Any]:
    """Return monthly aggregated statistics.

    Aggregates daily alert counts grouped by calendar month for all alerts
    in the in-memory store.  Each entry in ``months`` covers one month.

    Returns
    -------
    dict
        ``period`` set to ``"monthly"``, ``months`` list (each with
        ``year``, ``month``, and per-classification ``counts``), ``total``.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    monthly: dict[str, dict[str, int]] = {}

    for alert in _alerts_store:
        raw_ts = alert.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(raw_ts) if isinstance(raw_ts, str) else raw_ts
            key = f"{ts.year}-{ts.month:02d}"
        except (ValueError, AttributeError, TypeError):
            key = "unknown"

        if key not in monthly:
            monthly[key] = dict.fromkeys(classifications, 0)
        cls = alert.get("classification", "")
        if cls in monthly[key]:
            monthly[key][cls] += 1

    months_list = [
        {"month": k, "counts": v, "total": sum(v.values())}
        for k, v in sorted(monthly.items())
    ]
    grand_total = sum(m["total"] for m in months_list)  # type: ignore[misc]
    return {
        "period": "monthly",
        "months": months_list,
        "total": grand_total,
    }


@router.get("/api/stats/yearly")
async def get_stats_yearly() -> dict[str, Any]:
    """Return yearly aggregated statistics.

    Aggregates monthly counts into per-year totals.

    Returns
    -------
    dict
        ``period`` set to ``"yearly"``, ``years`` list (each with
        ``year`` and per-classification ``counts``), ``total``.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    yearly: dict[str, dict[str, int]] = {}

    for alert in _alerts_store:
        raw_ts = alert.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(raw_ts) if isinstance(raw_ts, str) else raw_ts
            key = str(ts.year)
        except (ValueError, AttributeError, TypeError):
            key = "unknown"

        if key not in yearly:
            yearly[key] = dict.fromkeys(classifications, 0)
        cls = alert.get("classification", "")
        if cls in yearly[key]:
            yearly[key][cls] += 1

    years_list = [
        {"year": k, "counts": v, "total": sum(v.values())}
        for k, v in sorted(yearly.items())
    ]
    grand_total = sum(y["total"] for y in years_list)  # type: ignore[misc]
    return {
        "period": "yearly",
        "years": years_list,
        "total": grand_total,
    }


# ---------------------------------------------------------------------------
# Runtime Settings
# ---------------------------------------------------------------------------


@router.get("/api/settings/hardware-noise")
async def get_hardware_noise_setting() -> dict[str, bool]:
    """Return the current state of the hardware-defects-as-noise toggle."""
    return {"hardware_defects_as_noise": _hardware_defects_as_noise}


@router.post("/api/settings/hardware-noise")
async def set_hardware_noise_setting(enabled: bool = True) -> dict[str, bool]:
    """Toggle the hardware-defects-as-noise setting.

    When enabled (default), RX_FAULT/SIGNAL/RFI events on backbone bundle
    member interfaces are reclassified as NOISE and excluded from active
    incidents.
    """
    global _hardware_defects_as_noise  # noqa: PLW0603
    _hardware_defects_as_noise = enabled
    return {"hardware_defects_as_noise": _hardware_defects_as_noise}


# ---------------------------------------------------------------------------
# Maintenance windows
# ---------------------------------------------------------------------------


@router.get("/api/maintenance")
async def get_maintenance_windows() -> list[dict[str, Any]]:
    """List active and upcoming maintenance windows.

    Returns all windows whose ``end_time`` is in the future (not yet expired).

    Returns
    -------
    list[dict]
        Maintenance window records, each with ``id``, ``device_name``,
        ``start_time``, ``end_time``, ``reason``, ``created_by``.
    """
    now = datetime.now(UTC)
    active: list[dict[str, Any]] = []
    for window in _maintenance_store:
        end_raw = window.get("end_time", "")
        try:
            end_ts = (
                datetime.fromisoformat(end_raw) if isinstance(end_raw, str) else end_raw
            )
            # Make aware if naive
            if end_ts.tzinfo is None:
                end_ts = end_ts.replace(tzinfo=UTC)
            if end_ts >= now:
                active.append(window)
        except (ValueError, AttributeError, TypeError):
            active.append(window)
    return active


@router.post("/api/maintenance", status_code=201)
async def create_maintenance_window(
    body: MaintenanceWindowCreate,
) -> dict[str, Any]:
    """Create a new maintenance window.

    Parameters
    ----------
    body:
        ``device_name``, ``start_time``, ``end_time`` (required);
        ``reason``, ``created_by`` (optional).

    Returns
    -------
    dict
        The created maintenance window record including its assigned ``id``.
    """
    global _maintenance_id_counter  # noqa: PLW0603
    _maintenance_id_counter += 1
    window: dict[str, Any] = {
        "id": _maintenance_id_counter,
        "device_name": body.device_name,
        "start_time": body.start_time.isoformat(),
        "end_time": body.end_time.isoformat(),
        "reason": body.reason,
        "created_by": body.created_by,
    }
    _maintenance_store.append(window)
    return window


@router.delete("/api/maintenance/{window_id}", status_code=200)
async def delete_maintenance_window(window_id: int) -> dict[str, Any]:
    """Delete a maintenance window by ID.

    Parameters
    ----------
    window_id:
        The numeric ID of the maintenance window to delete.

    Raises
    ------
    HTTPException
        404 if the window is not found.

    Returns
    -------
    dict
        ``{"status": "deleted", "id": window_id}``
    """
    for i, window in enumerate(_maintenance_store):
        if window.get("id") == window_id:
            _maintenance_store.pop(i)
            return {"status": "deleted", "id": window_id}
    raise HTTPException(
        status_code=404, detail=f"Maintenance window {window_id} not found"
    )


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.get("/api/devices")
async def get_devices() -> list[dict[str, Any]]:
    """Return all known network devices with their status.

    Returns
    -------
    list[dict]
        One entry per unique device (deduplicated — KKT aliases merged).
    """
    seen: set[str] = set()
    devices: list[dict[str, Any]] = []
    for ip, info in DEVICE_MAP.items():
        if info.name in seen:
            continue
        seen.add(info.name)
        devices.append(
            {
                "name": info.name,
                "hostname": info.hostname,
                "location": info.location,
                "platform": info.platform,
                "ip": ip,
                "status": "unknown",
            }
        )
    return devices


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


@router.get("/api/topology")
async def get_topology() -> dict[str, Any]:
    """Return network topology as nodes and links for SVG rendering.

    Returns
    -------
    dict
        ``nodes`` — list of device nodes with id, name, location, level.
        ``links`` — list of {source, target, bundle, description} dicts.
    """
    # Build node list from topology data (devices that have topology records)
    node_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []

    # Assign display levels: EQ=0, KKT=1, DHK/COX=2
    _level_map: dict[str, int] = {
        "Equinix-RTR-1": 0,
        "Equinix-RTR-2": 0,
        "KKT-Core-01": 1,
        "KKT-Core-02": 1,
        "KKT-Core-03": 1,
        "DHK-Core-03": 2,
        "COX-Core-01": 2,
        "COX-Core-03": 2,
        "DHK-Core-02": 2,
    }

    for ip, topo in NETWORK_TOPOLOGY.items():
        if topo.name not in node_ids:
            node_ids.add(topo.name)
            device_info = DEVICE_MAP.get(ip)
            nodes.append(
                {
                    "id": topo.name,
                    "name": topo.name,
                    "ip": ip,
                    "location": device_info.location if device_info else "",
                    "platform": device_info.platform if device_info else "",
                    "level": _level_map.get(topo.name, 2),
                    "status": "unknown",
                }
            )

    # Build link list from topology upstreams
    links: list[dict[str, Any]] = []
    seen_links: set[frozenset[str]] = set()
    for _ip, topo in NETWORK_TOPOLOGY.items():
        for bundle, link in topo.upstreams.items():
            remote_topo = NETWORK_TOPOLOGY.get(link.remote_device_ip)
            remote_name = remote_topo.name if remote_topo else link.remote_device_ip
            key = frozenset([topo.name, remote_name, bundle])
            if key in seen_links:
                continue
            seen_links.add(key)
            links.append(
                {
                    "source": topo.name,
                    "target": remote_name,
                    "bundle": bundle,
                    "description": link.description,
                    "members": len(link.members),
                    "status": "unknown",
                }
            )

    return {"nodes": nodes, "links": links}


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


@router.get("/api/bgp/peers")
async def get_bgp_peers() -> list[dict[str, Any]]:
    """Return BGP peer status list.

    Peers are derived from alerts in the store; returns empty list when no
    BGP events have been received yet.

    Returns
    -------
    list[dict]
        Each entry has neighbor, as_number, as_name, device, last_state.
    """
    seen: dict[str, dict[str, Any]] = {}
    for alert in _alerts_store:
        neighbor = alert.get("neighbor", "")
        if not neighbor:
            continue
        entry = {
            "neighbor": neighbor,
            "as_number": alert.get("as_number", 0),
            "as_name": alert.get("as_name", ""),
            "device": alert.get("device", ""),
            "last_state": alert.get("classification", "UNKNOWN"),
        }
        seen[neighbor] = entry
    return list(seen.values())
