"""REST API routes for BSCCL NetWatch.

Milestone 6: minimal health endpoint.
Milestone 7: expanded alert, incident, device, topology, stats, BGP endpoints.
Milestone 6/7 audit: monthly/yearly stats, maintenance window endpoints.
Milestone 8: DB-backed /api/alerts with period filter; /api/alerts/count.
Milestone 8+: CSV export endpoint for post-incident reports.

Note: slowapi's ``@limiter.limit()`` / ``@limiter.exempt`` decorators require
a ``request: Request`` parameter on each handler even when the body does not
reference it directly.  ARG001 is file-level suppressed for this reason.
"""

# ruff: noqa: ARG001

from __future__ import annotations

import asyncio  # noqa: TC003 — used at runtime (get_running_loop)
import csv
import io
import itertools
import logging
import re
import time
from collections import deque
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator

from src.auth import require_api_key
from src.data.bgp_bundle_map import lookup_bundle_for_bgp_peer
from src.data.device_map import DEVICE_MAP
from src.data.topology import NETWORK_TOPOLOGY
from src.database.timeutils import now_bdt_naive
from src.rate_limit import RATE_LIMIT_MUTATING, RATE_LIMIT_READ, limiter

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from src.core.correlator import CorrelatedEvent
    from src.core.enricher import EnrichedLog
    from src.core.syslog_receiver import SyslogReceiver
    from src.notifications.escalation import EscalationEngine

router = APIRouter()

logger = logging.getLogger(__name__)

# Application start time (module-level; set when the module is first imported)
_APP_START: float = time.monotonic()

# Shared counters updated by the ingestion pipeline
_alerts_processed: int = 0
_active_connections: int = 0

# In-memory stores — capped to prevent unbounded memory growth
_alerts_store: deque[dict[str, Any]] = deque(maxlen=10000)
_incidents_store: deque[dict[str, Any]] = deque(maxlen=500)
_maintenance_store: deque[dict[str, Any]] = deque(maxlen=500)
_maintenance_id_counter: int = 0
_alert_id_counter: itertools.count[int] = itertools.count(1)

# DB engine — set during lifespan startup via set_db_engine()
_db_engine: AsyncEngine | None = None

# Syslog receiver — set during lifespan startup via set_receiver()
_receiver: SyslogReceiver | None = None

# Escalation engine — set during lifespan startup via set_escalation_engine()
_escalation_engine: EscalationEngine | None = None

# Background task references — set during lifespan startup via set_background_tasks()
_background_tasks: dict[str, asyncio.Task[None]] = {}

# ---------------------------------------------------------------------------
# Input validation allowlists
# ---------------------------------------------------------------------------

_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"}
)

_VALID_PERIODS: frozenset[str] = frozenset(
    {"today", "yesterday", "7d", "30d", "1y", "all"}
)


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

# Mnemonics where a "Clear" substring in the message indicates recovery.
# LOW_RX_POWER_ALARM fires for both alarm-set ("Set|…") and alarm-clear ("Clear|…").
# The classification rules use rule_id="SFP_ALARM_CLEAR" for the clear variant, but
# rule_id is not persisted in alert_log, so the DB-synthesis path must detect it from
# the message text instead.
_RECOVERY_MNEMONICS_WITH_CLEAR = frozenset(
    {
        "LOW_RX_POWER_ALARM",
        "TX_POWER_ALARM",
        "RX_POWER_ALARM",
        "HIGH_RX_POWER_ALARM",
    }
)

_SILENT_FAULT_MNEMONICS = frozenset({"RX_FAULT", "SIGNAL", "RFI"})

# Runtime toggle: treat hardware defects (RX_FAULT/SIGNAL/RFI) on backbone
# bundle members as NOISE rather than CRITICAL incidents. Default ON.
_hardware_defects_as_noise: bool = True

# Runtime toggle: when False, MAXPFX (BGP max-prefix) events are muted across
# all live surfaces — notify, audio, active-incident card, live feed — while
# still being persisted to the DB.  Default ON.
_maxpfx_alerts_enabled: bool = True

# Debounce for the recovery cross-check in get_incidents()
_last_recovery_prune: float = 0.0
_RECOVERY_PRUNE_INTERVAL_S: float = 30.0
_last_recovery_prune_db: float = 0.0
_RECOVERY_PRUNE_DB_INTERVAL_S: float = 60.0


def _is_recovery_event(mnemonic: str, message: str, rule_id: str = "") -> bool:
    if rule_id and rule_id in _RECOVERY_RULE_IDS:
        return True
    if mnemonic in _RECOVERY_MNEMONICS_ALWAYS and "no longer" not in message:
        return True
    if mnemonic in _RECOVERY_MNEMONICS_WITH_CLEAR and re.search(r"\bClear\b", message):
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
    ("TwentyFiveGigE", "25GE"),
    ("FiftyGigE", "50GE"),
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


def _to_naive_iso(ts: Any) -> str:
    """Return ``ts`` as ISO-8601 with any UTC offset stripped (naive BDT face value).

    A tz-aware ``parsed.timestamp`` serialises as ``...+06:00``, which breaks the
    lexicographic timestamp comparisons in the recovery-prune helpers.

    Args:
        ts: A datetime object (tz-aware or naive) or any object with
            ``.isoformat()``.

    Returns:
        An ISO-8601 string with tzinfo stripped (naive BDT face value).
    """
    if isinstance(ts, datetime):
        return ts.replace(tzinfo=None).isoformat()
    raw: str = ts.isoformat()
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=None).isoformat()
    except (TypeError, ValueError):
        return raw


_BGP_NEIGHBOR_RE = re.compile(r"neighbor\s+(\S+)", re.IGNORECASE)


def _extract_bgp_neighbor_from_msg(message: str) -> str:
    """Extract the BGP neighbor address from a syslog message body.

    Args:
        message: Raw syslog message text.

    Returns:
        The neighbor IP/address string, or an empty string if not found.
    """
    # Cap scan length: the BGP neighbor always appears early;
    # bounds work on huge messages.
    m = _BGP_NEIGHBOR_RE.search(message[:500])
    return m.group(1) if m else ""


def _bgp_discriminator(neighbor: str, as_number: int, message: str) -> str:
    """Stable BGP-peer identity used to dedup ADJCHANGE incidents.

    A DOWN event usually carries ``bgp_neighbor``; its matching UP event
    sometimes omits it but still names the neighbor in the message text, or
    carries only the AS number. Falling back neighbor -> message -> AS keeps
    a DOWN and its UP under one key so the UP can supersede the DOWN.

    Args:
        neighbor: The ``bgp_neighbor`` field value (may be empty).
        as_number: The ``as_number`` field value (may be 0).
        message: The raw syslog message text.

    Returns:
        A stable string discriminator for the BGP peer identity.
    """
    # Empty result is an accepted edge case: an anonymous ADJCHANGE with no
    # neighbor and AS 0 (extremely rare) collapses onto the per-device key.
    return (
        neighbor
        or _extract_bgp_neighbor_from_msg(message)
        or (str(as_number) if as_number else "")
    )


def _incident_group_key(
    device: str,
    mnemonic: str,
    interface: str,
    neighbor: str,
    as_number: int,
    message: str,
) -> str:
    """Logical identity of an incident card, independent of the alert counter.

    Two alerts describing the same fault (same device + mnemonic +
    interface/BGP-peer) collapse onto one card instead of spawning a new
    ALERT-N card per occurrence.

    Args:
        device: Device name.
        mnemonic: Syslog mnemonic (e.g. ``ADJCHANGE``, ``UPDOWN``).
        interface: Interface name (may be empty).
        neighbor: BGP neighbor address (may be empty).
        as_number: BGP AS number (may be 0).
        message: Raw syslog message text.

    Returns:
        A stable string key identifying this fault/peer combination.
    """
    if mnemonic == "ADJCHANGE":
        return f"{device}:ADJCHANGE:{_bgp_discriminator(neighbor, as_number, message)}"
    iface = interface or _extract_iface_from_msg(message)
    return f"{device}:{mnemonic}:{iface}"


def is_alert_acknowledged(
    device: str,
    mnemonic: str,
    interface: str,
    neighbor: str,
    as_number: int,
    message: str,
    incident_id: str = "",
) -> bool:
    """Report whether the incident this alert belongs to is acknowledged.

    The notification path calls this to suppress repeat Discord/Telegram alerts
    for an incident an operator has already acknowledged in the dashboard.
    Matching mirrors ``add_alert_to_store``: a correlator-owned incident is
    matched by its ``INC-`` id; everything else by the shared
    ``_incident_group_key`` (so a repeat MAXPFX folds onto the same ACKed card
    regardless of BGP neighbor, exactly as the live card grouping does).

    Args:
        device: Device name.
        mnemonic: Syslog mnemonic.
        interface: Interface name (may be empty).
        neighbor: BGP neighbor address (may be empty).
        as_number: BGP AS number (may be 0).
        message: Raw syslog message text.
        incident_id: Correlator incident id (``INC-...``) when present, else "".

    Returns:
        True only if a matching incident card exists and is acknowledged.
    """
    if incident_id:
        inc = next((i for i in _incidents_store if i.get("id") == incident_id), None)
        return bool(inc and inc.get("acknowledged"))

    group_key = _incident_group_key(
        device, mnemonic, interface, neighbor, as_number, message
    )
    for inc in _incidents_store:
        if str(inc.get("id", "")).startswith("INC-"):
            continue
        if (
            _incident_group_key(
                inc.get("device", ""),
                inc.get("mnemonic", ""),
                inc.get("interface", ""),
                inc.get("neighbor", ""),
                inc.get("as_number", 0),
                inc.get("message", ""),
            )
            == group_key
        ):
            return bool(inc.get("acknowledged"))
    return False


def is_maxpfx_alerts_enabled() -> bool:
    """Return whether MAXPFX alerts are enabled (True) or muted (False)."""
    return _maxpfx_alerts_enabled


def _prune_recovered_incidents() -> None:
    """Remove incidents from the in-memory store that have been superseded
    by a recovery event in ``_alerts_store``.

    Acts as a safety net: even if the real-time recovery matching in
    ``add_alert_to_store()`` missed a match, this periodic sweep catches it.
    Debounced to run at most once per ``_RECOVERY_PRUNE_INTERVAL_S`` seconds.
    """
    global _last_recovery_prune  # noqa: PLW0603
    now = time.monotonic()
    if now - _last_recovery_prune < _RECOVERY_PRUNE_INTERVAL_S:
        return
    _last_recovery_prune = now

    if not _incidents_store or not _alerts_store:
        return

    resolve_ids: set[int] = set()
    for i, inc in enumerate(_incidents_store):
        inc_dev = inc.get("device", "")
        inc_iface = inc.get("interface", "")
        inc_neighbor = inc.get("neighbor", "")
        inc_started = inc.get("started_at", "")

        for alert in _alerts_store:
            if alert.get("device") != inc_dev:
                continue
            a_mnemonic = alert.get("mnemonic", "")
            a_message = alert.get("message", "")
            if not _is_recovery_event(a_mnemonic, a_message):
                continue
            if alert.get("timestamp", "") <= inc_started:
                continue
            a_iface = alert.get("interface", "")
            a_neighbor = alert.get("neighbor", "")
            if inc_iface and a_iface and inc_iface == a_iface:
                resolve_ids.add(i)
                break
            if inc_neighbor and a_neighbor and inc_neighbor == a_neighbor:
                resolve_ids.add(i)
                break
            if inc.get("mnemonic") == a_mnemonic:
                a_iface_msg = _extract_iface_from_msg(a_message)
                inc_iface_msg = inc_iface or _extract_iface_from_msg(
                    inc.get("message", "")
                )
                if a_iface_msg and inc_iface_msg and a_iface_msg == inc_iface_msg:
                    resolve_ids.add(i)
                    break

    if resolve_ids:
        kept = [
            inc for idx, inc in enumerate(_incidents_store) if idx not in resolve_ids
        ]
        _incidents_store.clear()
        _incidents_store.extend(kept)
        logger.info("Recovery prune removed %d stale incident(s)", len(resolve_ids))


async def _prune_recovered_incidents_db() -> None:
    """DB-backed fallback: resolve incidents whose recovery events are no
    longer in ``_alerts_store`` (e.g. after eviction or restart).

    Queries the database for recovery events that post-date each active
    incident, removing any incident that has a matching recovery row.
    Debounced to run at most once per ``_RECOVERY_PRUNE_DB_INTERVAL_S``.
    """
    global _last_recovery_prune_db  # noqa: PLW0603
    now = time.monotonic()
    if now - _last_recovery_prune_db < _RECOVERY_PRUNE_DB_INTERVAL_S:
        return
    _last_recovery_prune_db = now

    if not _incidents_store or _db_engine is None:
        return

    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    _recovery_mnemonics = sorted(
        _RECOVERY_MNEMONICS_WITH_UP | _RECOVERY_MNEMONICS_ALWAYS
    )
    devices = {inc.get("device", "") for inc in _incidents_store}

    async with AsyncSession(_db_engine) as session:
        stmt = (
            select(AlertLog)
            .where(AlertLog.device_name.in_(sorted(devices)))
            .where(AlertLog.mnemonic.in_(_recovery_mnemonics))
            .order_by(AlertLog.timestamp.desc())
            .limit(500)
        )
        result = await session.execute(stmt)
        recovery_rows = list(result.scalars().all())

    if not recovery_rows:
        return

    resolve_ids: set[int] = set()
    for i, inc in enumerate(_incidents_store):
        inc_dev = inc.get("device", "")
        inc_iface = inc.get("interface", "")
        inc_neighbor = inc.get("neighbor", "")
        inc_started = inc.get("started_at", "")
        inc_mnemonic = inc.get("mnemonic", "")

        for row in recovery_rows:
            if row.device_name != inc_dev:
                continue
            if not _is_recovery_event(row.mnemonic, row.message or ""):
                continue
            row_ts = row.timestamp.isoformat() if row.timestamp else ""
            if row_ts <= inc_started:
                continue
            r_iface = row.interface_name or _extract_iface_from_msg(row.message or "")
            r_neighbor = getattr(row, "bgp_neighbor", "") or ""
            if inc_iface and r_iface and inc_iface == r_iface:
                resolve_ids.add(i)
                break
            if inc_neighbor and r_neighbor and inc_neighbor == r_neighbor:
                resolve_ids.add(i)
                break
            if inc_mnemonic == row.mnemonic:
                r_iface_msg = _extract_iface_from_msg(row.message or "")
                inc_iface_msg = inc_iface or _extract_iface_from_msg(
                    inc.get("message", "")
                )
                if r_iface_msg and inc_iface_msg and r_iface_msg == inc_iface_msg:
                    resolve_ids.add(i)
                    break

    if resolve_ids:
        kept = [
            inc for idx, inc in enumerate(_incidents_store) if idx not in resolve_ids
        ]
        _incidents_store.clear()
        _incidents_store.extend(kept)
        logger.info("DB recovery prune removed %d stale incident(s)", len(resolve_ids))


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


def set_db_engine(engine: AsyncEngine | None) -> None:
    """Register (or clear) the async DB engine for use by /api/alerts.

    Called from ``main.py`` lifespan after the engine is created, and again
    with ``None`` on shutdown so handlers stop using the disposed engine.
    """
    global _db_engine  # noqa: PLW0603
    _db_engine = engine


def set_escalation_engine(engine: EscalationEngine | None) -> None:
    """Register (or clear) the escalation engine for the ack endpoint.

    Called from ``main.py`` lifespan so that acknowledging an incident can
    cancel its pending escalation (the 15-minute unacked timer).
    """
    global _escalation_engine  # noqa: PLW0603
    _escalation_engine = engine


def set_receiver(receiver: SyslogReceiver) -> None:
    """Register the syslog receiver for Loki health reporting.

    Called from ``main.py`` lifespan after the receiver is created.
    """
    global _receiver  # noqa: PLW0603
    _receiver = receiver


def set_background_tasks(tasks: dict[str, asyncio.Task[None]]) -> None:
    """Register background task references for health-check liveness reporting.

    Called from ``main.py`` lifespan after background tasks are created.

    Parameters
    ----------
    tasks:
        Mapping of task name to its ``asyncio.Task`` handle.
    """
    global _background_tasks  # noqa: PLW0603
    _background_tasks = tasks


def get_maintenance_store() -> deque[dict[str, Any]]:
    """Return the in-memory maintenance window list (read-only access)."""
    return _maintenance_store


async def load_persisted_state(engine: AsyncEngine) -> None:
    """Seed the in-memory caches from DB on startup.

    Restores:
    - All maintenance windows from the ``maintenance_window`` table into
      ``_maintenance_store`` (replacing any prior in-memory content).
    - The ``hardware_defects_as_noise`` toggle from the ``app_setting`` table.

    This function is idempotent and safe to call once per process startup.
    Failures are logged but never propagate — the app starts with defaults.

    Parameters
    ----------
    engine:
        The async DB engine to read from.
    """
    import logging  # noqa: PLC0415

    _load_log = logging.getLogger(__name__)

    global _hardware_defects_as_noise, _maxpfx_alerts_enabled  # noqa: PLW0603

    try:
        from sqlalchemy.ext.asyncio import (
            AsyncSession as _AsyncSession,  # noqa: PLC0415
        )

        from src.database.crud import (  # noqa: PLC0415
            get_app_setting,
            list_maintenance_windows,
        )

        async with _AsyncSession(engine) as session:
            # ── Maintenance windows ────────────────────────────────────────
            rows = await list_maintenance_windows(session)
            _maintenance_store.clear()
            for row in rows:
                _maintenance_store.append(
                    {
                        "id": row.id,
                        "device_name": row.device_name,
                        "start_time": row.start_time.isoformat(),
                        "end_time": row.end_time.isoformat(),
                        "reason": row.reason,
                        "created_by": row.created_by,
                    }
                )
            _load_log.info("Loaded %d maintenance windows from DB", len(rows))

            # ── Hardware-noise toggle ──────────────────────────────────────
            value = await get_app_setting(session, "hardware_defects_as_noise")
            if value is not None:
                _hardware_defects_as_noise = value.lower() == "true"
                _load_log.info(
                    "Loaded hardware_defects_as_noise=%s from DB",
                    _hardware_defects_as_noise,
                )

            # ── MAXPFX-alerts toggle ──────────────────────────────────────
            mpx = await get_app_setting(session, "maxpfx_alerts_enabled")
            if mpx is not None:
                _maxpfx_alerts_enabled = mpx.lower() == "true"
                _load_log.info(
                    "Loaded maxpfx_alerts_enabled=%s from DB",
                    _maxpfx_alerts_enabled,
                )

            # ── Notification settings ─────────────────────────────────────
            from src.config import get_settings as _gs  # noqa: PLC0415

            _s = _gs()
            for _key, _attr in [
                ("discord_enabled", "discord_enabled"),
                ("telegram_enabled", "telegram_enabled"),
                ("dedup_window_seconds", "dedup_window_seconds"),
            ]:
                _val = await get_app_setting(session, _key)
                if _val is not None:
                    if _attr.endswith("_seconds"):
                        object.__setattr__(_s, _attr, int(_val))
                    else:
                        object.__setattr__(_s, _attr, _val.lower() == "true")
                    _load_log.info("Loaded %s=%s from DB", _key, _val)

            val = await get_app_setting(session, "notify_severity")
            if val is not None and val in ("CRITICAL", "WARNING", "INFO"):
                object.__setattr__(_s, "notify_severity", val)
                _load_log.info("Loaded notify_severity=%s from DB", val)

            # ── Sound & UI preferences ────────────────────────────────────
            for _snd_key in _sound_prefs:
                _snd_val = await get_app_setting(session, _snd_key)
                if _snd_val is not None:
                    _sound_prefs[_snd_key] = _snd_val.lower() == "true"
                    _load_log.info("Loaded %s=%s from DB", _snd_key, _snd_val)

            # ── Resolve stale noise-eligible alerts ───────────────────────
            if _hardware_defects_as_noise:
                resolved = await _resolve_noise_alerts_on_startup(engine)
                if resolved > 0:
                    _load_log.info(
                        "Resolved %d stale RX_FAULT/SIGNAL/RFI alerts in DB",
                        resolved,
                    )
    except Exception as exc:  # noqa: BLE001
        _load_log.warning("Could not load persisted state from DB: %s", exc)


async def resolve_silent_faults_in_db(
    engine: AsyncEngine,
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

    now = now_bdt_naive()
    cutoff = now - timedelta(hours=24)
    async with AsyncSession(engine) as session:
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


async def resolve_recovery_alerts_in_db(
    engine: AsyncEngine,
    device_name: str,
    interface_name: str,
    bgp_neighbor: str,
    as_number: int | None,
    mnemonic: str,
    message: str = "",
) -> int:
    """Mark matching unresolved CRITICAL alerts as resolved in the database.

    Called when a recovery event (Interface UP, BGP UP, Bundle ACTIVE, etc.)
    arrives.  Finds unresolved CRITICAL alerts for the same device and
    interface/BGP-peer and sets ``resolved_at`` so they no longer appear as
    active incidents after a server restart.

    Only resolves alerts from the last 24 hours to bound blast radius.
    Returns the number of rows updated.
    """
    from sqlalchemy import CursorResult, and_, or_, update  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    now = now_bdt_naive()
    cutoff = now - timedelta(hours=24)

    iface = interface_name or _extract_iface_from_msg(message)

    match_conditions = []
    if iface:
        match_conditions.append(AlertLog.interface_name == iface)
    if bgp_neighbor and mnemonic == "ADJCHANGE":
        bgp_parts = [AlertLog.bgp_neighbor == bgp_neighbor]
        if as_number:
            bgp_parts.append(AlertLog.as_number == as_number)
        match_conditions.append(and_(AlertLog.mnemonic == "ADJCHANGE", or_(*bgp_parts)))
    if not match_conditions and mnemonic in _RECOVERY_MNEMONICS_ALWAYS:
        match_conditions.append(AlertLog.mnemonic == mnemonic)

    if not match_conditions:
        return 0

    async with AsyncSession(engine) as session:
        stmt = (
            update(AlertLog)
            .where(AlertLog.device_name == device_name)
            .where(AlertLog.classification == "CRITICAL")
            .where(AlertLog.resolved_at.is_(None))
            .where(AlertLog.timestamp >= cutoff)
            .where(or_(*match_conditions))
            .values(resolved_at=now, resolution_reason="recovery_event")
        )
        result = cast("CursorResult[Any]", await session.execute(stmt))
        await session.commit()
        return result.rowcount


async def _resolve_noise_alerts_on_startup(engine: AsyncEngine) -> int:
    """Mark unresolved RX_FAULT/SIGNAL/RFI alerts as noise-resolved on startup.

    Called once during ``load_persisted_state`` when the hardware-defects-as-noise
    toggle is enabled.  Resolves stale alerts so they don't reappear as active
    incidents after a server restart.
    """
    from sqlalchemy import CursorResult, update  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    now = now_bdt_naive()
    async with AsyncSession(engine) as session:
        stmt = (
            update(AlertLog)
            .where(AlertLog.mnemonic.in_(sorted(_SILENT_FAULT_MNEMONICS)))
            .where(AlertLog.resolved_at.is_(None))
            .values(
                classification="NOISE",
                resolved_at=now,
                resolution_reason="noise_toggle_enabled",
            )
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


class IncidentAckRequest(BaseModel):
    """Request body for acknowledging an incident."""

    operator_name: str = Field(default="", max_length=64)
    comment: str = Field(default="", max_length=1000)


class ShiftHandoffCreate(BaseModel):
    """Request body for creating a shift handoff note."""

    shift_name: str = Field(..., pattern=r"^(morning|evening|night)$")
    shift_date: str = Field(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
    operator_name: str = Field(..., min_length=1, max_length=64)
    notes: str = Field(default="", max_length=2000)
    open_incidents: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    warning_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def validate_shift_date(self) -> ShiftHandoffCreate:
        """Validate that shift_date is a real calendar date."""
        from datetime import date as _date  # noqa: PLC0415

        try:
            _date.fromisoformat(self.shift_date)
        except ValueError as exc:
            msg = "shift_date must be a valid calendar date"
            raise ValueError(msg) from exc
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


def add_alert_to_store(enriched: EnrichedLog, correlated: CorrelatedEvent) -> None:
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
        "id": next(_alert_id_counter),
        "timestamp": _to_naive_iso(enriched.parsed.timestamp),
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
        "as_number": enriched.as_number or 0,
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
        resolve_ids: set[int] = set()
        for i, inc in enumerate(_incidents_store):
            if inc["device"] != dev:
                continue
            inc_iface = inc.get("interface") or _extract_iface_from_msg(
                inc.get("message", "")
            )
            if iface and inc_iface == iface:
                resolve_ids.add(i)
            elif neighbor and inc.get("mnemonic") == "ADJCHANGE":
                inc_neighbor = inc.get("neighbor", "")
                if inc_neighbor and inc_neighbor == neighbor:
                    resolve_ids.add(i)
                else:
                    inc_msg = inc.get("message", "")
                    if neighbor in inc_msg or (as_num and str(as_num) in inc_msg):
                        resolve_ids.add(i)
        if resolve_ids:
            kept = [
                inc for i, inc in enumerate(_incidents_store) if i not in resolve_ids
            ]
            _incidents_store.clear()
            _incidents_store.extend(kept)

        # Persist resolution to DB so resolved incidents stay resolved
        # across server restarts.  This runs for EVERY recovery event —
        # even when _incidents_store was empty (e.g. right after restart)
        # — so that stale DOWN alerts in the DB are correctly marked.
        if _db_engine is not None:
            import asyncio as _aio  # noqa: PLC0415

            _r_dev = dev
            _r_iface = iface
            _r_neighbor = neighbor
            _r_as_num = as_num
            _r_mnemonic = enriched.parsed.mnemonic
            _r_message = enriched.parsed.message
            _r_engine: AsyncEngine = _db_engine

            async def _persist_recovery() -> None:
                try:
                    cnt = await resolve_recovery_alerts_in_db(
                        _r_engine,
                        _r_dev,
                        _r_iface,
                        _r_neighbor,
                        _r_as_num,
                        _r_mnemonic,
                        _r_message,
                    )
                    if cnt:
                        logger.info(
                            "Recovery resolved %d DB alerts for %s/%s",
                            cnt,
                            _r_dev,
                            _r_iface or _r_neighbor,
                        )
                except Exception:  # noqa: BLE001
                    logger.exception(
                        "Failed to persist recovery resolution for %s/%s",
                        _r_dev,
                        _r_iface or _r_neighbor,
                    )

            try:
                loop = _aio.get_running_loop()
                loop.create_task(_persist_recovery())
            except RuntimeError:
                logger.warning(
                    "No event loop for recovery DB persist: %s/%s",
                    _r_dev,
                    _r_iface or _r_neighbor,
                )

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
                bgp_resolve_ids: set[int] = set()
                for i, inc in enumerate(_incidents_store):
                    if inc["device"] != dev:
                        continue
                    if inc.get("mnemonic") not in _SILENT_FAULT_MNEMONICS:
                        continue
                    inc_iface = inc.get("interface") or _extract_iface_from_msg(
                        inc.get("message", "")
                    )
                    if inc_iface in members:
                        bgp_resolve_ids.add(i)
                if bgp_resolve_ids:
                    kept_incs = [
                        inc
                        for i, inc in enumerate(_incidents_store)
                        if i not in bgp_resolve_ids
                    ]
                    _incidents_store.clear()
                    _incidents_store.extend(kept_incs)
                if bgp_resolve_ids and _db_engine is not None:
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
                        _engine_capture: AsyncEngine = _db_engine

                        async def _resolve_with_logging() -> None:
                            try:
                                await resolve_silent_faults_in_db(
                                    _engine_capture, _dev_capture, _members_capture
                                )
                            except Exception:  # noqa: BLE001
                                _bgp_log.exception(
                                    "Failed to persist BGP-UP resolution for %s/%s",
                                    _dev_capture,
                                    _bundle_capture,
                                )

                        loop.create_task(_resolve_with_logging())

    if (
        not is_recovery
        and alert["classification"] != "NOISE"
        and (
            alert["classification"] == "CRITICAL"
            or (correlated.incident_id and not correlated.is_symptom)
        )
    ):
        if correlated.incident_id:
            inc_id = correlated.incident_id
            existing = next((i for i in _incidents_store if i["id"] == inc_id), None)
        else:
            group_key = _incident_group_key(
                enriched.device_name,
                enriched.parsed.mnemonic,
                enriched.interface_name,
                enriched.bgp_neighbor,
                enriched.as_number or 0,
                enriched.parsed.message,
            )
            # Skip correlator-owned cards (id "INC-..."): those are grouped by
            # the correlation engine via correlated.incident_id above, so the
            # ungrouped fallback must never fold a standalone alert into one.
            existing = next(
                (
                    i
                    for i in _incidents_store
                    if not str(i.get("id", "")).startswith("INC-")
                    and _incident_group_key(
                        i.get("device", ""),
                        i.get("mnemonic", ""),
                        i.get("interface", ""),
                        i.get("neighbor", ""),
                        i.get("as_number", 0),
                        i.get("message", ""),
                    )
                    == group_key
                ),
                None,
            )
            inc_id = existing["id"] if existing else f"ALERT-{alert['id']}"
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
                    "severity": alert["classification"],
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
                    "neighbor": enriched.bgp_neighbor,
                    "as_number": enriched.as_number or 0,
                }
            )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


_STALE_DATA_THRESHOLD_SECONDS = 600  # 10 minutes


@router.get("/health")
@limiter.exempt  # type: ignore[untyped-decorator]
async def health(request: Request) -> dict[str, Any]:
    """Health check endpoint.

    Returns
    -------
    dict
        ``status``, ``version``, ``uptime_seconds``, ``alerts_processed``,
        ``active_connections``, ``database_ok``, ``background_tasks``,
        ``loki_connected``, ``last_alert_received_at``, ``stale_data``.

        ``status`` is ``"degraded"`` when the DB check fails or when
        syslog data is stale (no message received in the last 10 minutes).
        ``background_tasks`` maps task names to ``True`` (running) or
        ``False`` (stopped/crashed).
    """
    uptime = time.monotonic() - _APP_START
    database_ok = False
    if _db_engine is not None:
        try:
            from sqlalchemy import text  # noqa: PLC0415
            from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

            async with AsyncSession(_db_engine) as _session:
                await _session.execute(text("SELECT 1"))
            database_ok = True
        except Exception:  # noqa: BLE001
            database_ok = False

    bg_status = {name: not task.done() for name, task in _background_tasks.items()}

    # Loki / syslog receiver health
    loki_connected = False
    last_alert_received_at: str | None = None
    stale_data = False

    if _receiver is not None:
        loki_connected = _receiver.is_connected
        last_msg = _receiver.last_message_at
        if last_msg is not None:
            last_alert_received_at = last_msg.isoformat()
            elapsed = (datetime.now(UTC) - last_msg).total_seconds()
            stale_data = elapsed > _STALE_DATA_THRESHOLD_SECONDS
        else:
            # No message ever received — consider stale if receiver has
            # been running for longer than the threshold.
            stale_data = uptime > _STALE_DATA_THRESHOLD_SECONDS

    degraded = False
    if _db_engine is not None and not database_ok:
        degraded = True
    if stale_data:
        degraded = True

    status = "degraded" if degraded else "ok"
    return {
        "status": status,
        "version": "0.1.0",
        "uptime_seconds": round(uptime, 1),
        "alerts_processed": _alerts_processed,
        "active_connections": _active_connections,
        "database_ok": database_ok,
        "loki_connected": loki_connected,
        "last_alert_received_at": last_alert_received_at,
        "stale_data": stale_data,
        "background_tasks": bg_status,
    }


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------


@router.get("/metrics", include_in_schema=False)
@limiter.exempt  # type: ignore[untyped-decorator]
async def metrics_endpoint(request: Request) -> Response:
    """Prometheus metrics exposition endpoint.

    Returns the current metric values in the Prometheus text exposition
    format (``text/plain`` with version negotiated by prometheus-client).
    Unauthenticated — scrapers need direct access.  Uses a dedicated
    :class:`CollectorRegistry` so it never interferes with other
    instrumented components.
    """
    from src.metrics import render  # noqa: PLC0415

    content, media_type = render()
    return Response(content=content, media_type=media_type)


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
@limiter.limit(RATE_LIMIT_READ)
async def get_alerts(
    request: Request,
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

    Raises
    ------
    HTTPException
        400 if ``severity`` or ``period`` is not in the allowed set.
    """
    if severity is not None and severity.upper() not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid severity '{severity}'. "
                f"Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
            ),
        )
    if period is not None and period not in _VALID_PERIODS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid period '{period}'. "
                f"Must be one of: {', '.join(sorted(_VALID_PERIODS))}"
            ),
        )

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
    _engine = _db_engine  # narrowed: not None (checked above)

    async with AsyncSession(_engine) as session:
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
@limiter.limit(RATE_LIMIT_READ)
async def get_alerts_count(
    request: Request,
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

    Raises
    ------
    HTTPException
        400 if ``period`` is not in the allowed set.
    """
    if period is not None and period not in _VALID_PERIODS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid period '{period}'. "
                f"Must be one of: {', '.join(sorted(_VALID_PERIODS))}"
            ),
        )

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
    _engine = _db_engine  # narrowed: not None (checked above)

    async with AsyncSession(_engine) as session:
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


_CSV_EXPORT_LIMIT = 50_000
_CSV_COLUMNS = [
    "timestamp",
    "device",
    "mnemonic",
    "classification",
    "message",
    "interface",
    "client",
    "as_name",
    "incident_id",
]


@router.get(
    "/api/alerts/export",
    dependencies=[Depends(require_api_key)],
)
async def export_alerts_csv(
    period: str | None = Query(
        default="today",
        description="Time filter: today, yesterday, 7d, 30d, 1y, all",
    ),
    format: str = Query(  # noqa: A002
        default="csv",
        description="Export format (currently only csv)",
    ),
) -> Response:
    """Export alerts as a CSV file for post-incident reporting.

    Returns a downloadable CSV containing up to 50,000 alert rows for the
    requested period.  The ``Content-Disposition`` header triggers a browser
    download with a date-stamped filename.

    Parameters
    ----------
    period:
        Time filter: today (default), yesterday, 7d, 30d, 1y, all.
    format:
        Export format.  Only ``csv`` is supported.

    Raises
    ------
    HTTPException
        400 if ``period`` or ``format`` is invalid.
    """
    if period is not None and period not in _VALID_PERIODS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid period '{period}'. "
                f"Must be one of: {', '.join(sorted(_VALID_PERIODS))}"
            ),
        )
    if format != "csv":
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format '{format}'. Only 'csv' is supported.",
        )

    # ── Fetch rows ────────────────────────────────────────────────────────
    rows: list[dict[str, Any]] = []

    if _db_engine is not None:
        from sqlalchemy import desc, select  # noqa: PLC0415
        from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

        from src.database.models import AlertLog  # noqa: PLC0415

        start, end = _period_to_time_range(period)
        async with AsyncSession(_db_engine) as session:
            stmt = (
                select(AlertLog)
                .order_by(desc(AlertLog.timestamp))
                .limit(_CSV_EXPORT_LIMIT)
            )
            if start is not None:
                stmt = stmt.where(AlertLog.timestamp >= start)
            if end is not None:
                stmt = stmt.where(AlertLog.timestamp < end)
            result = await session.execute(stmt)
            db_rows = result.scalars().all()

        for row in db_rows:
            rows.append(
                {
                    "timestamp": row.timestamp.isoformat() if row.timestamp else "",
                    "device": row.device_name,
                    "mnemonic": row.mnemonic,
                    "classification": row.classification,
                    "message": row.message,
                    "interface": row.interface_name,
                    "client": row.client_name,
                    "as_name": row.as_name,
                    "incident_id": row.incident_id or "",
                }
            )
    else:
        # Fallback: in-memory store (no period filter on this path)
        for alert in list(_alerts_store)[:_CSV_EXPORT_LIMIT]:
            rows.append(
                {
                    "timestamp": alert.get("timestamp", ""),
                    "device": alert.get("device", ""),
                    "mnemonic": alert.get("mnemonic", ""),
                    "classification": alert.get("classification", ""),
                    "message": alert.get("message", ""),
                    "interface": alert.get(
                        "interface", alert.get("interface_name", "")
                    ),
                    "client": alert.get("client", alert.get("client_name", "")),
                    "as_name": alert.get("as_name", ""),
                    "incident_id": alert.get("incident_id", ""),
                }
            )

    # ── Build CSV ─────────────────────────────────────────────────────────
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    csv_content = buf.getvalue()

    today_str = datetime.now(UTC).strftime("%Y-%m-%d")
    filename = f"netwatch-alerts-{today_str}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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

    # Fall through to DB lookup when the alert is not in the in-memory store
    if _db_engine is not None:
        try:
            numeric_id = int(alert_id)
        except (ValueError, TypeError):
            numeric_id = None

        if numeric_id is not None:
            from sqlalchemy import select  # noqa: PLC0415
            from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

            from src.database.models import AlertLog  # noqa: PLC0415

            async with AsyncSession(_db_engine) as session:
                row = (
                    await session.execute(
                        select(AlertLog).where(AlertLog.id == numeric_id)
                    )
                ).scalar_one_or_none()
            if row is not None:
                return {
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
        _prune_recovered_incidents()
        if _incidents_store and _db_engine is not None:
            await _prune_recovered_incidents_db()
        if _hardware_defects_as_noise:
            return [
                inc
                for inc in _incidents_store
                if inc.get("mnemonic") not in _SILENT_FAULT_MNEMONICS
            ]
        return list(_incidents_store)

    if _db_engine is None:
        return []

    from sqlalchemy import desc, select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    _engine = _db_engine  # narrowed: not None (checked above)

    _now_bdt = now_bdt_naive()
    _cutoff_24h = _now_bdt - timedelta(hours=24)

    async with AsyncSession(_engine) as session:
        # 1. Unresolved CRITICAL alerts (potential active incidents)
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
        critical_rows = list(result.scalars().all())

        # 2. Recovery events — needed to determine if a CRITICAL alert has
        #    been superseded by a later recovery, even when resolved_at was
        #    never set (pre-fix DB records).  Use the earliest critical
        #    row's timestamp as the floor so recovery events are never
        #    missed due to a fixed 24h cutoff.
        _recovery_mnemonics = sorted(
            _RECOVERY_MNEMONICS_WITH_UP | _RECOVERY_MNEMONICS_ALWAYS
        )
        _crit_ts = (r.timestamp for r in critical_rows if r.timestamp)
        _recov_cutoff = (
            min(_crit_ts, default=_cutoff_24h) if critical_rows else _cutoff_24h
        )
        recov_stmt = (
            select(AlertLog)
            .where(AlertLog.mnemonic.in_(_recovery_mnemonics))
            .where(AlertLog.timestamp >= _recov_cutoff)
            .order_by(desc(AlertLog.timestamp))
            .limit(500)
        )
        recov_result = await session.execute(recov_stmt)
        recovery_rows = list(recov_result.scalars().all())

    # Merge both sets, sort by timestamp DESC (newest first)
    rows: list[Any] = critical_rows + [
        r for r in recovery_rows if _is_recovery_event(r.mnemonic, r.message or "")
    ]
    rows.sort(
        key=lambda r: r.timestamp if r.timestamp else datetime.min,  # noqa: DTZ901
        reverse=True,
    )

    # Determine the latest state per device+key using a single pass.
    # Because the list is sorted by timestamp DESC, the FIRST row seen
    # for each key is the most recent event.  If that event is a recovery,
    # the session/interface is considered resolved even if older DOWN rows
    # exist.  If the most recent event is active (DOWN/fault), the incident
    # is kept regardless of any earlier UP rows.
    #
    # Resolution is DEVICE-SPECIFIC: the same interface name on different
    # routers connects to different far-end equipment (e.g., KKT-Core-1
    # TGE0/0/1/7 → Equinix vs KKT-Core-2 TGE0/0/1/7 → F@H-IPT-02).
    latest_state: dict[str, str] = {}  # key → "recovery" | "active"
    key_rows: dict[str, list[Any]] = {}  # key → list of non-recovery rows

    # NOTE: this first-pass key tracks RECOVERY STATE per fault and is
    # intentionally NOT the same as the second-pass card-dedup key. It is
    # broader for the non-interface else-branch (it folds in bgp_neighbor) so
    # a DOWN and its later UP land in the same recovery bucket. The UI card
    # grouping below keys via _incident_group_key, matching the live path.
    for row in rows:
        is_recov = _is_recovery_event(row.mnemonic, row.message or "")
        iface = row.interface_name or _extract_iface_from_msg(row.message or "")
        if row.mnemonic == "ADJCHANGE":
            disc = _bgp_discriminator(
                row.bgp_neighbor or "", row.as_number or 0, row.message or ""
            )
            key = f"{row.device_name}:BGP:{disc}"
        elif iface:
            key = f"{row.device_name}:{iface}"
        else:
            key = f"{row.device_name}:{row.mnemonic}:{row.bgp_neighbor or ''}"

        if key not in latest_state:
            latest_state[key] = "recovery" if is_recov else "active"

        if not is_recov:
            key_rows.setdefault(key, []).append(row)

    # Build incidents only for keys whose latest event is NOT a recovery.
    seen: dict[str, dict[str, Any]] = {}
    for key, state in latest_state.items():
        if state == "recovery":
            continue
        for row in key_rows.get(key, []):
            # Use the same canonical key as the live path (add_alert_to_store)
            # so card grouping/counts are identical before and after a restart.
            seen_key = _incident_group_key(
                row.device_name,
                row.mnemonic,
                row.interface_name or "",
                row.bgp_neighbor or "",
                row.as_number or 0,
                row.message or "",
            )
            if seen_key in seen:
                seen[seen_key]["alert_count"] = seen[seen_key].get("alert_count", 0) + 1
                continue
            inc = {
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
                "started_at": (row.timestamp.isoformat() if row.timestamp else ""),
                "last_alert": (row.timestamp.isoformat() if row.timestamp else ""),
                "interface": row.interface_name or "",
                "client": row.client_name or "",
                "as_name": row.as_name or "",
                "neighbor": getattr(row, "bgp_neighbor", "") or "",
                "as_number": getattr(row, "as_number", 0) or 0,
            }
            seen[seen_key] = inc

    # Restore ACK state from the incident_ack table so acknowledgments
    # survive server restarts.
    if seen and _db_engine is not None:
        try:
            from sqlalchemy import select as _ack_select  # noqa: PLC0415
            from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
                AsyncSession as _AckRestoreSession,
            )

            from src.database.models import (  # noqa: PLC0415
                IncidentAck as _RestoreAck,
            )

            inc_ids = [inc["id"] for inc in seen.values()]
            async with _AckRestoreSession(_db_engine) as ack_session:
                ack_rows = (
                    (
                        await ack_session.execute(
                            _ack_select(_RestoreAck)
                            .where(_RestoreAck.incident_id.in_(inc_ids))
                            .order_by(_RestoreAck.created_at.desc())
                        )
                    )
                    .scalars()
                    .all()
                )

            acked_map: dict[str, Any] = {}
            for ack_row in ack_rows:
                if ack_row.incident_id not in acked_map:
                    acked_map[ack_row.incident_id] = ack_row

            for inc in seen.values():
                ack_data = acked_map.get(inc["id"])
                if ack_data is not None:
                    inc["acknowledged"] = True
                    inc["acknowledged_at"] = ack_data.created_at.isoformat()
                    inc["acknowledged_by"] = ack_data.operator_name
                    inc["ack_comment"] = ack_data.comment
        except Exception:  # noqa: BLE001
            logger.warning("Failed to restore ACK state from DB", exc_info=True)

    # Cache synthesized incidents into the in-memory store so they are
    # available for acknowledge/resolve operations without another DB hit.
    if seen:
        _incidents_store.clear()
        for inc_item in seen.values():
            _incidents_store.append(inc_item)

    return list(seen.values())


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


@router.post(
    "/api/incidents/{incident_id}/acknowledge",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def acknowledge_incident(
    request: Request,
    incident_id: str,
    body: IncidentAckRequest | None = None,
) -> dict[str, Any]:
    """Acknowledge an active incident with operator name and comment.

    Records the acknowledgement in the audit trail (incident_ack table)
    and updates the in-memory incident state.

    Parameters
    ----------
    incident_id:
        Unique incident identifier.
    body:
        Optional ``operator_name`` and ``comment``.

    Raises
    ------
    HTTPException
        401 if API-key auth is enabled and the header is missing/wrong.
        404 if the incident is not found.
    """
    now = now_bdt_naive()
    ack_body = body or IncidentAckRequest()
    for incident in _incidents_store:
        if str(incident.get("id")) == incident_id:
            incident["acknowledged"] = True
            incident["acknowledged_at"] = now.isoformat()
            incident["acknowledged_by"] = ack_body.operator_name
            incident["ack_comment"] = ack_body.comment
            # Cancel any pending escalation for this incident's device+mnemonic
            # so a human ACK actually stops the 15-minute unacked escalation timer.
            if _escalation_engine is not None:
                _escalation_engine.acknowledge(
                    str(incident.get("device", "")),
                    str(incident.get("mnemonic", "")),
                )
            if _db_engine:
                from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
                    AsyncSession as _AckSession,
                )

                from src.database.models import (  # noqa: PLC0415
                    IncidentAck as _IncidentAck,
                )

                try:
                    async with _AckSession(_db_engine) as session:
                        ack = _IncidentAck(
                            incident_id=incident_id,
                            operator_name=ack_body.operator_name,
                            comment=ack_body.comment,
                            created_at=now,
                        )
                        session.add(ack)

                        from sqlalchemy import update  # noqa: PLC0415

                        from src.database.models import (  # noqa: PLC0415
                            AlertLog as _AckAlertLog,
                        )

                        alert_id_str = incident_id.replace("ALERT-", "")
                        if alert_id_str.isdigit():
                            await session.execute(
                                update(_AckAlertLog)
                                .where(_AckAlertLog.id == int(alert_id_str))
                                .values(acknowledged_at=now)
                            )
                        elif incident_id.startswith("INC-"):
                            await session.execute(
                                update(_AckAlertLog)
                                .where(
                                    _AckAlertLog.incident_id == incident_id,
                                    _AckAlertLog.acknowledged_at.is_(None),
                                )
                                .values(acknowledged_at=now)
                            )

                        await session.commit()
                except Exception:  # noqa: BLE001
                    import logging  # noqa: PLC0415

                    logging.getLogger(__name__).warning(
                        "Failed to persist ack for %s", incident_id
                    )
            return {
                "status": "acknowledged",
                "incident_id": incident_id,
                "acknowledged_at": now.isoformat(),
                "acknowledged_by": ack_body.operator_name,
                "comment": ack_body.comment,
            }
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@router.get("/api/incidents/{incident_id}/acks")
async def get_incident_acks(incident_id: str) -> list[dict[str, Any]]:
    """Get the acknowledgement audit trail for an incident.

    Returns
    -------
    list[dict]
        Ack records for the incident, ordered newest-first.
    """
    if not _db_engine:
        return []
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession as _AckListSession  # noqa: PLC0415

    from src.database.models import IncidentAck as _IncidentAckModel  # noqa: PLC0415

    try:
        async with _AckListSession(_db_engine) as session:
            stmt = (
                select(_IncidentAckModel)
                .where(_IncidentAckModel.incident_id == incident_id)
                .order_by(_IncidentAckModel.created_at.desc())
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "incident_id": row.incident_id,
                    "operator_name": row.operator_name,
                    "comment": row.comment,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# Shift handoff
# ---------------------------------------------------------------------------


@router.get("/api/shift/current")
async def get_current_shift() -> dict[str, Any]:
    """Get current shift info and summary since shift start.

    Returns
    -------
    dict
        ``shift_name``, ``shift_start``, ``shift_end_hour``, ``shift_end_min``,
        ``critical_since_shift``, ``warning_since_shift``, ``info_since_shift``,
        ``open_incidents``, ``current_time_bdt``.
    """
    now = datetime.now(timezone(timedelta(hours=6)))  # BDT
    hour = now.hour
    minute = now.minute
    current_time_minutes = hour * 60 + minute

    if 480 <= current_time_minutes < 900:  # 08:00 - 15:00
        shift_name = "morning"
        shift_start_hour, shift_start_min = 8, 0
        shift_end_hour, shift_end_min = 15, 0
    elif 900 <= current_time_minutes < 1350:  # 15:00 - 22:30
        shift_name = "evening"
        shift_start_hour, shift_start_min = 15, 0
        shift_end_hour, shift_end_min = 22, 30
    else:  # 22:30 - 08:00
        shift_name = "night"
        shift_start_hour, shift_start_min = 22, 30
        shift_end_hour, shift_end_min = 8, 0

    shift_start_today = now.replace(
        hour=shift_start_hour, minute=shift_start_min, second=0, microsecond=0
    )
    if shift_name == "night" and current_time_minutes < 480:
        shift_start_today = shift_start_today - timedelta(days=1)

    shift_start_utc = shift_start_today.astimezone(UTC)
    shift_start_iso = shift_start_today.isoformat()
    shift_start_utc_iso = shift_start_utc.isoformat()
    critical_since_shift = 0
    warning_since_shift = 0
    info_since_shift = 0
    for alert in _alerts_store:
        ts = alert.get("timestamp", "")
        if ts >= shift_start_utc_iso or ts >= shift_start_iso:
            cls = alert.get("classification", "")
            if cls == "CRITICAL":
                critical_since_shift += 1
            elif cls == "WARNING":
                warning_since_shift += 1
            elif cls == "INFO":
                info_since_shift += 1

    open_incidents = sum(1 for inc in _incidents_store if not inc.get("acknowledged"))

    return {
        "shift_name": shift_name,
        "shift_start": shift_start_iso,
        "shift_end_hour": shift_end_hour,
        "shift_end_min": shift_end_min,
        "critical_since_shift": critical_since_shift,
        "warning_since_shift": warning_since_shift,
        "info_since_shift": info_since_shift,
        "open_incidents": open_incidents,
        "current_time_bdt": now.isoformat(),
    }


@router.get("/api/shift/handoffs")
async def get_shift_handoffs(
    limit: int = Query(default=10, ge=1, le=50),
) -> list[dict[str, Any]]:
    """Get recent shift handoff notes.

    Parameters
    ----------
    limit:
        Maximum number of records to return (1-50, default 10).

    Returns
    -------
    list[dict]
        Handoff records, ordered newest-first.
    """
    if not _db_engine:
        return []
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
        AsyncSession as _HandoffSession,
    )

    from src.database.models import ShiftHandoff as _ShiftHandoff  # noqa: PLC0415

    try:
        async with _HandoffSession(_db_engine) as session:
            stmt = (
                select(_ShiftHandoff)
                .order_by(_ShiftHandoff.created_at.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "shift_name": row.shift_name,
                    "shift_date": row.shift_date,
                    "operator_name": row.operator_name,
                    "notes": row.notes,
                    "open_incidents": row.open_incidents,
                    "critical_count": row.critical_count,
                    "warning_count": row.warning_count,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ]
    except Exception:  # noqa: BLE001
        return []


@router.post(
    "/api/shift/handoff",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def create_shift_handoff(
    request: Request, body: ShiftHandoffCreate
) -> dict[str, Any]:
    """Create a shift handoff note.

    Protected when ``API_KEY`` is configured; open when ``API_KEY`` is unset.

    Parameters
    ----------
    body:
        ``shift_name``, ``shift_date``, ``operator_name`` (required);
        ``notes``, ``open_incidents``, ``critical_count``, ``warning_count``
        (optional).

    Returns
    -------
    dict
        ``status``, ``id``, ``shift_name``, ``operator_name``.

    Raises
    ------
    HTTPException
        500 if the DB write fails.
    """
    now = now_bdt_naive()
    if not _db_engine:
        return {"status": "error", "detail": "Database not available"}
    from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
        AsyncSession as _HandoffCreateSession,
    )

    from src.database.models import (  # noqa: PLC0415
        ShiftHandoff as _ShiftHandoffModel,
    )

    try:
        async with _HandoffCreateSession(_db_engine) as session:
            handoff = _ShiftHandoffModel(
                shift_name=body.shift_name,
                shift_date=body.shift_date,
                operator_name=body.operator_name,
                notes=body.notes,
                open_incidents=body.open_incidents,
                critical_count=body.critical_count,
                warning_count=body.warning_count,
                created_at=now,
            )
            session.add(handoff)
            await session.flush()
            handoff_id = handoff.id
            await session.commit()
            return {
                "status": "created",
                "id": handoff_id,
                "shift_name": body.shift_name,
                "operator_name": body.operator_name,
            }
    except Exception as exc:  # noqa: BLE001
        import logging  # noqa: PLC0415

        logging.getLogger(__name__).exception("shift handoff DB write failed")
        raise HTTPException(
            status_code=500, detail="Failed to save handoff note"
        ) from exc


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


async def _stats_by_period(period_name: str, period_key: str) -> dict[str, Any]:
    """Return alert counts grouped by classification for a given period.

    When ``_db_engine`` is set, queries the DB with the appropriate time
    bounds (same logic as ``get_alerts_count``).  Falls back to the
    in-memory store with timestamp filtering when no DB is available.

    Parameters
    ----------
    period_name:
        Human label returned in the response (e.g. ``"daily"``).
    period_key:
        Key passed to ``_period_to_time_range`` (e.g. ``"today"``).

    Returns
    -------
    dict with keys: period, counts, total, hourly_buckets, per_device.
    hourly_buckets is a list of 24 dicts (one per hour-of-day) each with
    hour plus one key per classification.  per_device is the top-10 devices
    by alert count, sorted descending, excluding blank device names.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]

    def _empty_buckets() -> list[dict[str, int]]:
        return [
            {
                "hour": h,
                "CRITICAL": 0,
                "WARNING": 0,
                "INFO": 0,
                "NOISE": 0,
                "USER_LOGIN": 0,
            }
            for h in range(24)
        ]

    def _finalize_per_device(device_counts: dict[str, int]) -> list[dict[str, Any]]:
        return [
            {"device": k, "count": v}
            for k, v in sorted(device_counts.items(), key=lambda kv: (-kv[1], kv[0]))[
                :10
            ]
        ]

    if _db_engine is not None:
        from sqlalchemy import func, select  # noqa: PLC0415
        from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

        from src.database.models import AlertLog  # noqa: PLC0415

        start, end = _period_to_time_range(period_key)
        async with AsyncSession(_db_engine) as session:
            # Classification counts
            stmt = select(AlertLog.classification, func.count(AlertLog.id)).group_by(
                AlertLog.classification
            )
            if start is not None:
                stmt = stmt.where(AlertLog.timestamp >= start)
            if end is not None:
                stmt = stmt.where(AlertLog.timestamp < end)
            result = await session.execute(stmt)
            rows = result.all()

            # Hourly breakdown by classification
            hour_col = func.cast(
                func.strftime("%H", AlertLog.timestamp), type_=AlertLog.id.type
            )
            hour_stmt = select(
                hour_col.label("hour"),
                AlertLog.classification,
                func.count(AlertLog.id),
            ).group_by("hour", AlertLog.classification)
            if start is not None:
                hour_stmt = hour_stmt.where(AlertLog.timestamp >= start)
            if end is not None:
                hour_stmt = hour_stmt.where(AlertLog.timestamp < end)
            hour_result = await session.execute(hour_stmt)
            hour_rows = hour_result.all()

            # Per-device counts
            dev_stmt = (
                select(AlertLog.device_name, func.count(AlertLog.id))
                .where(AlertLog.device_name != "")
                .group_by(AlertLog.device_name)
            )
            if start is not None:
                dev_stmt = dev_stmt.where(AlertLog.timestamp >= start)
            if end is not None:
                dev_stmt = dev_stmt.where(AlertLog.timestamp < end)
            dev_result = await session.execute(dev_stmt)
            dev_rows = dev_result.all()

        counts: dict[str, int] = dict.fromkeys(classifications, 0)
        for cls, cnt in rows:
            if cls in counts:
                counts[cls] = cnt

        buckets: list[dict[str, int]] = _empty_buckets()
        for raw_hour, cls, cnt in hour_rows:
            h = int(raw_hour)
            if 0 <= h <= 23 and cls in classifications:
                buckets[h][cls] = int(cnt)

        # device_name is already filtered non-blank by the SQL WHERE clause
        device_counts: dict[str, int] = {
            dev_name: int(cnt) for dev_name, cnt in dev_rows
        }

        return {
            "period": period_name,
            "counts": counts,
            "total": sum(counts.values()),
            "hourly_buckets": buckets,
            "per_device": _finalize_per_device(device_counts),
        }

    # Fallback: in-memory store with timestamp filtering
    start, end = _period_to_time_range(period_key)
    counts = dict.fromkeys(classifications, 0)
    buckets = _empty_buckets()
    device_counts = {}
    for alert in _alerts_store:
        raw_ts = alert.get("timestamp", "")
        ts: datetime | None = None
        if start is not None or end is not None:
            try:
                parsed = (
                    datetime.fromisoformat(raw_ts)
                    if isinstance(raw_ts, str)
                    else raw_ts
                )
                # Strip tzinfo to match the naive bounds from _period_to_time_range
                if parsed.tzinfo is not None:
                    parsed = parsed.replace(tzinfo=None)
                if start is not None and parsed < start:
                    continue
                if end is not None and parsed >= end:
                    continue
                ts = parsed
            except (ValueError, AttributeError, TypeError):
                continue
        # _stats_by_period is only ever called with bounded periods
        # ("today"/"7d"), so the unbounded case leaves ts=None and simply
        # skips hourly bucketing — counts/per_device still accumulate.

        cls = alert.get("classification", "")
        if cls in counts:
            counts[cls] += 1

        if ts is not None and cls in classifications:
            buckets[ts.hour][cls] += 1

        dev = alert.get("device", "")
        if dev:
            device_counts[dev] = device_counts.get(dev, 0) + 1

    return {
        "period": period_name,
        "counts": counts,
        "total": sum(counts.values()),
        "hourly_buckets": buckets,
        "per_device": _finalize_per_device(device_counts),
    }


@router.get("/api/stats/daily")
@limiter.limit(RATE_LIMIT_READ)
async def get_stats_daily(request: Request) -> dict[str, Any]:
    """Return daily aggregated statistics.

    Returns a dict with alert counts by classification for today.
    When ``_db_engine`` is set, queries the DB with today's time bounds.
    """
    return await _stats_by_period("daily", "today")


@router.get("/api/stats/weekly")
@limiter.limit(RATE_LIMIT_READ)
async def get_stats_weekly(request: Request) -> dict[str, Any]:
    """Return weekly aggregated statistics.

    Returns a dict with alert counts by classification for the past 7 days.
    When ``_db_engine`` is set, queries the DB with 7-day time bounds.
    """
    return await _stats_by_period("weekly", "7d")


@router.get("/api/stats/heatmap")
async def get_stats_heatmap(
    period: str = Query(default="30d", description="Time period: 7d, 30d, 1y, all"),
) -> dict[str, Any]:
    """Return a 7x24 alert heatmap grouped by day-of-week and hour-of-day.

    Each cell ``data[day][hour]`` contains the number of alerts that occurred
    during that (day, hour) combination over the requested period.

    Day indices: 0=Monday, 1=Tuesday, ..., 6=Sunday.
    Hour indices: 0-23 (BDT, UTC+6).

    Parameters
    ----------
    period:
        Time filter: 7d, 30d (default), 1y, all.

    Returns
    -------
    dict
        ``data`` — 7x24 integer matrix, ``max_count`` — highest cell value,
        ``period`` — echo of the requested period.

    Raises
    ------
    HTTPException
        400 if ``period`` is not in the allowed set.
    """
    allowed = frozenset({"7d", "30d", "1y", "all"})
    if period not in allowed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid period '{period}'. "
                f"Must be one of: {', '.join(sorted(allowed))}"
            ),
        )

    # Initialise 7 x 24 zero matrix (Mon=0 .. Sun=6, hours 0-23)
    data: list[list[int]] = [[0] * 24 for _ in range(7)]

    if _db_engine is not None:
        from sqlalchemy import func, select  # noqa: PLC0415
        from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

        from src.database.models import AlertLog  # noqa: PLC0415

        start, _ = _period_to_time_range(period)
        async with AsyncSession(_db_engine) as session:
            # SQLite strftime('%w') returns 0=Sunday..6=Saturday.
            dow_col = func.cast(
                func.strftime("%w", AlertLog.timestamp), type_=AlertLog.id.type
            )
            hour_col = func.cast(
                func.strftime("%H", AlertLog.timestamp), type_=AlertLog.id.type
            )
            stmt = select(
                dow_col.label("dow"),
                hour_col.label("hour"),
                func.count(AlertLog.id).label("cnt"),
            ).group_by("dow", "hour")

            if start is not None:
                stmt = stmt.where(AlertLog.timestamp >= start)

            result = await session.execute(stmt)
            rows = result.all()

        for sqlite_dow, hour, cnt in rows:
            # SQLite: 0=Sun,1=Mon..6=Sat → Python: Mon=0..Sun=6
            py_dow = (int(sqlite_dow) - 1) % 7
            data[py_dow][int(hour)] = int(cnt)
    else:
        # Fallback: count from in-memory store
        start, _ = _period_to_time_range(period)
        for alert in _alerts_store:
            raw_ts = alert.get("timestamp", "")
            try:
                ts = (
                    datetime.fromisoformat(raw_ts)
                    if isinstance(raw_ts, str)
                    else raw_ts
                )
                if ts.tzinfo is not None:
                    ts = ts.replace(tzinfo=None)
                if start is not None and ts < start:
                    continue
            except (ValueError, AttributeError, TypeError):
                continue
            # weekday(): Monday=0 .. Sunday=6
            data[ts.weekday()][ts.hour] += 1

    max_count = max(max(row) for row in data)
    return {"data": data, "max_count": max_count, "period": period}


async def _db_period_counts(fmt: str) -> dict[str, dict[str, int]] | None:
    """Group ``AlertLog`` counts by classification within ``strftime(fmt)`` buckets.

    Returns ``{bucket_key: {classification: count}}`` from the DB, or ``None``
    when no DB engine is configured (the caller then falls back to the in-memory
    store).  ``fmt`` is a SQLite strftime format, e.g. ``"%Y-%m"`` (month) or
    ``"%Y"`` (year).
    """
    if _db_engine is None:
        return None
    from sqlalchemy import func, select  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.database.models import AlertLog  # noqa: PLC0415

    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    buckets: dict[str, dict[str, int]] = {}
    async with AsyncSession(_db_engine) as session:
        stmt = select(
            func.strftime(fmt, AlertLog.timestamp).label("bucket"),
            AlertLog.classification,
            func.count(AlertLog.id),
        ).group_by("bucket", AlertLog.classification)
        rows = (await session.execute(stmt)).all()
    for bucket, cls, cnt in rows:
        if bucket is None:
            continue
        b = buckets.setdefault(str(bucket), dict.fromkeys(classifications, 0))
        if cls in b:
            b[cls] = cnt
    return buckets


@router.get("/api/stats/monthly")
@limiter.limit(RATE_LIMIT_READ)
async def get_stats_monthly(request: Request) -> dict[str, Any]:
    """Return monthly aggregated statistics.

    Aggregates daily alert counts grouped by calendar month for all alerts
    in the in-memory store.  Each entry in ``months`` covers one month.

    Returns
    -------
    dict
        ``period`` set to ``"monthly"``, ``months`` list (each with
        ``year``, ``month``, and per-classification ``counts``), ``total``.
    """
    monthly = await _db_period_counts("%Y-%m")
    if monthly is None:
        classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
        monthly = {}
        for alert in _alerts_store:
            raw_ts = alert.get("timestamp", "")
            try:
                ts = (
                    datetime.fromisoformat(raw_ts)
                    if isinstance(raw_ts, str)
                    else raw_ts
                )
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
@limiter.limit(RATE_LIMIT_READ)
async def get_stats_yearly(request: Request) -> dict[str, Any]:
    """Return yearly aggregated statistics.

    Aggregates monthly counts into per-year totals.

    Returns
    -------
    dict
        ``period`` set to ``"yearly"``, ``years`` list (each with
        ``year`` and per-classification ``counts``), ``total``.
    """
    yearly = await _db_period_counts("%Y")
    if yearly is None:
        classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
        yearly = {}
        for alert in _alerts_store:
            raw_ts = alert.get("timestamp", "")
            try:
                ts = (
                    datetime.fromisoformat(raw_ts)
                    if isinstance(raw_ts, str)
                    else raw_ts
                )
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


@router.post(
    "/api/settings/hardware-noise",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def set_hardware_noise_setting(
    request: Request, enabled: bool = True
) -> dict[str, bool]:
    """Toggle the hardware-defects-as-noise setting.

    Protected when ``API_KEY`` is configured; open when ``API_KEY`` is unset.

    When enabled (default), RX_FAULT/SIGNAL/RFI events on backbone bundle
    member interfaces are reclassified as NOISE and excluded from active
    incidents.

    The new value is persisted to the database (``app_setting`` table under
    the key ``"hardware_defects_as_noise"``) and the in-memory flag is
    updated atomically so the hot path always reads from memory.
    """
    global _hardware_defects_as_noise  # noqa: PLW0603
    _hardware_defects_as_noise = enabled
    if enabled:
        kept = [
            inc
            for inc in _incidents_store
            if inc.get("mnemonic") not in _SILENT_FAULT_MNEMONICS
        ]
        _incidents_store.clear()
        _incidents_store.extend(kept)
    if _db_engine is not None:
        try:
            from sqlalchemy.ext.asyncio import (
                AsyncSession as _AsyncSession,  # noqa: PLC0415
            )

            from src.database.crud import set_app_setting  # noqa: PLC0415

            async with _AsyncSession(_db_engine) as session:
                await set_app_setting(
                    session,
                    "hardware_defects_as_noise",
                    "true" if enabled else "false",
                )
                await session.commit()
        except Exception:  # noqa: BLE001
            logger.warning("Failed to persist setting to DB", exc_info=True)
    return {"hardware_defects_as_noise": _hardware_defects_as_noise}


@router.get("/api/settings/maxpfx-alerts")
async def get_maxpfx_alerts_setting() -> dict[str, bool]:
    """Return whether MAXPFX alerts are enabled (True) or muted (False)."""
    return {"maxpfx_alerts_enabled": _maxpfx_alerts_enabled}


@router.post(
    "/api/settings/maxpfx-alerts",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def set_maxpfx_alerts_setting(
    request: Request, enabled: bool = True
) -> dict[str, bool]:
    """Toggle MAXPFX alerts.

    Protected when ``API_KEY`` is configured; open when ``API_KEY`` is unset.

    When disabled, MAXPFX (BGP max-prefix) events are muted across all live
    surfaces — Discord/Telegram, audio, active-incident card, and the live
    dashboard feed — but are still written to the database for audit/history.
    On disable, existing MAXPFX incident cards are pruned from the in-memory
    store.  The new value is persisted to the ``app_setting`` table under the
    key ``"maxpfx_alerts_enabled"``.
    """
    global _maxpfx_alerts_enabled  # noqa: PLW0603
    _maxpfx_alerts_enabled = enabled
    if not enabled:
        kept = [inc for inc in _incidents_store if inc.get("mnemonic") != "MAXPFX"]
        _incidents_store.clear()
        _incidents_store.extend(kept)
    if _db_engine is not None:
        try:
            from sqlalchemy.ext.asyncio import (
                AsyncSession as _AsyncSession,  # noqa: PLC0415
            )

            from src.database.crud import set_app_setting  # noqa: PLC0415

            async with _AsyncSession(_db_engine) as session:
                await set_app_setting(
                    session,
                    "maxpfx_alerts_enabled",
                    "true" if enabled else "false",
                )
                await session.commit()
        except Exception:  # noqa: BLE001
            logger.warning("Failed to persist setting to DB", exc_info=True)
    return {"maxpfx_alerts_enabled": _maxpfx_alerts_enabled}


# ---------------------------------------------------------------------------
# Notification settings
# ---------------------------------------------------------------------------


@router.get("/api/settings/notifications")
async def get_notification_settings() -> dict[str, Any]:
    """Return current notification preferences."""
    from src.config import get_settings  # noqa: PLC0415

    s = get_settings()
    return {
        "discord_enabled": s.discord_enabled,
        "telegram_enabled": s.telegram_enabled,
        "notify_severity": getattr(s, "notify_severity", "CRITICAL"),
        "dedup_window": s.dedup_window_seconds,
    }


@router.post(
    "/api/settings/notifications",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def set_notification_settings(
    request: Request,
    discord_enabled: bool | None = None,
    telegram_enabled: bool | None = None,
    dedup_window: int | None = None,
    notify_severity: str | None = None,
) -> dict[str, Any]:
    """Update notification preferences at runtime.

    Only updates fields that are provided. Persists to the DB app_setting
    table so values survive restart.
    """
    from src.config import get_settings  # noqa: PLC0415

    s = get_settings()
    if discord_enabled is not None:
        object.__setattr__(s, "discord_enabled", discord_enabled)
    if telegram_enabled is not None:
        object.__setattr__(s, "telegram_enabled", telegram_enabled)
    if dedup_window is not None and 30 <= dedup_window <= 3600:
        object.__setattr__(s, "dedup_window_seconds", dedup_window)
    if notify_severity is not None and notify_severity in (
        "CRITICAL",
        "WARNING",
        "INFO",
    ):
        object.__setattr__(s, "notify_severity", notify_severity)

    if _db_engine is not None:
        try:
            from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
                AsyncSession as _NotifSession,
            )

            from src.database.crud import set_app_setting  # noqa: PLC0415

            async with _NotifSession(_db_engine) as session:
                if discord_enabled is not None:
                    await set_app_setting(
                        session, "discord_enabled", str(s.discord_enabled).lower()
                    )
                if telegram_enabled is not None:
                    await set_app_setting(
                        session, "telegram_enabled", str(s.telegram_enabled).lower()
                    )
                if dedup_window is not None:
                    await set_app_setting(
                        session, "dedup_window_seconds", str(s.dedup_window_seconds)
                    )
                if notify_severity is not None:
                    await set_app_setting(
                        session,
                        "notify_severity",
                        getattr(s, "notify_severity", "CRITICAL"),
                    )
                await session.commit()
        except Exception:  # noqa: BLE001
            logger.warning("Failed to persist setting to DB", exc_info=True)

    return {
        "discord_enabled": s.discord_enabled,
        "telegram_enabled": s.telegram_enabled,
        "dedup_window": s.dedup_window_seconds,
        "notify_severity": getattr(s, "notify_severity", "CRITICAL"),
    }


# ---------------------------------------------------------------------------
# Sound & UI preferences (DB-persisted, survive restart / cross-browser)
# ---------------------------------------------------------------------------

_sound_prefs: dict[str, bool] = {
    "sound_enabled": True,
    "sound_critical": True,
    "sound_warning": True,
    "sound_recovery": True,
    "repeat_alarm": True,
    "browser_notif": False,
}


@router.get("/api/settings/sound")
async def get_sound_settings() -> dict[str, bool]:
    """Return current sound and UI notification preferences."""
    return dict(_sound_prefs)


@router.post(
    "/api/settings/sound",
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def set_sound_settings(
    request: Request,
    sound_enabled: bool | None = None,
    sound_critical: bool | None = None,
    sound_warning: bool | None = None,
    sound_recovery: bool | None = None,
    repeat_alarm: bool | None = None,
    browser_notif: bool | None = None,
) -> dict[str, bool]:
    """Update sound/UI preferences. Only updates fields that are provided.

    Persisted to the ``app_setting`` table so values survive restart and
    are consistent across all browsers/clients.
    """
    updates: dict[str, bool] = {}
    if sound_enabled is not None:
        updates["sound_enabled"] = sound_enabled
    if sound_critical is not None:
        updates["sound_critical"] = sound_critical
    if sound_warning is not None:
        updates["sound_warning"] = sound_warning
    if sound_recovery is not None:
        updates["sound_recovery"] = sound_recovery
    if repeat_alarm is not None:
        updates["repeat_alarm"] = repeat_alarm
    if browser_notif is not None:
        updates["browser_notif"] = browser_notif

    _sound_prefs.update(updates)

    if _db_engine is not None and updates:
        try:
            from sqlalchemy.ext.asyncio import (  # noqa: PLC0415
                AsyncSession as _SoundSession,
            )

            from src.database.crud import set_app_setting  # noqa: PLC0415

            async with _SoundSession(_db_engine) as session:
                for key, val in updates.items():
                    await set_app_setting(session, key, str(val).lower())
                await session.commit()
        except Exception:  # noqa: BLE001
            logger.warning("Failed to persist sound setting to DB", exc_info=True)

    return dict(_sound_prefs)


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
            continue
    return active


@router.post(
    "/api/maintenance",
    status_code=201,
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def create_maintenance_window(
    request: Request,
    body: MaintenanceWindowCreate,
) -> dict[str, Any]:
    """Create a new maintenance window.

    Protected when ``API_KEY`` is configured; open when ``API_KEY`` is unset.

    Parameters
    ----------
    body:
        ``device_name``, ``start_time``, ``end_time`` (required);
        ``reason``, ``created_by`` (optional).

    Returns
    -------
    dict
        The created maintenance window record including its assigned ``id``.

    Notes
    -----
    Write-through: the window is persisted to the DB (when available) and
    the in-memory cache is updated atomically so the hot path reads from
    memory.  The DB primary key becomes the canonical ``id``; when no DB is
    available the legacy integer counter is used as a fallback.
    """
    global _maintenance_id_counter  # noqa: PLW0603

    if _db_engine is not None:
        try:
            from sqlalchemy.ext.asyncio import (
                AsyncSession as _AsyncSession,  # noqa: PLC0415
            )

            from src.database.crud import (  # noqa: PLC0415
                create_maintenance_window as _db_create,
            )

            async with _AsyncSession(_db_engine) as session:
                db_window = await _db_create(
                    session,
                    device_name=body.device_name,
                    start_time=body.start_time,
                    end_time=body.end_time,
                    reason=body.reason,
                    created_by=body.created_by,
                )
                # Capture id BEFORE commit() — commit() expires the ORM
                # object, and accessing id after session closes would
                # raise DetachedInstanceError.
                window_id = db_window.id
                await session.commit()
        except Exception:  # noqa: BLE001
            # DB unavailable — fall back to the legacy in-memory counter
            _maintenance_id_counter += 1
            window_id = _maintenance_id_counter
    else:
        _maintenance_id_counter += 1
        window_id = _maintenance_id_counter

    window: dict[str, Any] = {
        "id": window_id,
        "device_name": body.device_name,
        "start_time": body.start_time.isoformat(),
        "end_time": body.end_time.isoformat(),
        "reason": body.reason,
        "created_by": body.created_by,
    }
    _maintenance_store.append(window)
    return window


@router.delete(
    "/api/maintenance/{window_id}",
    status_code=200,
    dependencies=[Depends(require_api_key)],
)
@limiter.limit(RATE_LIMIT_MUTATING)
async def delete_maintenance_window(request: Request, window_id: int) -> dict[str, Any]:
    """Delete a maintenance window by ID.

    Protected when ``API_KEY`` is configured; open when ``API_KEY`` is unset.

    Parameters
    ----------
    window_id:
        The numeric ID of the maintenance window to delete.

    Raises
    ------
    HTTPException
        401 if API-key auth is enabled and the header is missing/wrong.
        404 if the window is not found (in-memory cache is the authoritative
        check when no DB is available; DB check applies when the engine is set).

    Returns
    -------
    dict
        ``{"status": "deleted", "id": window_id}``

    Notes
    -----
    Write-through: the window is removed from the DB (when available) and
    the in-memory cache is updated atomically.
    """
    # Remove from in-memory cache first (always the fast check)
    in_memory_found = False
    for window in list(_maintenance_store):
        if window.get("id") == window_id:
            _maintenance_store.remove(window)
            in_memory_found = True
            break

    # Also delete from DB (best-effort; doesn't affect the 404 decision below)
    if _db_engine is not None:
        try:
            from sqlalchemy.ext.asyncio import (
                AsyncSession as _AsyncSession,  # noqa: PLC0415
            )

            from src.database.crud import (  # noqa: PLC0415
                delete_maintenance_window as _db_delete,
            )

            async with _AsyncSession(_db_engine) as session:
                await _db_delete(session, window_id)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            import logging  # noqa: PLC0415

            # Non-fatal: the in-memory cache is already updated, but the row
            # survives in the DB and will reappear on the next startup reload.
            # Surface it so operators can reconcile rather than silently drop.
            logging.getLogger(__name__).warning(
                "DB delete for maintenance window %d failed: %s — "
                "the window may reappear after a restart",
                window_id,
                exc,
            )

    if not in_memory_found:
        raise HTTPException(
            status_code=404, detail=f"Maintenance window {window_id} not found"
        )
    return {"status": "deleted", "id": window_id}


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
    # Build name alias map: topology_name ↔ device_map_name for the same IP
    _name_aliases: dict[str, str] = {}
    for _topo_ip, _topo_entry in NETWORK_TOPOLOGY.items():
        _dm = DEVICE_MAP.get(_topo_ip)
        if _dm and _dm.name != _topo_entry.name:
            _name_aliases[_dm.name] = _topo_entry.name
            _name_aliases[_topo_entry.name] = _dm.name

    # Compute live device status from DB (authoritative) + in-memory overlay
    _dev_severity: dict[str, str] = {}
    _dev_crit_ifaces: dict[str, set[str]] = {}

    if _db_engine is not None:
        try:
            from sqlalchemy import case, func, select  # noqa: PLC0415
            from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

            from src.database.models import AlertLog  # noqa: PLC0415

            now_bdt = datetime.now(_BDT).replace(tzinfo=None)
            cutoff = now_bdt - timedelta(hours=24)
            async with AsyncSession(_db_engine) as session:
                # Worst severity per device in last 24h
                sev_col = case(
                    (AlertLog.classification == "CRITICAL", 2),
                    (AlertLog.classification == "WARNING", 1),
                    else_=0,
                )
                stmt = (
                    select(
                        AlertLog.device_name,
                        func.max(sev_col).label("worst"),
                    )
                    .where(AlertLog.timestamp >= cutoff)
                    .group_by(AlertLog.device_name)
                )
                rows = (await session.execute(stmt)).all()
                for dev_name, worst in rows:
                    if worst == 2:
                        _dev_severity[dev_name] = "critical"
                    elif worst == 1:
                        _dev_severity[dev_name] = "warning"
                    else:
                        _dev_severity[dev_name] = "ok"

                # Critical interfaces for link status
                crit_stmt = (
                    select(AlertLog.device_name, AlertLog.interface_name)
                    .where(AlertLog.classification == "CRITICAL")
                    .where(AlertLog.resolved_at.is_(None))
                    .where(AlertLog.timestamp >= cutoff)
                    .where(AlertLog.interface_name != "")
                )
                crit_rows = (await session.execute(crit_stmt)).all()
                for dev_name, iface in crit_rows:
                    _dev_crit_ifaces.setdefault(dev_name, set()).add(iface)
        except Exception:  # noqa: BLE001, S110
            pass  # fall through to in-memory scan

    # Propagate status to aliased names (DB name ↔ topology name)
    for src_name, tgt_name in list(_name_aliases.items()):
        if src_name in _dev_severity and tgt_name not in _dev_severity:
            _dev_severity[tgt_name] = _dev_severity[src_name]
        if src_name in _dev_crit_ifaces and tgt_name not in _dev_crit_ifaces:
            _dev_crit_ifaces[tgt_name] = _dev_crit_ifaces[src_name]

    # Overlay with in-memory alerts (captures events not yet committed to DB)
    for alert in _alerts_store:
        dev = alert.get("device", "")
        cls = alert.get("classification", "")
        if not dev:
            continue
        cur = _dev_severity.get(dev, "ok")
        if cls == "CRITICAL" and cur != "critical":
            _dev_severity[dev] = "critical"
            _dev_crit_ifaces.setdefault(dev, set()).add(
                alert.get("interface", "") or alert.get("interface_name", "")
            )
        elif cls == "WARNING" and cur not in ("critical",):
            _dev_severity[dev] = "warning"
        elif cur not in ("critical", "warning"):
            _dev_severity[dev] = "ok"

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
        "KKT-Core-3": 1,
        "DHK-Core-03": 2,
        "DHK-Core-2-Agg": 2,
        "COX-Core-01": 2,
        "COX-Core-3": 2,
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
                    "status": _dev_severity.get(topo.name, "unknown"),
                }
            )

    # Build link list from topology upstreams + add missing remote nodes
    links: list[dict[str, Any]] = []
    seen_links: set[frozenset[str]] = set()
    for _ip, topo in NETWORK_TOPOLOGY.items():
        for bundle, link in topo.upstreams.items():
            remote_topo = NETWORK_TOPOLOGY.get(link.remote_device_ip)
            if remote_topo:
                remote_name = remote_topo.name
            else:
                remote_dev = DEVICE_MAP.get(link.remote_device_ip)
                remote_name = remote_dev.name if remote_dev else link.remote_device_ip

            if remote_name not in node_ids:
                node_ids.add(remote_name)
                remote_dev = DEVICE_MAP.get(link.remote_device_ip)
                nodes.append(
                    {
                        "id": remote_name,
                        "name": remote_name,
                        "ip": link.remote_device_ip,
                        "location": remote_dev.location if remote_dev else "",
                        "platform": remote_dev.platform if remote_dev else "",
                        "level": _level_map.get(remote_name, 2),
                        "status": _dev_severity.get(remote_name, "unknown"),
                    }
                )

            key = frozenset([topo.name, remote_name, bundle])
            if key in seen_links:
                continue
            seen_links.add(key)
            link_status = "unknown"
            src_sev = _dev_severity.get(topo.name)
            tgt_sev = _dev_severity.get(remote_name)
            if src_sev or tgt_sev:
                crit_ifaces = _dev_crit_ifaces.get(topo.name, set())
                member_hit = any(m in crit_ifaces for m in link.members)
                if member_hit:
                    link_status = "critical"
                elif "critical" in (src_sev, tgt_sev) or "warning" in (
                    src_sev,
                    tgt_sev,
                ):
                    link_status = "warning"
                else:
                    link_status = "ok"

            links.append(
                {
                    "source": topo.name,
                    "target": remote_name,
                    "bundle": bundle,
                    "description": link.description,
                    "members": len(link.members),
                    "status": link_status,
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
