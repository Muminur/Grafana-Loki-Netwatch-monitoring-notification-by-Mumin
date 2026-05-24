"""FastAPI application entry point for BSCCL NetWatch.

Startup sequence:
  1. Load settings from .env
  2. Create DB tables (idempotent)
  3. Start SyslogReceiver (Loki WS / HTTP / UDP)

Shutdown sequence:
  1. Stop SyslogReceiver gracefully

Routes:
  GET  /              — Dashboard page
  GET  /statistics    — Statistics page
  GET  /settings      — Settings page
  GET  /health        — Health check
  WS   /ws            — Live alert WebSocket (all events)
  WS   /ws/filtered   — Live alert WebSocket (filtered by classification)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routes import (
    add_alert_to_store,
    get_maintenance_store,
    increment_alerts_processed,
    router,
    set_db_engine,
)
from src.api.websocket import WebSocketManager
from src.config import get_settings
from src.core.correlator import CorrelatedEvent, CorrelationEngine
from src.core.dedup import DedupEngine
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.core.syslog_receiver import SyslogReceiver
from src.database.crud import insert_alert
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog
from src.notifications.discord import send_discord_alert
from src.notifications.escalation import EscalationEngine
from src.notifications.telegram import send_telegram_alert

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application-level singletons
# ---------------------------------------------------------------------------

_ws_manager = WebSocketManager()

# Pipeline singletons — populated during lifespan startup
_engine: object = None
_correlator: CorrelationEngine | None = None
_dedup: DedupEngine | None = None
_escalation: EscalationEngine | None = None

# ---------------------------------------------------------------------------
# Template + static file setup
# ---------------------------------------------------------------------------

_WEB_DIR = Path(__file__).resolve().parent / "web"
_templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))


# ---------------------------------------------------------------------------
# Ingestion callback
# ---------------------------------------------------------------------------


async def _on_syslog_line(raw_line: str) -> None:
    """Process a raw syslog line through the full pipeline.

    Pipeline: parse → enrich → correlate → dedup → store_to_db →
              notify → broadcast → count.

    Parameters
    ----------
    raw_line:
        A single raw syslog line string from Loki or UDP.
    """
    parsed = parse_syslog(raw_line)
    if parsed is None:
        return

    enriched = enrich(parsed)

    # ── Correlate ──────────────────────────────────────────────────────────
    correlated = _correlator.correlate(enriched) if _correlator is not None else None

    # ── Dedup check ────────────────────────────────────────────────────────
    if _dedup is not None:
        should_send, _reason = _dedup.should_notify(enriched)
    else:
        should_send = True

    # ── Store to DB ────────────────────────────────────────────────────────
    suppress = correlated.suppress_notification if correlated is not None else False
    will_notify = should_send and enriched.notify and not suppress
    incident_id = (correlated.incident_id or "") if correlated is not None else ""
    if should_send and _engine is not None:
        try:
            alert = AlertLog(
                timestamp=enriched.parsed.timestamp,
                source_ip=enriched.parsed.source_ip,
                device_name=enriched.device_name,
                hostname=enriched.parsed.hostname,
                rp_location=enriched.parsed.rp_location,
                facility=enriched.parsed.facility,
                subfacility=enriched.parsed.subfacility,
                severity_level=enriched.parsed.severity_level,
                mnemonic=enriched.parsed.mnemonic,
                message=enriched.parsed.message,
                raw=enriched.parsed.raw,
                classification=enriched.classification,
                interface_name=enriched.interface_name,
                interface_description=enriched.interface_description,
                client_name=enriched.client_name,
                bgp_neighbor=enriched.bgp_neighbor,
                as_number=enriched.as_number,
                as_name=enriched.as_name,
                incident_id=incident_id,
                notification_sent=will_notify,
            )
            async with AsyncSession(_engine) as session:  # type: ignore[arg-type]
                await insert_alert(session, alert)
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            _log.error("DB insert failed: %s", exc)

    # ── Update in-memory API store ─────────────────────────────────────────
    if should_send:
        if correlated is None:
            correlated = CorrelatedEvent(enriched=enriched)
        try:
            add_alert_to_store(enriched, correlated)
        except Exception as exc:  # noqa: BLE001
            _log.error("add_alert_to_store failed: %s", exc)

    # ── Maintenance window suppression ────────────────────────────────────
    if will_notify:
        from datetime import UTC  # noqa: PLC0415
        from datetime import datetime as _dt  # noqa: PLC0415

        _now = _dt.now(UTC)
        for m in get_maintenance_store():
            if m.get("device_name") != enriched.device_name:
                continue
            try:
                s_raw, e_raw = m.get("start_time", ""), m.get("end_time", "")
                m_start = _dt.fromisoformat(s_raw) if isinstance(s_raw, str) else s_raw
                m_end = _dt.fromisoformat(e_raw) if isinstance(e_raw, str) else e_raw
                if m_start.tzinfo is None:
                    m_start = m_start.replace(tzinfo=UTC)
                if m_end.tzinfo is None:
                    m_end = m_end.replace(tzinfo=UTC)
                if m_start <= _now <= m_end:
                    will_notify = False
                    break
            except (ValueError, AttributeError, TypeError):
                continue

    # ── Notify (Discord + Telegram) ────────────────────────────────────────
    if will_notify:
        settings = get_settings()
        if settings.discord_enabled:
            await send_discord_alert(enriched, settings)
        if settings.telegram_enabled:
            await send_telegram_alert(enriched, settings)
        if _escalation is not None:
            _escalation.track_alert(enriched)

    # ── Broadcast to WebSocket clients ─────────────────────────────────────
    if should_send:
        await _ws_manager.broadcast_filtered(
            {
                "type": "alert",
                "classification": enriched.classification,
                "device": enriched.device_name,
                "hostname": enriched.parsed.hostname,
                "mnemonic": enriched.parsed.mnemonic,
                "message": enriched.parsed.message,
                "timestamp": enriched.parsed.timestamp.isoformat(),
                "interface": enriched.interface_name,
                "interface_description": enriched.interface_description,
                "client": enriched.client_name,
                "neighbor": enriched.bgp_neighbor,
                "as_number": enriched.as_number,
                "as_name": enriched.as_name,
                "event_type": enriched.event_type,
                "incident_id": incident_id,
                "suppress_notification": suppress,
            },
            enriched.classification,
        )

    increment_alerts_processed()


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------


async def _digest_scheduler(engine: object) -> None:
    """Background task: run daily digest at 02:00 UTC (08:00 BDT) every day.

    Checks the current UTC hour every 60 seconds.  When the hour is 02 and
    the digest has not yet been sent today, generates and dispatches it.

    Parameters
    ----------
    engine:
        The SQLAlchemy async engine used to open a session for the digest query.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    from src.notifications.digest import send_daily_digest  # noqa: PLC0415

    last_sent_date: str = ""

    while True:
        try:
            await asyncio.sleep(60)
            now = datetime.now(UTC)
            today = now.strftime("%Y-%m-%d")
            if now.hour == 2 and last_sent_date != today:  # noqa: PLR2004
                _log.info("Running daily digest for %s", today)
                async with AsyncSession(engine) as session:  # type: ignore[arg-type]
                    await send_daily_digest(session)
                last_sent_date = today
                _log.info("Daily digest dispatched for %s", today)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Digest scheduler error: %s", exc)


async def _escalation_checker() -> None:
    """Background task: check for pending escalations every 60 seconds.

    Alerts that have been tracked by the escalation engine for longer than
    the escalation delay (default 15 min) without acknowledgement are logged
    as pending escalations.  Notification dispatch will be added in a later
    milestone once the escalation alert format is finalised.
    """
    while True:
        try:
            await asyncio.sleep(60)
            if _escalation is not None:
                pending = _escalation.get_pending_escalations()
                for alert in pending:
                    _log.warning(
                        "ESCALATION: %s/%s unacknowledged for >15 min",
                        alert.device_name,
                        alert.parsed.mnemonic,
                    )
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Escalation checker error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    """Application lifespan: startup and shutdown logic.

    Startup
    -------
    1. Load settings and create DB engine + tables.
    2. Initialise pipeline singletons (correlator, dedup, escalation).
    3. Start the syslog receiver (async background task).
    4. Start the daily digest scheduler background task.
    5. Start the escalation checker background task.

    Shutdown
    --------
    1. Stop the syslog receiver gracefully.
    2. Cancel background tasks.
    3. Dispose the DB engine.
    """
    global _engine, _correlator, _dedup, _escalation  # noqa: PLW0603

    settings = get_settings()

    # ── Database ───────────────────────────────────────────────────────────
    engine = await get_engine(settings.database_url)
    await create_tables(engine)
    _engine = engine
    set_db_engine(engine)

    # Load historical alert count from DB so the counter doesn't reset on restart
    try:
        from sqlalchemy import func, select  # noqa: PLC0415

        async with AsyncSession(engine) as session:
            count_result = await session.execute(select(func.count(AlertLog.id)))
            existing_count = count_result.scalar() or 0
        if existing_count > 0:
            from src.api.routes import _set_alerts_processed  # noqa: PLC0415

            _set_alerts_processed(existing_count)
            _log.info("Loaded %d historical alerts from DB", existing_count)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Could not load historical alert count: %s", exc)

    # Re-classify existing alerts whose rules may have changed since they
    # were ingested (classification is stored at ingestion time).
    try:
        from src.core.classifier import classify  # noqa: PLC0415

        async with AsyncSession(engine) as session:
            reclass_result = await session.execute(select(AlertLog))
            rows = reclass_result.scalars().all()
            fixed = 0
            for row in rows:
                if not row.raw:
                    continue
                parsed = parse_syslog(row.raw)
                if parsed is None:
                    continue
                cls = classify(parsed)
                if cls.classification != row.classification:
                    row.classification = cls.classification
                    session.add(row)
                    fixed += 1
            if fixed:
                await session.commit()
                _log.info("Re-classified %d alerts with updated rules", fixed)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Could not re-classify alerts: %s", exc)

    _log.info("Database ready: %s", settings.database_url)

    # ── Pipeline singletons ────────────────────────────────────────────────
    _correlator = CorrelationEngine()
    _dedup = DedupEngine(
        window_seconds=settings.dedup_window_seconds,
        flap_window=settings.bgp_flap_window_seconds,
        bundle_window=settings.bundle_group_window_seconds,
    )
    _escalation = EscalationEngine()
    _log.info(
        "Pipeline ready: dedup=%ds flap=%ds bundle=%ds",
        settings.dedup_window_seconds,
        settings.bgp_flap_window_seconds,
        settings.bundle_group_window_seconds,
    )

    # ── Syslog receiver (resume from last known DB timestamp) ────────────
    resume_ns = 0
    try:
        async with AsyncSession(engine) as session:
            from sqlalchemy import func as sa_func  # noqa: PLC0415

            ts_result = await session.execute(select(sa_func.max(AlertLog.timestamp)))
            last_ts = ts_result.scalar()
            if last_ts is not None:
                resume_ns = int(last_ts.timestamp() * 1_000_000_000)
                _log.info("Resuming syslog poll from DB anchor: %s", last_ts)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Could not read last alert timestamp: %s", exc)

    receiver = SyslogReceiver(settings, _on_syslog_line, resume_from_ns=resume_ns)
    await receiver.start()
    _log.info("SyslogReceiver started (mode: %s)", settings.syslog_mode)

    # ── Daily digest scheduler ─────────────────────────────────────────────
    digest_task = asyncio.create_task(_digest_scheduler(engine))
    _log.info("Daily digest scheduler started (fires at 02:00 UTC / 08:00 BDT)")

    # ── Escalation checker ─────────────────────────────────────────────────
    escalation_task = asyncio.create_task(_escalation_checker())
    _log.info("Escalation checker started (60-second interval)")

    yield  # application runs here

    # ── Shutdown ───────────────────────────────────────────────────────────
    _log.info("Shutting down SyslogReceiver…")
    await receiver.stop()

    _log.info("Cancelling background tasks…")
    digest_task.cancel()
    escalation_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await digest_task
    with contextlib.suppress(asyncio.CancelledError):
        await escalation_task

    _log.info("Disposing DB engine…")
    await engine.dispose()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="BSCCL NetWatch",
    version="0.1.0",
    description="Network Syslog Classification & Alerting Dashboard",
    lifespan=lifespan,
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# ── Static files ─────────────────────────────────────────────────────────────
app.mount(
    "/static",
    StaticFiles(directory=str(_WEB_DIR / "static")),
    name="static",
)

# ── REST API router ─────────────────────────────────────────────────────────
app.include_router(router)


# ── Page routes ──────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request) -> HTMLResponse:
    """Render the main NOC dashboard page."""
    return _templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"active_page": "dashboard"},
    )


@app.get("/statistics", response_class=HTMLResponse)
async def statistics_page(request: Request) -> HTMLResponse:
    """Render the statistics page."""
    return _templates.TemplateResponse(
        request=request,
        name="statistics.html",
        context={"active_page": "statistics"},
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    """Render the settings page."""
    from src.config import get_settings as _gs  # noqa: PLC0415

    s = _gs()
    return _templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "active_page": "settings",
            "dedup_window": s.dedup_window_seconds,
        },
    )


# ── WebSocket endpoints ──────────────────────────────────────────────────────


@app.websocket("/ws")
async def ws_all(websocket: WebSocket) -> None:
    """Live WebSocket — broadcasts all classified alerts."""
    await _ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive; ignore inbound messages from browser clients
            await websocket.receive_text()
    except Exception:  # noqa: BLE001,S110
        _log.debug("WebSocket /ws client disconnected")
    finally:
        await _ws_manager.disconnect(websocket)


@app.websocket("/ws/filtered")
async def ws_filtered(websocket: WebSocket) -> None:
    """Filtered WebSocket — client sends its classification filter as first message."""
    await _ws_manager.connect(websocket)
    try:
        classification = await websocket.receive_text()
        _ws_manager.set_filter(websocket, classification.strip().upper())
        while True:
            await websocket.receive_text()
    except Exception:  # noqa: BLE001,S110
        _log.debug("WebSocket /ws/filtered client disconnected")
    finally:
        await _ws_manager.disconnect(websocket)
