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
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.routes import (
    add_alert_to_store,
    get_maintenance_store,
    increment_alerts_processed,
    load_persisted_state,
    router,
    set_background_tasks,
    set_db_engine,
    set_receiver,
)
from src.api.websocket import WebSocketManager
from src.config import get_settings
from src.core.correlator import CorrelatedEvent, CorrelationEngine
from src.core.dedup import DedupEngine
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.core.syslog_receiver import SyslogReceiver
from src.database.crud import insert_alert, prune_old_alerts, prune_old_stats, vacuum_db
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog
from src.logging_config import configure_logging
from src.metrics import (
    record_alert,
    record_dedup_suppressed,
    record_notification,
)
from src.notifications.discord import send_discord_alert, send_discord_escalation
from src.notifications.escalation import EscalationEngine
from src.notifications.telegram import send_telegram_alert, send_telegram_escalation
from src.rate_limit import limiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------

# Content-Security-Policy rationale:
#   * default-src 'self'        — restrict all resource types to same origin
#   * script-src 'self' 'unsafe-inline' cdn.jsdelivr.net
#                               — Chart.js CDN fallback; inline clock script
#                                 in base.html and JS in templates
#   * style-src 'self' 'unsafe-inline' fonts.googleapis.com
#                               — neon-theme.css + Chart.js inline styles;
#                                 Google Fonts CDN fallback in base.html
#   * font-src 'self' fonts.gstatic.com
#                               — Google Fonts glyph files fallback
#   * img-src 'self' data:      — data: URIs used by Chart.js for canvas export
#   * connect-src 'self' ws: wss:
#                               — WebSocket connections (/ws, /ws/filtered)
#   * frame-ancestors 'none'    — equivalent defence-in-depth alongside
#                                 X-Frame-Options: DENY
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
    "font-src 'self' fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach security-related HTTP response headers to every response."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = _CSP
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Assign a unique request ID to each request and log the access line.

    Behaviour
    ---------
    * Generates a UUID4 per request.
    * Stores it on ``request.state.request_id`` so downstream handlers can
      reference it (e.g. for structured logging in route handlers).
    * Adds ``X-Request-ID`` to the response headers so clients can correlate
      their own logs with server-side logs.
    * Logs a single INFO line containing the HTTP method, path, response
      status code, elapsed time in milliseconds, and the request ID.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000
        response.headers["X-Request-ID"] = request_id
        _log.info(
            "%s %s %s %.1fms rid=%s",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id,
        )
        return response


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def _rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded  # noqa: ARG001
) -> JSONResponse:
    """Return a 429 JSON response when a client exceeds a rate limit."""
    return JSONResponse(
        status_code=429,
        content={
            "detail": f"Rate limit exceeded: {exc.detail}",
        },
    )


# ---------------------------------------------------------------------------
# Application-level singletons
# ---------------------------------------------------------------------------

_ws_manager = WebSocketManager()

# Pipeline singletons — populated during lifespan startup
_engine: AsyncEngine | None = None
_correlator: CorrelationEngine | None = None
_dedup: DedupEngine | None = None
_escalation: EscalationEngine | None = None

# ---------------------------------------------------------------------------
# Template + static file setup
# ---------------------------------------------------------------------------

_WEB_DIR = Path(__file__).resolve().parent / "web"
_APP_VERSION = "2.0"
_templates = Jinja2Templates(directory=str(_WEB_DIR / "templates"))
_templates.env.globals["app_version"] = _APP_VERSION


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
        if not should_send:
            record_dedup_suppressed()
    else:
        should_send = True

    # ── Store to DB ────────────────────────────────────────────────────────
    # NOTE: Noise reclassification (hardware defects on backhaul members) is
    # handled exclusively in add_alert_to_store() (routes.py) to avoid the
    # logic being duplicated in two places with potential divergence.
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
                as_number=enriched.as_number or 0,
                as_name=enriched.as_name,
                incident_id=incident_id,
                notification_sent=will_notify,
            )
            async with AsyncSession(_engine) as session:
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
        if settings.discord_enabled and await send_discord_alert(enriched, settings):
            record_notification("discord")
        if settings.telegram_enabled and await send_telegram_alert(enriched, settings):
            record_notification("telegram")
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
                "as_number": enriched.as_number or 0,
                "as_name": enriched.as_name,
                "event_type": enriched.event_type,
                "incident_id": incident_id,
                "suppress_notification": suppress,
            },
            enriched.classification,
        )

    increment_alerts_processed()
    record_alert(enriched.classification)


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
    the escalation delay (default 15 min) without acknowledgement are sent
    as escalation notifications to Discord and Telegram, then marked as
    escalated so they are not re-sent on every subsequent check cycle.
    """
    while True:
        try:
            await asyncio.sleep(60)
            if _escalation is not None:
                pending = _escalation.get_pending_escalations()
                for alert, elapsed_minutes in pending:
                    _log.warning(
                        "ESCALATION: %s/%s unacknowledged for >%d min",
                        alert.device_name,
                        alert.parsed.mnemonic,
                        elapsed_minutes,
                    )
                    settings = get_settings()
                    if settings.discord_enabled:
                        await send_discord_escalation(alert, elapsed_minutes, settings)
                    if settings.telegram_enabled:
                        await send_telegram_escalation(alert, elapsed_minutes, settings)
                    _escalation.mark_escalated(alert.device_name, alert.parsed.mnemonic)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Escalation checker error: %s", exc)


async def _hourly_aggregator(engine: object) -> None:
    """Background task: aggregate alert counts into HourlyStats every 5 minutes.

    Opens a fresh session, calls ``aggregate_hourly()``, commits, and sleeps
    for 5 minutes.  Any exception other than ``CancelledError`` is caught and
    logged so a transient DB error never crashes the server.

    Parameters
    ----------
    engine:
        The SQLAlchemy async engine used to open a session for the aggregation.
    """
    from src.statistics.aggregator import aggregate_hourly  # noqa: PLC0415

    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            async with AsyncSession(engine) as session:  # type: ignore[arg-type]
                await aggregate_hourly(session)
                await session.commit()
            _log.debug("HourlyStats aggregation completed")
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Hourly aggregator error: %s", exc)


async def _retention_cleanup(engine: object) -> None:
    """Background task: prune old alerts/stats and VACUUM once per day at 03:00 UTC.

    Checks the current UTC hour every 60 seconds.  When the hour is 03 and
    the cleanup has not yet run today, prunes AlertLog rows older than the
    configured ``retention_days``, HourlyStats older than 365 days, then runs
    ``VACUUM`` to reclaim disk space.

    Parameters
    ----------
    engine:
        The SQLAlchemy async engine used to open a session for the cleanup.
    """
    from datetime import UTC, datetime  # noqa: PLC0415

    from sqlalchemy.ext.asyncio import AsyncSession  # noqa: PLC0415

    last_run_date: str = ""
    settings = get_settings()

    while True:
        try:
            await asyncio.sleep(60)
            now = datetime.now(UTC)
            today = now.strftime("%Y-%m-%d")
            if now.hour == 3 and last_run_date != today:  # noqa: PLR2004
                _log.info("Starting daily retention cleanup for %s", today)

                # Prune old alerts
                async with AsyncSession(engine) as session:  # type: ignore[arg-type]
                    alert_count = await prune_old_alerts(
                        session, settings.retention_days
                    )
                    await session.commit()
                if alert_count:
                    _log.info(
                        "Pruned %d alerts older than %d days",
                        alert_count,
                        settings.retention_days,
                    )

                # Prune old hourly stats
                async with AsyncSession(engine) as session:  # type: ignore[arg-type]
                    stats_count = await prune_old_stats(session, 365)
                    await session.commit()
                if stats_count:
                    _log.info("Pruned %d hourly stats older than 365 days", stats_count)

                # VACUUM to reclaim disk space
                await vacuum_db(engine)  # type: ignore[arg-type]
                _log.info("VACUUM completed")

                last_run_date = today
                _log.info("Retention cleanup finished for %s", today)
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Retention cleanup error: %s", exc)


_STALE_THRESHOLD_SECONDS = 600  # 10 minutes without a syslog message


async def _self_monitor(receiver: SyslogReceiver) -> None:
    """Background task: detect stale syslog data and alert operators.

    Runs every 60 seconds.  When no syslog message has been received in
    the last 10 minutes, sends a one-shot notification via Discord and
    Telegram.  The alert flag resets automatically once data flow resumes,
    so a fresh notification is sent on the next outage.

    A startup grace period equal to the stale threshold prevents false
    alerts when the app starts and no syslog messages have arrived yet.
    """
    import time  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    stale_alert_sent = False
    start_monotonic = time.monotonic()

    while True:
        try:
            await asyncio.sleep(60)
            last_msg = receiver.last_message_at
            if last_msg is not None:
                elapsed = (datetime.now(UTC) - last_msg).total_seconds()
                is_stale = elapsed > _STALE_THRESHOLD_SECONDS
            else:
                # No message ever received — only flag stale after the
                # startup grace period (same as the stale threshold) so
                # we don't fire a false alert on fresh startup.
                uptime = time.monotonic() - start_monotonic
                is_stale = uptime > _STALE_THRESHOLD_SECONDS

            if is_stale and not stale_alert_sent:
                settings = get_settings()
                host = settings.monitor_host
                message = (
                    f"NetWatch has not received any syslog data for "
                    f"10 minutes — check Loki connection at "
                    f"{host}:3100"
                )
                _log.warning("Self-monitor: %s", message)

                if settings.discord_enabled and settings.discord_webhook_url:
                    try:
                        import httpx as _httpx  # noqa: PLC0415

                        payload = {
                            "embeds": [
                                {
                                    "title": "⚠️ NetWatch Self-Monitor Alert",
                                    "description": message,
                                    "color": 0xFF8C00,
                                }
                            ]
                        }
                        async with _httpx.AsyncClient(timeout=10.0) as client:
                            await client.post(
                                settings.discord_webhook_url, json=payload
                            )
                    except Exception as exc:  # noqa: BLE001
                        _log.error("Self-monitor Discord send failed: %s", exc)

                if (
                    settings.telegram_enabled
                    and settings.telegram_bot_token
                    and settings.telegram_chat_id
                ):
                    try:
                        import httpx as _httpx  # noqa: PLC0415

                        url = (
                            f"https://api.telegram.org"
                            f"/bot{settings.telegram_bot_token}/sendMessage"
                        )
                        tg_text = f"*NetWatch Self-Monitor*\n{message}"
                        tg_payload = {
                            "chat_id": settings.telegram_chat_id,
                            "text": tg_text,
                            "parse_mode": "Markdown",
                        }
                        async with _httpx.AsyncClient(timeout=10.0) as client:
                            await client.post(url, json=tg_payload)
                    except Exception as exc:  # noqa: BLE001
                        _log.error("Self-monitor Telegram send failed: %s", exc)

                stale_alert_sent = True

            elif not is_stale and stale_alert_sent:
                _log.info("Self-monitor: syslog data flow resumed")
                stale_alert_sent = False

        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            _log.error("Self-monitor error: %s", exc)


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
    6. Start the hourly stats aggregator background task.

    Shutdown
    --------
    1. Stop the syslog receiver gracefully.
    2. Cancel background tasks.
    3. Dispose the DB engine.
    """
    global _engine, _correlator, _dedup, _escalation  # noqa: PLW0603

    settings = get_settings()

    # ── Logging ────────────────────────────────────────────────────────────
    configure_logging(settings.log_format, settings.log_level)
    _log.info(
        "Logging configured (format=%s level=%s)",
        settings.log_format,
        settings.log_level,
    )

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

    # Load persisted maintenance windows + hardware-noise toggle into cache
    await load_persisted_state(engine)

    # Re-classify recent alerts whose rules may have changed since they
    # were ingested (classification is stored at ingestion time).
    # Bounded to the last 7 days and 10 000 rows to avoid a full table scan.
    # Skip alerts already reclassified as NOISE by the hardware-noise toggle.
    try:
        from datetime import datetime as _reclass_dt  # noqa: PLC0415
        from datetime import timedelta as _reclass_td  # noqa: PLC0415
        from datetime import timezone as _reclass_tz  # noqa: PLC0415

        from src.api.routes import (  # noqa: PLC0415
            _SILENT_FAULT_MNEMONICS as _NOISE_MNEMONICS,
        )
        from src.api.routes import (  # noqa: PLC0415
            _hardware_defects_as_noise as _noise_on,
        )
        from src.core.classifier import classify  # noqa: PLC0415

        # SQLite stores timestamps as naive BDT (UTC+6) face values, so
        # the cutoff must use BDT to compare correctly.
        _bdt = _reclass_tz(_reclass_td(hours=6))
        _reclass_cutoff = _reclass_dt.now(_bdt) - _reclass_td(days=7)
        async with AsyncSession(engine) as session:
            reclass_result = await session.execute(
                select(AlertLog)
                .where(AlertLog.timestamp >= _reclass_cutoff)
                .order_by(AlertLog.timestamp.desc())
                .limit(10_000)
            )
            rows = reclass_result.scalars().all()
            fixed = 0
            for row in rows:
                if not row.raw:
                    continue
                if (
                    _noise_on
                    and row.mnemonic in _NOISE_MNEMONICS
                    and row.classification == "NOISE"
                ):
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

    # Seed the correlator incident-ID sequence from the DB so new IDs never
    # collide with existing ones on the same UTC day after a restart.
    try:
        from datetime import UTC as _UTC  # noqa: PLC0415
        from datetime import datetime as _datetime  # noqa: PLC0415

        from sqlalchemy import Integer as _Integer  # noqa: PLC0415
        from sqlalchemy import func as _sa_func  # noqa: PLC0415
        from sqlalchemy import select as _sa_select

        today_str = _datetime.now(_UTC).strftime("%Y%m%d")
        inc_prefix = f"INC-{today_str}-%"
        # INC-YYYYMMDD-NNN: 'INC-' (4) + YYYYMMDD (8) + '-' (1) = 13 chars
        # before the NNN part, so SUBSTR(incident_id, 14) extracts NNN.
        _SEQ_START = 14  # noqa: N806
        async with AsyncSession(engine) as session:
            seq_result = await session.execute(
                _sa_select(
                    _sa_func.max(
                        _sa_func.cast(
                            _sa_func.substr(AlertLog.incident_id, _SEQ_START),
                            _Integer,
                        )
                    )
                ).where(AlertLog.incident_id.like(inc_prefix))
            )
            max_seq = seq_result.scalar() or 0
        if max_seq > 0:
            _correlator.seed_sequence(max_seq)
            _log.info(
                "Seeded correlator incident sequence to %d for today (%s)",
                max_seq,
                today_str,
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("Could not seed correlator sequence: %s", exc)

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

    # ── Restore in-flight escalation state from DB ─────────────────────────
    # Reconstruct _escalation from AlertLog rows so in-flight timers are
    # preserved across restarts.  The original tracked_at is approximated
    # from the row's timestamp (the moment the alert was first ingested).
    # Only CRITICAL rows that are unresolved AND unacknowledged within a
    # bounded recent window are considered — capped at 200 rows so startup
    # remains fast even against very large DBs.
    try:
        from datetime import datetime as _datetime  # noqa: PLC0415
        from datetime import timedelta as _timedelta  # noqa: PLC0415
        from datetime import timezone as _timezone  # noqa: PLC0415

        from sqlalchemy import and_ as _and  # noqa: PLC0415
        from sqlalchemy import select as _select  # noqa: PLC0415

        _utc6_tz = _timezone(_timedelta(hours=6))
        # Use 2× the delay as the lookback window; access via public-friendly
        # notation by reading the already-set private attr once at startup.
        _esc_delay_secs = _escalation.escalation_delay_seconds
        _esc_cutoff = _datetime.now(_utc6_tz) - _timedelta(seconds=_esc_delay_secs * 2)

        async with AsyncSession(engine) as session:
            _esc_stmt = (
                _select(AlertLog)
                .where(
                    _and(
                        AlertLog.classification == "CRITICAL",
                        AlertLog.resolved_at.is_(None),
                        AlertLog.acknowledged_at.is_(None),
                        AlertLog.timestamp >= _esc_cutoff,
                    )
                )
                .order_by(AlertLog.timestamp.asc())
                .limit(200)
            )
            _esc_result = await session.execute(_esc_stmt)
            _esc_rows = _esc_result.scalars().all()

        _restored = 0
        for _row in _esc_rows:
            if not _row.raw:
                continue
            try:
                _parsed = parse_syslog(_row.raw)
                if _parsed is None:
                    continue
                _enriched = enrich(_parsed)
                _tracked_at = _row.timestamp
                if _tracked_at.tzinfo is None:
                    _tracked_at = _tracked_at.replace(tzinfo=_utc6_tz)
                _escalation.restore(
                    _enriched,
                    tracked_at=_tracked_at,
                    acknowledged=False,
                )
                _restored += 1
            except Exception as _row_exc:  # noqa: BLE001
                _log.debug(
                    "Escalation restore: skipping row id=%s: %s",
                    _row.id,
                    _row_exc,
                )

        if _restored:
            _log.info("Restored %d in-flight escalation entries from DB", _restored)
    except Exception as exc:  # noqa: BLE001
        _log.warning("Could not restore escalation state from DB: %s", exc)

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
    set_receiver(receiver)
    try:
        await receiver.start()
        _log.info("SyslogReceiver started (mode: %s)", settings.syslog_mode)
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "SyslogReceiver initial start failed (%s); "
            "dashboard will serve cached data. "
            "Receiver background task will retry automatically.",
            exc,
        )

    # ── Daily digest scheduler ─────────────────────────────────────────────
    digest_task = asyncio.create_task(_digest_scheduler(engine))
    _log.info("Daily digest scheduler started (fires at 02:00 UTC / 08:00 BDT)")

    # ── Escalation checker ─────────────────────────────────────────────────
    escalation_task = asyncio.create_task(_escalation_checker())
    _log.info("Escalation checker started (60-second interval)")

    # ── Hourly stats aggregator ────────────────────────────────────────────
    hourly_task = asyncio.create_task(_hourly_aggregator(engine))
    _log.info("Hourly stats aggregator started (5-minute interval)")

    # ── Retention cleanup ──────────────────────────────────────────────────
    retention_task = asyncio.create_task(_retention_cleanup(engine))
    _log.info(
        "Retention cleanup started (fires at 03:00 UTC / 09:00 BDT, "
        "retention=%d days)",
        settings.retention_days,
    )

    # ── Self-monitor (stale data detection) ───────────────────────────────
    self_monitor_task = asyncio.create_task(_self_monitor(receiver))
    _log.info("Self-monitor started (60-second interval, 10-minute stale threshold)")

    # ── Register task handles for /health liveness reporting ───────────────
    set_background_tasks(
        {
            "digest": digest_task,
            "escalation": escalation_task,
            "aggregator": hourly_task,
            "retention": retention_task,
            "self_monitor": self_monitor_task,
        }
    )

    yield  # application runs here

    # ── Shutdown ───────────────────────────────────────────────────────────
    _log.info("Shutting down SyslogReceiver…")
    await receiver.stop()

    _log.info("Cancelling background tasks…")
    digest_task.cancel()
    escalation_task.cancel()
    hourly_task.cancel()
    retention_task.cancel()
    self_monitor_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await digest_task
    with contextlib.suppress(asyncio.CancelledError):
        await escalation_task
    with contextlib.suppress(asyncio.CancelledError):
        await hourly_task
    with contextlib.suppress(asyncio.CancelledError):
        await retention_task
    with contextlib.suppress(asyncio.CancelledError):
        await self_monitor_task

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

# ── Rate limiter ─────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# ── CORS ──────────────────────────────────────────────────────────────────────
# Origins are loaded from CORS_ORIGINS env var via Settings.cors_origins.
# Default: http://localhost:8080, http://127.0.0.1:8080
#
# NOTE: Starlette processes middleware in reverse-add order (last added =
# outermost).  CORSMiddleware must be added BEFORE SecurityHeadersMiddleware
# so that CORS is innermost and SecurityHeadersMiddleware (added last, outermost)
# runs on every response — including OPTIONS preflight short-circuits from CORS.
try:
    _cors_origins = get_settings().cors_origins
except ValueError as _cfg_err:
    # Fail fast at startup with a clear message rather than a bare attribute
    # error later when the CORS middleware tries to use an unset variable.
    _log.critical("Invalid configuration — cannot start: %s", _cfg_err)
    raise
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["content-type", "x-api-key"],
)

# ── Request-ID middleware (added second; wraps CORS, wrapped by SecurityHeaders) ─
# Starlette processes middleware in reverse-add order, so the last-added
# middleware is outermost.  Add order: CORS(1) → RequestID(2) → Security(3).
# Response path: App → CORS → RequestID (sets X-Request-ID) → SecurityHeaders
# (adds sec headers).  RequestID therefore runs BEFORE SecurityHeaders on the
# response path, which is correct: the header is present when Security sees it.
app.add_middleware(RequestIDMiddleware)

# ── Security headers (outermost — must be added LAST so it wraps everything) ─
# Added after CORSMiddleware so it is outermost and runs on ALL responses,
# including CORS preflight (OPTIONS) short-circuit responses.
app.add_middleware(SecurityHeadersMiddleware)

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


async def _ws_authenticate(websocket: WebSocket) -> bool:
    """Authenticate a WebSocket connection using a query-param token.

    When ``API_KEY`` is configured, the client must pass ``?token=<key>``
    as a query parameter.  If the token is missing or incorrect the
    connection is accepted and then immediately closed with code **4001**
    ("Unauthorized") so the client receives a clear rejection.

    Returns ``True`` if the connection is authorised (or auth is disabled),
    ``False`` if it was rejected and closed.
    """
    settings = get_settings()
    configured_key = settings.api_key.strip()
    if not configured_key:
        # Auth disabled — backward-compatible; allow all connections.
        return True
    token = websocket.query_params.get("token", "")
    if secrets.compare_digest(token.encode(), configured_key.encode()):
        return True
    # Reject: accept first (required by ASGI) then close with 4001.
    await websocket.accept()
    await websocket.close(code=4001, reason="Unauthorized")
    _log.warning("WebSocket connection rejected — invalid or missing token")
    return False


@app.websocket("/ws")
async def ws_all(websocket: WebSocket) -> None:
    """Live WebSocket — broadcasts all classified alerts."""
    from starlette.websockets import WebSocketDisconnect  # noqa: PLC0415

    if not await _ws_authenticate(websocket):
        return

    await _ws_manager.connect(websocket)
    try:
        while True:
            # Keep alive; ignore inbound messages from browser clients
            await websocket.receive_text()
    except WebSocketDisconnect:
        _log.debug("WebSocket /ws client disconnected normally")
    except Exception as exc:  # noqa: BLE001
        _log.warning("WebSocket /ws unexpected error: %s", exc)
    finally:
        await _ws_manager.disconnect(websocket)


@app.websocket("/ws/filtered")
async def ws_filtered(websocket: WebSocket) -> None:
    """Filtered WebSocket — client sends its classification filter as first message."""
    from starlette.websockets import WebSocketDisconnect  # noqa: PLC0415

    if not await _ws_authenticate(websocket):
        return

    await _ws_manager.connect(websocket)
    try:
        classification = await websocket.receive_text()
        _ws_manager.set_filter(websocket, classification.strip().upper())
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _log.debug("WebSocket /ws/filtered client disconnected normally")
    except Exception as exc:  # noqa: BLE001
        _log.warning("WebSocket /ws/filtered unexpected error: %s", exc)
    finally:
        await _ws_manager.disconnect(websocket)
