"""FastAPI application entry point for BSCCL NetWatch.

Startup sequence:
  1. Load settings from .env
  2. Create DB tables (idempotent)
  3. Start SyslogReceiver (Loki WS / HTTP / UDP)

Shutdown sequence:
  1. Stop SyslogReceiver gracefully

Routes:
  GET  /health         — Health check
  WS   /ws             — Live alert WebSocket (all events)
  WS   /ws/filtered    — Live alert WebSocket (filtered by classification)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI, WebSocket

from src.api.routes import router
from src.api.websocket import WebSocketManager
from src.config import get_settings
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.core.syslog_receiver import SyslogReceiver
from src.database.migrations import create_tables, get_engine

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application-level singletons
# ---------------------------------------------------------------------------

_ws_manager = WebSocketManager()


# ---------------------------------------------------------------------------
# Ingestion callback
# ---------------------------------------------------------------------------


async def _on_syslog_line(raw_line: str) -> None:
    """Process a raw syslog line: parse → enrich → broadcast → count.

    Currently: parse, enrich, and broadcast over WebSocket.
    DB storage and notification dispatch are wired in Milestone 7.

    Parameters
    ----------
    raw_line:
        A single raw syslog line string from Loki or UDP.
    """
    parsed = parse_syslog(raw_line)
    if parsed is None:
        return

    enriched = enrich(parsed)

    # Broadcast to all connected WebSocket clients
    await _ws_manager.broadcast(
        {
            "type": "alert",
            "classification": enriched.classification,
            "device": enriched.device_name,
            "mnemonic": enriched.parsed.mnemonic,
            "message": enriched.parsed.message,
            "timestamp": enriched.parsed.timestamp.isoformat(),
        }
    )

    # Update the route counter (best-effort; import error is non-fatal)
    try:  # noqa: SIM105
        from src.api.routes import increment_alerts_processed  # noqa: PLC0415

        increment_alerts_processed()
    except Exception:  # noqa: BLE001,S110
        _log.debug("Could not increment alerts_processed counter")


# ---------------------------------------------------------------------------
# Lifespan context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    """Application lifespan: startup and shutdown logic.

    Startup
    -------
    1. Load settings and create DB engine + tables.
    2. Start the syslog receiver (async background task).

    Shutdown
    --------
    1. Stop the syslog receiver gracefully.
    2. Dispose the DB engine.
    """
    settings = get_settings()

    # ── Database ───────────────────────────────────────────────────────────
    engine = await get_engine(settings.database_url)
    await create_tables(engine)
    _log.info("Database ready: %s", settings.database_url)

    # ── Syslog receiver ────────────────────────────────────────────────────
    receiver = SyslogReceiver(settings, _on_syslog_line)
    await receiver.start()
    _log.info("SyslogReceiver started (mode: %s)", settings.syslog_mode)

    yield  # application runs here

    # ── Shutdown ───────────────────────────────────────────────────────────
    _log.info("Shutting down SyslogReceiver…")
    await receiver.stop()

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

# ── REST API router ─────────────────────────────────────────────────────────
app.include_router(router)


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
