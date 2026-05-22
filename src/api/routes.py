"""REST API routes for BSCCL NetWatch.

Milestone 6: minimal health endpoint.
Milestone 7 will expand with alert list, incident, and stats endpoints.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter

router = APIRouter()

# Application start time (module-level; set when the module is first imported)
_APP_START: float = time.monotonic()

# Shared counters updated by the ingestion pipeline
_alerts_processed: int = 0
_active_connections: int = 0


def increment_alerts_processed() -> None:
    """Increment the global alert counter (called by the ingestion pipeline)."""
    global _alerts_processed  # noqa: PLW0603
    _alerts_processed += 1


def set_active_connections(count: int) -> None:
    """Update the WebSocket connection count (called by WebSocketManager)."""
    global _active_connections  # noqa: PLW0603
    _active_connections = count


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
