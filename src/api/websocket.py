"""WebSocket connection manager for BSCCL NetWatch live dashboard.

Maintains a pool of connected browser clients and provides broadcast
helpers for pushing alert data in real time.

Supports optional per-client classification filtering:
  - Clients that have not set a filter receive all broadcasts.
  - Clients that have set a filter (via ``set_filter``) only receive
    messages whose ``classification`` field matches their filter.
"""

from __future__ import annotations

import contextlib
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

_log = logging.getLogger(__name__)


class WebSocketManager:
    """Manage a pool of live WebSocket connections.

    Thread-safety: this manager is designed for a single-process asyncio
    server.  No locking is required because asyncio is cooperative.
    """

    def __init__(self) -> None:
        # All active WebSocket connections
        self._connections: list[WebSocket] = []
        # Per-connection classification filter (None = no filter = all events)
        self._filters: dict[int, str | None] = {}

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection.

        Parameters
        ----------
        websocket:
            The incoming FastAPI ``WebSocket`` instance.
        """
        await websocket.accept()
        self._connections.append(websocket)
        self._filters[id(websocket)] = None
        _log.debug("WS connected (total: %d)", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the pool.

        Safe to call even if *websocket* is not currently registered.

        Parameters
        ----------
        websocket:
            The ``WebSocket`` instance to remove.
        """
        with contextlib.suppress(ValueError):
            self._connections.remove(websocket)
        self._filters.pop(id(websocket), None)
        _log.debug("WS disconnected (total: %d)", len(self._connections))

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def set_filter(self, websocket: WebSocket, classification: str) -> None:
        """Set a classification filter for a specific client.

        Subsequent ``broadcast_filtered`` calls will only deliver messages
        to this client when the message's ``classification`` matches.

        Parameters
        ----------
        websocket:
            The client to configure.
        classification:
            One of ``CRITICAL``, ``WARNING``, ``INFO``, ``NOISE``,
            ``USER_LOGIN``.
        """
        self._filters[id(websocket)] = classification

    # ------------------------------------------------------------------
    # Broadcast
    # ------------------------------------------------------------------

    async def broadcast(self, data: dict) -> None:  # type: ignore[type-arg]
        """Send *data* as JSON to all connected clients.

        Clients that fail to receive (e.g. already closed) are silently
        removed from the pool.

        Parameters
        ----------
        data:
            Any JSON-serialisable dict.
        """
        payload = json.dumps(data)
        stale: list[WebSocket] = []

        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:  # noqa: BLE001
                _log.debug("Removing stale WebSocket connection")
                stale.append(ws)

        for ws in stale:
            await self.disconnect(ws)

    async def broadcast_filtered(
        self,
        data: dict,  # type: ignore[type-arg]
        classification: str,
    ) -> None:
        """Send *data* only to clients whose filter matches *classification*.

        Clients with no filter (filter is ``None``) receive all broadcasts.
        Clients with a filter only receive messages where the filter value
        equals *classification*.

        Parameters
        ----------
        data:
            Any JSON-serialisable dict.
        classification:
            The classification label of this event (e.g. ``"CRITICAL"``).
        """
        payload = json.dumps(data)
        stale: list[WebSocket] = []

        for ws in list(self._connections):
            client_filter = self._filters.get(id(ws))
            # Send if: no filter set, or filter matches classification
            if client_filter is None or client_filter == classification:
                try:
                    await ws.send_text(payload)
                except Exception:  # noqa: BLE001
                    _log.debug("Removing stale WebSocket connection")
                    stale.append(ws)

        for ws in stale:
            await self.disconnect(ws)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> int:
        """Number of currently connected WebSocket clients."""
        return len(self._connections)
