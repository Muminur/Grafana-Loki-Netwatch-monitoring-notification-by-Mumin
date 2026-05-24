"""WebSocket connection manager for BSCCL NetWatch live dashboard.

Maintains a pool of connected browser clients and provides broadcast
helpers for pushing alert data in real time.

Supports optional per-client classification filtering:
  - Clients that have not set a filter receive all broadcasts.
  - Clients that have set a filter (via ``set_filter``) only receive
    messages whose ``classification`` field matches their filter.

Hardening features
------------------
* ``MAX_CONNECTIONS`` cap — new connections beyond this limit are immediately
  rejected (close code 1008) to prevent unbounded memory growth.
* Per-send timeout (``SEND_TIMEOUT_SECONDS``) — a hung or slow client cannot
  stall the broadcast loop; its send is cancelled and the client is removed.
* Explicit disconnect vs. error distinction — normal ``WebSocketDisconnect``
  and ``asyncio.CancelledError`` / ``asyncio.TimeoutError`` are logged at
  DEBUG; unexpected exceptions are logged at WARNING so they surface in
  production logs without spam.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import TYPE_CHECKING

from fastapi import WebSocketDisconnect

from src.metrics import set_ws_connections

if TYPE_CHECKING:
    from fastapi import WebSocket

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants (intentionally NOT in config.py — self-contained)
# ---------------------------------------------------------------------------

#: Hard cap on simultaneous WebSocket connections.
#: Requests beyond this are refused immediately (close code 1008 — Policy
#: Violation) to prevent memory exhaustion under heavy load.
MAX_CONNECTIONS: int = 1000

#: Per-client send timeout in seconds.  A client that does not drain its
#: receive buffer within this window is considered hung and is dropped.
SEND_TIMEOUT_SECONDS: float = 5.0


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

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept and register a new WebSocket connection.

        If the pool has reached ``MAX_CONNECTIONS`` the connection is accepted
        then immediately closed with code 1008 (Policy Violation) and ``False``
        is returned.  Callers **must** check the return value and bail out of
        their handler when ``False`` is returned.

        Parameters
        ----------
        websocket:
            The incoming FastAPI ``WebSocket`` instance.

        Returns
        -------
        bool
            ``True`` if the connection was admitted; ``False`` if the cap was
            reached and the client was rejected.
        """
        await websocket.accept()

        if len(self._connections) >= MAX_CONNECTIONS:
            _log.warning(
                "WS connection cap (%d) reached — rejecting new client",
                MAX_CONNECTIONS,
            )
            with contextlib.suppress(Exception):
                await websocket.close(code=1008)
            return False

        self._connections.append(websocket)
        self._filters[id(websocket)] = None
        set_ws_connections(len(self._connections))
        _log.debug("WS connected (total: %d)", len(self._connections))
        return True

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
        set_ws_connections(len(self._connections))
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
    # Broadcast helpers
    # ------------------------------------------------------------------

    async def _send_with_backpressure(self, websocket: WebSocket, payload: str) -> None:
        """Send *payload* to *websocket* with a per-client timeout.

        Raises
        ------
        asyncio.TimeoutError
            If the send did not complete within ``SEND_TIMEOUT_SECONDS``.
        WebSocketDisconnect
            If the client disconnected before or during the send.
        Exception
            Any other unexpected send-level error.
        """
        await asyncio.wait_for(
            websocket.send_text(payload), timeout=SEND_TIMEOUT_SECONDS
        )

    async def broadcast(self, data: dict) -> None:  # type: ignore[type-arg]
        """Send *data* as JSON to all connected clients.

        Clients that fail to receive (e.g. already closed) are removed
        from the pool.  Normal disconnects are logged at DEBUG; unexpected
        errors are logged at WARNING.  A hung client will be dropped after
        ``SEND_TIMEOUT_SECONDS`` so it cannot block other broadcasts.

        Parameters
        ----------
        data:
            Any JSON-serialisable dict.
        """
        payload = json.dumps(data)
        stale: list[WebSocket] = []

        cancelled = False
        for ws in list(self._connections):
            try:
                await self._send_with_backpressure(ws, payload)
            except asyncio.CancelledError:
                # Outer task was cancelled — note the WS as stale then stop
                # the loop and re-raise so the caller's cancellation propagates.
                _log.debug("WS broadcast cancelled — dropping client and re-raising")
                stale.append(ws)
                cancelled = True
                break
            except WebSocketDisconnect:
                _log.debug("WS client disconnected normally during broadcast")
                stale.append(ws)
            except TimeoutError:
                _log.debug("WS client timed out during broadcast — dropping")
                stale.append(ws)
            except Exception:  # noqa: BLE001
                _log.warning(
                    "Unexpected error sending to WS client — dropping",
                    exc_info=True,
                )
                stale.append(ws)

        for ws in stale:
            await self.disconnect(ws)

        if cancelled:
            raise asyncio.CancelledError

    async def broadcast_filtered(
        self,
        data: dict,  # type: ignore[type-arg]
        classification: str,
    ) -> None:
        """Send *data* only to clients whose filter matches *classification*.

        Clients with no filter (filter is ``None``) receive all broadcasts.
        Clients with a filter only receive messages where the filter value
        equals *classification*.

        Backpressure and error handling follow the same rules as
        :meth:`broadcast`.

        Parameters
        ----------
        data:
            Any JSON-serialisable dict.
        classification:
            The classification label of this event (e.g. ``"CRITICAL"``).
        """
        payload = json.dumps(data)
        stale: list[WebSocket] = []

        cancelled = False
        for ws in list(self._connections):
            client_filter = self._filters.get(id(ws))
            # Send if: no filter set, or filter matches classification
            if client_filter is None or client_filter == classification:
                try:
                    await self._send_with_backpressure(ws, payload)
                except asyncio.CancelledError:
                    _log.debug(
                        "WS filtered broadcast cancelled"
                        " — dropping client and re-raising"
                    )
                    stale.append(ws)
                    cancelled = True
                    break
                except WebSocketDisconnect:
                    _log.debug(
                        "WS client disconnected normally during filtered broadcast"
                    )
                    stale.append(ws)
                except TimeoutError:
                    _log.debug(
                        "WS client timed out during filtered broadcast — dropping"
                    )
                    stale.append(ws)
                except Exception:  # noqa: BLE001
                    _log.warning(
                        "Unexpected error sending to WS client (filtered) — dropping",
                        exc_info=True,
                    )
                    stale.append(ws)

        for ws in stale:
            await self.disconnect(ws)

        if cancelled:
            raise asyncio.CancelledError

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def active_connections(self) -> int:
        """Number of currently connected WebSocket clients."""
        return len(self._connections)
