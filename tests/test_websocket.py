"""Tests for WebSocketManager — connect, broadcast, disconnect, filtering.

TDD approach.
- broadcast/disconnect/filter logic is tested directly with mock WebSocket objects.
- Integration tests (connect via TestClient) are kept separate from the async
  broadcast calls to avoid event-loop conflicts between TestClient threads and
  the asyncio event loop.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.api.websocket import WebSocketManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_websocket() -> MagicMock:
    """Return a mock FastAPI WebSocket with async accept/send_text methods."""
    ws = MagicMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# 1. test_websocket_connect_and_broadcast
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_connect_and_broadcast() -> None:
    """Connect a mock client, broadcast a dict, verify send_text is called."""
    manager = WebSocketManager()
    ws = _make_mock_websocket()

    await manager.connect(ws)
    assert manager.active_connections == 1

    data = {"type": "alert", "classification": "CRITICAL", "message": "BGP Down"}
    await manager.broadcast(data)

    ws.send_text.assert_awaited_once()
    call_arg = ws.send_text.call_args[0][0]
    parsed = json.loads(call_arg)
    assert parsed["classification"] == "CRITICAL"
    assert parsed["type"] == "alert"


# ---------------------------------------------------------------------------
# 2. test_websocket_disconnect_no_error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_disconnect_no_error() -> None:
    """Connect then disconnect — no exception; manager state is clean."""
    manager = WebSocketManager()
    ws = _make_mock_websocket()

    await manager.connect(ws)
    assert manager.active_connections == 1

    await manager.disconnect(ws)
    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 3. test_websocket_multiple_clients
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_multiple_clients() -> None:
    """Two clients connected; broadcast reaches both."""
    manager = WebSocketManager()
    ws1 = _make_mock_websocket()
    ws2 = _make_mock_websocket()

    await manager.connect(ws1)
    await manager.connect(ws2)
    assert manager.active_connections == 2

    data = {"type": "alert", "classification": "WARNING"}
    await manager.broadcast(data)

    ws1.send_text.assert_awaited_once()
    ws2.send_text.assert_awaited_once()

    payload1 = json.loads(ws1.send_text.call_args[0][0])
    payload2 = json.loads(ws2.send_text.call_args[0][0])
    assert payload1["classification"] == "WARNING"
    assert payload2["classification"] == "WARNING"


# ---------------------------------------------------------------------------
# 4. test_websocket_filtered_critical_only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_filtered_critical_only() -> None:
    """Client subscribes to CRITICAL → receives CRITICAL but not INFO."""
    manager = WebSocketManager()
    ws = _make_mock_websocket()

    await manager.connect(ws)
    manager.set_filter(ws, "CRITICAL")

    # Broadcast INFO — should NOT be delivered
    await manager.broadcast_filtered(
        {"type": "alert", "classification": "INFO"}, "INFO"
    )
    ws.send_text.assert_not_awaited()

    # Broadcast CRITICAL — SHOULD be delivered
    await manager.broadcast_filtered(
        {"type": "alert", "classification": "CRITICAL"}, "CRITICAL"
    )
    ws.send_text.assert_awaited_once()
    payload = json.loads(ws.send_text.call_args[0][0])
    assert payload["classification"] == "CRITICAL"


# ---------------------------------------------------------------------------
# 5. test_broadcast_to_empty_pool_no_error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broadcast_to_empty_pool_no_error() -> None:
    """Broadcast with no connected clients must not raise any exception."""
    manager = WebSocketManager()
    await manager.broadcast({"type": "heartbeat"})
    await manager.broadcast_filtered({"type": "heartbeat"}, "CRITICAL")


# ---------------------------------------------------------------------------
# 6. test_active_connections_count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_active_connections_count() -> None:
    """active_connections count is correct as clients connect/disconnect."""
    manager = WebSocketManager()

    assert manager.active_connections == 0

    ws1 = _make_mock_websocket()
    ws2 = _make_mock_websocket()

    await manager.connect(ws1)
    assert manager.active_connections == 1

    await manager.connect(ws2)
    assert manager.active_connections == 2

    await manager.disconnect(ws2)
    assert manager.active_connections == 1

    await manager.disconnect(ws1)
    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 7. test_stale_connection_removed_on_broadcast
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_connection_removed_on_broadcast() -> None:
    """A client whose send_text raises is silently removed during broadcast."""
    manager = WebSocketManager()
    ws_good = _make_mock_websocket()
    ws_stale = _make_mock_websocket()
    ws_stale.send_text = AsyncMock(side_effect=RuntimeError("connection closed"))

    await manager.connect(ws_good)
    await manager.connect(ws_stale)
    assert manager.active_connections == 2

    await manager.broadcast({"type": "alert"})

    # Stale connection should have been removed
    assert manager.active_connections == 1
    # Good client received the message
    ws_good.send_text.assert_awaited_once()


# ---------------------------------------------------------------------------
# 8. test_no_filter_receives_all_classifications
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_filter_receives_all_classifications() -> None:
    """A client with no filter set receives all broadcast_filtered messages."""
    manager = WebSocketManager()
    ws = _make_mock_websocket()

    await manager.connect(ws)
    # No set_filter called — default is None (receive everything)

    await manager.broadcast_filtered({"classification": "INFO"}, "INFO")
    await manager.broadcast_filtered({"classification": "CRITICAL"}, "CRITICAL")
    await manager.broadcast_filtered({"classification": "WARNING"}, "WARNING")

    assert ws.send_text.await_count == 3


# ---------------------------------------------------------------------------
# 9. test_disconnect_twice_no_error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disconnect_twice_no_error() -> None:
    """Calling disconnect twice on the same websocket must not raise."""
    manager = WebSocketManager()
    ws = _make_mock_websocket()

    await manager.connect(ws)
    await manager.disconnect(ws)
    # Second disconnect — safe
    await manager.disconnect(ws)
    assert manager.active_connections == 0
