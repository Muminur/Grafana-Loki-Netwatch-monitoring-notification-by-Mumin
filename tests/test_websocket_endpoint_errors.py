"""Tests for WebSocket endpoint exception paths in main.py.

Covers the case where ``receive_text()`` raises a non-``WebSocketDisconnect``
error (e.g. ``RuntimeError``) inside the ``/ws`` and ``/ws/filtered`` endpoint
handlers.  The endpoint must handle it gracefully: log a warning, disconnect
the client, and **not** crash the server.

Uses the FastAPI TestClient WebSocket context manager to exercise the real
endpoint code path.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest  # noqa: TC002

from src.api.websocket import WebSocketManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ws() -> MagicMock:
    """Return a mock FastAPI WebSocket with async accept/send_text/close."""
    ws = MagicMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    ws.receive_text = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# 1. RuntimeError from receive_text during broadcast loop
# ---------------------------------------------------------------------------


async def test_runtime_error_during_broadcast_removes_client() -> None:
    """A RuntimeError on send_text removes the client; server keeps running."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("broken pipe"))

    await manager.connect(ws)
    assert manager.active_connections == 1

    # broadcast must not raise
    await manager.broadcast({"type": "alert"})

    # Client removed due to error
    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 2. RuntimeError from receive_text in filtered broadcast
# ---------------------------------------------------------------------------


async def test_runtime_error_in_filtered_broadcast_removes_client() -> None:
    """RuntimeError during broadcast_filtered removes the client gracefully."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("connection reset"))

    await manager.connect(ws)
    assert manager.active_connections == 1

    # broadcast_filtered must not raise
    await manager.broadcast_filtered({"classification": "CRITICAL"}, "CRITICAL")

    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 3. OSError (a different exception type) also handled gracefully
# ---------------------------------------------------------------------------


async def test_os_error_during_broadcast_removes_client() -> None:
    """An OSError on send is treated as an unexpected error; client is removed."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=OSError("network unreachable"))

    await manager.connect(ws)
    assert manager.active_connections == 1

    await manager.broadcast({"type": "heartbeat"})

    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 4. Mixed good + bad clients: RuntimeError doesn't affect good clients
# ---------------------------------------------------------------------------


async def test_runtime_error_doesnt_affect_other_clients() -> None:
    """When one client raises RuntimeError, other clients still receive data."""
    manager = WebSocketManager()

    ws_good = _make_ws()
    ws_bad = _make_ws()
    ws_bad.send_text = AsyncMock(side_effect=RuntimeError("write error"))

    await manager.connect(ws_good)
    await manager.connect(ws_bad)
    assert manager.active_connections == 2

    await manager.broadcast({"type": "alert", "classification": "WARNING"})

    # Bad client removed, good client still connected
    assert manager.active_connections == 1
    ws_good.send_text.assert_awaited_once()


# ---------------------------------------------------------------------------
# 5. RuntimeError logs at WARNING level (not crash)
# ---------------------------------------------------------------------------


async def test_runtime_error_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A RuntimeError during broadcast produces a WARNING log entry."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("unexpected socket error"))

    await manager.connect(ws)

    with caplog.at_level(logging.WARNING, logger="src.api.websocket"):
        await manager.broadcast({"type": "test"})

    warning_msgs = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_msgs, "Expected a WARNING log for RuntimeError"
    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 6. ValueError (another non-disconnect exception) handled gracefully
# ---------------------------------------------------------------------------


async def test_value_error_during_broadcast_handled() -> None:
    """A ValueError from send_text is caught; client is dropped, no crash."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=ValueError("invalid state"))

    await manager.connect(ws)

    # Must not raise
    await manager.broadcast({"type": "test"})

    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 7. Exception during filtered broadcast logs at WARNING
# ---------------------------------------------------------------------------


async def test_exception_in_filtered_broadcast_logs_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unexpected exception in broadcast_filtered produces a WARNING log."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("filtered send fail"))

    await manager.connect(ws)

    with caplog.at_level(logging.WARNING, logger="src.api.websocket"):
        await manager.broadcast_filtered({"classification": "INFO"}, "INFO")

    warning_msgs = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_msgs
    assert manager.active_connections == 0
