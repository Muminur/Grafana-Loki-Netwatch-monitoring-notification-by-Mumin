"""Tests for WebSocketManager hardening features.

Covers:
  1. Connection cap (MAX_CONNECTIONS) — connections beyond the limit are rejected.
  2. Backpressure safety — a slow/hung client does not block other broadcasts.
  3. Disconnect-vs-error distinction — normal disconnects are quiet; unexpected
     errors produce WARNING logs.
  4. Timeout-triggered removal — a client whose send exceeds SEND_TIMEOUT_SECONDS
     is dropped without blocking the rest of the broadcast loop.
  5. Healthy clients still receive broadcasts when a bad client is present.

All WebSocket objects are fakes/mocks — no real network sockets are opened.
asyncio.wait_for is patched where needed so tests run at full speed.
"""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest  # noqa: TC002
from fastapi import WebSocketDisconnect

import src.api.websocket as ws_module
from src.api.websocket import MAX_CONNECTIONS, SEND_TIMEOUT_SECONDS, WebSocketManager

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ws() -> MagicMock:
    """Return a mock FastAPI WebSocket with async accept/send_text/close."""
    ws = MagicMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    ws.close = AsyncMock()
    return ws


# ---------------------------------------------------------------------------
# 1. Connection cap enforcement
# ---------------------------------------------------------------------------


async def test_connection_cap_admits_up_to_max(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exactly MAX_CONNECTIONS clients are admitted without rejection."""
    cap = 5
    monkeypatch.setattr(ws_module, "MAX_CONNECTIONS", cap)

    manager = WebSocketManager()
    for _ in range(cap):
        ws = _make_ws()
        result = await manager.connect(ws)
        assert result is True

    assert manager.active_connections == cap


async def test_connection_cap_rejects_beyond_max(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The (MAX_CONNECTIONS + 1)th client is rejected and closed."""
    cap = 3
    monkeypatch.setattr(ws_module, "MAX_CONNECTIONS", cap)

    manager = WebSocketManager()
    for _ in range(cap):
        ws = _make_ws()
        await manager.connect(ws)

    overflow = _make_ws()
    result = await manager.connect(overflow)

    assert result is False
    # The overflow client must have been closed (code 1008)
    overflow.close.assert_awaited_once()
    kw = overflow.close.call_args[1]
    pos = overflow.close.call_args[0]
    close_code = kw.get("code") or (pos[0] if pos else None)
    assert close_code == 1008
    # Pool count must not have grown
    assert manager.active_connections == cap


async def test_connection_cap_rejected_client_not_in_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected client is NOT added to the connection pool or filter map."""
    cap = 2
    monkeypatch.setattr(ws_module, "MAX_CONNECTIONS", cap)

    manager = WebSocketManager()
    admitted: list[MagicMock] = []
    for _ in range(cap):
        ws = _make_ws()
        await manager.connect(ws)
        admitted.append(ws)

    overflow = _make_ws()
    await manager.connect(overflow)

    # overflow must not be reachable via broadcast
    await manager.broadcast({"type": "test"})
    overflow.send_text.assert_not_awaited()
    # Admitted clients still receive it
    for ws in admitted:
        ws.send_text.assert_awaited_once()


async def test_reject_when_cap_close_errors_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If closing the rejected client itself raises, connect() must NOT propagate."""
    cap = 1
    monkeypatch.setattr(ws_module, "MAX_CONNECTIONS", cap)

    manager = WebSocketManager()
    ws_first = _make_ws()
    await manager.connect(ws_first)

    overflow = _make_ws()
    overflow.close = AsyncMock(side_effect=RuntimeError("already closed"))
    # Must not raise
    result = await manager.connect(overflow)
    assert result is False


# ---------------------------------------------------------------------------
# 2. Backpressure — slow / hung client is dropped without blocking others
# ---------------------------------------------------------------------------


async def test_timed_out_client_is_removed(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client whose send times out is removed; healthy clients still receive."""
    manager = WebSocketManager()

    ws_good = _make_ws()
    ws_slow = _make_ws()

    await manager.connect(ws_good)
    await manager.connect(ws_slow)
    assert manager.active_connections == 2

    # Make ws_slow's send_text hang (never return)
    async def _hang(*_args: object, **_kwargs: object) -> None:
        await asyncio.sleep(9999)

    ws_slow.send_text = _hang  # type: ignore[method-assign]

    # Patch wait_for so the timeout fires immediately
    real_wait_for = asyncio.wait_for

    async def _fast_wait_for(
        coro: object, *, timeout: float | None = None, **kwargs: object
    ) -> object:
        if timeout is not None and timeout > 0.01:
            timeout = 0.001  # collapse to near-zero for the test
        return await real_wait_for(coro, timeout=timeout, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "wait_for", _fast_wait_for)

    await manager.broadcast({"type": "test"})

    # Slow client should be gone
    assert manager.active_connections == 1
    # Good client received the message
    ws_good.send_text.assert_awaited_once()


async def test_timeout_in_filtered_broadcast(monkeypatch: pytest.MonkeyPatch) -> None:
    """broadcast_filtered also drops a timed-out client."""
    manager = WebSocketManager()

    ws_good = _make_ws()
    ws_slow = _make_ws()

    await manager.connect(ws_good)
    await manager.connect(ws_slow)

    async def _hang(*_args: object, **_kwargs: object) -> None:
        await asyncio.sleep(9999)

    ws_slow.send_text = _hang  # type: ignore[method-assign]

    real_wait_for = asyncio.wait_for

    async def _fast_wait_for(
        coro: object, *, timeout: float | None = None, **kwargs: object
    ) -> object:
        if timeout is not None and timeout > 0.01:
            timeout = 0.001
        return await real_wait_for(coro, timeout=timeout, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(asyncio, "wait_for", _fast_wait_for)

    await manager.broadcast_filtered({"classification": "CRITICAL"}, "CRITICAL")

    assert manager.active_connections == 1
    ws_good.send_text.assert_awaited_once()


# ---------------------------------------------------------------------------
# 3. Disconnect vs error logging
# ---------------------------------------------------------------------------


async def test_normal_disconnect_logged_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """WebSocketDisconnect during broadcast is logged at DEBUG, not WARNING."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=WebSocketDisconnect(code=1001))

    await manager.connect(ws)

    with caplog.at_level(logging.DEBUG, logger="src.api.websocket"):
        await manager.broadcast({"type": "test"})

    # No WARNING entries for a normal disconnect
    warning_msgs = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not warning_msgs

    # Client removed
    assert manager.active_connections == 0


async def test_unexpected_error_logged_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unexpected RuntimeError during send is logged at WARNING."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=RuntimeError("socket broken"))

    await manager.connect(ws)

    with caplog.at_level(logging.WARNING, logger="src.api.websocket"):
        await manager.broadcast({"type": "test"})

    warning_msgs = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_msgs, "Expected at least one WARNING log for unexpected error"
    assert manager.active_connections == 0


async def test_disconnect_in_filtered_broadcast_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """WebSocketDisconnect in broadcast_filtered does not produce a WARNING."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=WebSocketDisconnect(code=1001))

    await manager.connect(ws)

    with caplog.at_level(logging.DEBUG, logger="src.api.websocket"):
        await manager.broadcast_filtered({"classification": "CRITICAL"}, "CRITICAL")

    warning_msgs = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert not warning_msgs
    assert manager.active_connections == 0


async def test_unexpected_error_in_filtered_broadcast_logged_at_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unexpected error in broadcast_filtered produces a WARNING log."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=OSError("write failed"))

    await manager.connect(ws)

    with caplog.at_level(logging.WARNING, logger="src.api.websocket"):
        await manager.broadcast_filtered({"classification": "INFO"}, "INFO")

    warning_msgs = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warning_msgs
    assert manager.active_connections == 0


# ---------------------------------------------------------------------------
# 3b. CancelledError is re-raised after cleanup — not swallowed
# ---------------------------------------------------------------------------


async def test_cancelled_error_propagates_from_broadcast() -> None:
    """CancelledError in broadcast is re-raised after the stale client is removed."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=asyncio.CancelledError())

    await manager.connect(ws)

    with pytest.raises(asyncio.CancelledError):
        await manager.broadcast({"type": "test"})

    # The stale client must have been removed before the re-raise
    assert manager.active_connections == 0


async def test_cancelled_error_propagates_from_broadcast_filtered() -> None:
    """CancelledError during broadcast_filtered is re-raised after cleanup."""
    manager = WebSocketManager()
    ws = _make_ws()
    ws.send_text = AsyncMock(side_effect=asyncio.CancelledError())

    await manager.connect(ws)

    with pytest.raises(asyncio.CancelledError):
        await manager.broadcast_filtered({"classification": "CRITICAL"}, "CRITICAL")

    assert manager.active_connections == 0


async def test_cancelled_error_removes_stale_and_reraises_mid_loop() -> None:
    """When CancelledError fires mid-broadcast, processed-so-far are cleaned up."""
    manager = WebSocketManager()
    ws_good = _make_ws()
    ws_cancelled = _make_ws()
    ws_cancelled.send_text = AsyncMock(side_effect=asyncio.CancelledError())

    await manager.connect(ws_good)
    await manager.connect(ws_cancelled)

    with pytest.raises(asyncio.CancelledError):
        await manager.broadcast({"type": "test"})

    # The cancelled client must be removed; good client may or may not have
    # received the message depending on iteration order — but count must be 1.
    assert manager.active_connections == 1


# ---------------------------------------------------------------------------
# 4. Broadcast still reaches healthy clients when one is failing
# ---------------------------------------------------------------------------


async def test_healthy_clients_receive_after_bad_client_dropped() -> None:
    """Good clients receive broadcast even when a bad client raises mid-loop."""
    manager = WebSocketManager()

    ws_good1 = _make_ws()
    ws_bad = _make_ws()
    ws_good2 = _make_ws()

    ws_bad.send_text = AsyncMock(side_effect=RuntimeError("broken pipe"))

    await manager.connect(ws_good1)
    await manager.connect(ws_bad)
    await manager.connect(ws_good2)

    data = {"type": "alert", "classification": "CRITICAL"}
    await manager.broadcast(data)

    ws_good1.send_text.assert_awaited_once()
    ws_good2.send_text.assert_awaited_once()

    payload = json.loads(ws_good1.send_text.call_args[0][0])
    assert payload["classification"] == "CRITICAL"

    assert manager.active_connections == 2


async def test_multiple_bad_clients_all_removed() -> None:
    """All bad clients in a single broadcast are removed; good ones kept."""
    manager = WebSocketManager()

    ws_good = _make_ws()
    bads = [_make_ws() for _ in range(3)]
    for ws in bads:
        ws.send_text = AsyncMock(side_effect=WebSocketDisconnect())

    await manager.connect(ws_good)
    for ws in bads:
        await manager.connect(ws)

    assert manager.active_connections == 4

    await manager.broadcast({"type": "heartbeat"})

    assert manager.active_connections == 1
    ws_good.send_text.assert_awaited_once()


# ---------------------------------------------------------------------------
# 5. Module constants are correct types and values
# ---------------------------------------------------------------------------


def test_max_connections_is_positive_int() -> None:
    """MAX_CONNECTIONS must be a positive integer."""
    assert isinstance(MAX_CONNECTIONS, int)
    assert MAX_CONNECTIONS > 0


def test_send_timeout_seconds_is_positive_float() -> None:
    """SEND_TIMEOUT_SECONDS must be a positive number."""
    assert isinstance(SEND_TIMEOUT_SECONDS, float)
    assert SEND_TIMEOUT_SECONDS > 0


# ---------------------------------------------------------------------------
# 6. Backward-compat: connect() bool return — old callers that ignore it still work
# ---------------------------------------------------------------------------


async def test_connect_return_value_ignored_backward_compat() -> None:
    """Callers that do not capture the return value of connect() still work."""
    manager = WebSocketManager()
    ws = _make_ws()
    # Simply await without capturing — must not raise
    await manager.connect(ws)
    assert manager.active_connections == 1


# ---------------------------------------------------------------------------
# 7. broadcast uses asyncio.wait_for with SEND_TIMEOUT_SECONDS per client
# ---------------------------------------------------------------------------


async def test_broadcast_uses_module_timeout_via_wait_for() -> None:
    """broadcast() wraps each send in wait_for with SEND_TIMEOUT_SECONDS."""
    manager = WebSocketManager()
    ws = _make_ws()
    await manager.connect(ws)

    captured_timeout: list[float] = []

    # Capture the timeout arg then return immediately (no recursion)
    async def _spy_wait_for(
        coro: object, *, timeout: float | None = None, **_kw: object
    ) -> None:
        if timeout is not None:
            captured_timeout.append(timeout)
        # Close the coroutine cleanly to avoid ResourceWarning
        if hasattr(coro, "close"):
            coro.close()  # type: ignore[union-attr]

    with patch("src.api.websocket.asyncio.wait_for", side_effect=_spy_wait_for):
        await manager.broadcast({"type": "test"})

    assert captured_timeout, "wait_for was never called with a timeout"
    assert captured_timeout[0] == SEND_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# 8. WebSocket authentication — rejection tests
# ---------------------------------------------------------------------------


async def test_ws_auth_rejects_missing_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, a WS connection with no token is closed with 4001."""
    from src.config import get_settings
    from src.main import _ws_authenticate

    monkeypatch.setenv("API_KEY", "secret-ws-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    ws = _make_ws()
    ws.query_params = {}

    try:
        result = await _ws_authenticate(ws)
        assert result is False
        ws.accept.assert_awaited_once()
        ws.close.assert_awaited_once()
        close_kw = ws.close.call_args[1]
        assert close_kw.get("code") == 4001
        assert close_kw.get("reason") == "Unauthorized"
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


async def test_ws_auth_rejects_wrong_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Incorrect token is closed with 4001 when API_KEY is configured."""
    from src.config import get_settings
    from src.main import _ws_authenticate

    monkeypatch.setenv("API_KEY", "correct-key-123")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    ws = _make_ws()
    ws.query_params = {"token": "wrong-key-456"}

    try:
        result = await _ws_authenticate(ws)
        assert result is False
        ws.accept.assert_awaited_once()
        ws.close.assert_awaited_once()
        close_kw = ws.close.call_args[1]
        assert close_kw.get("code") == 4001
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


async def test_ws_auth_rejects_empty_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicitly empty token is rejected when API_KEY is set."""
    from src.config import get_settings
    from src.main import _ws_authenticate

    monkeypatch.setenv("API_KEY", "non-empty-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    ws = _make_ws()
    ws.query_params = {"token": ""}

    try:
        result = await _ws_authenticate(ws)
        assert result is False
        ws.accept.assert_awaited_once()
        ws.close.assert_awaited_once()
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


async def test_ws_auth_rejected_connection_not_added_to_manager(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rejected WS client must NOT appear in the connection pool."""
    from src.config import get_settings
    from src.main import _ws_authenticate

    monkeypatch.setenv("API_KEY", "pool-test-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    manager = WebSocketManager()
    ws = _make_ws()
    ws.query_params = {"token": "bad-token"}

    try:
        rejected = await _ws_authenticate(ws)
        assert rejected is False
        # Simulate: the endpoint returns early, never calls connect
        assert manager.active_connections == 0
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


async def test_ws_auth_uses_constant_time_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_ws_authenticate must use secrets.compare_digest (not ==) for token check."""
    import secrets as secrets_mod

    from src.config import get_settings
    from src.main import _ws_authenticate

    monkeypatch.setenv("API_KEY", "timing-safe-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    ws = _make_ws()
    ws.query_params = {"token": "timing-safe-key"}

    called_with: list[tuple[bytes, bytes]] = []
    original_compare = secrets_mod.compare_digest

    def spy_compare(a: bytes, b: bytes) -> bool:
        called_with.append((a, b))
        return original_compare(a, b)

    monkeypatch.setattr(secrets_mod, "compare_digest", spy_compare)

    try:
        result = await _ws_authenticate(ws)
        assert result is True
        assert called_with, "secrets.compare_digest was not called"
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()
