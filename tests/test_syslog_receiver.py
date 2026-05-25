"""Tests for SyslogReceiver — Loki WebSocket / HTTP poll / UDP fallback.

TDD: tests written BEFORE implementation (RED phase).
All external connections are mocked — no real network calls.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import websockets
import websockets.exceptions

from src.config import Settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------


def _make_loki_ws_message(line: str) -> str:
    """Build a Loki tail WebSocket JSON message wrapping a syslog line."""
    return json.dumps(
        {
            "streams": [
                {
                    "stream": {"job": "syslog"},
                    "values": [["1716408741000000000", line]],
                }
            ]
        }
    )


def _make_loki_http_response(line: str) -> dict:  # type: ignore[type-arg]
    """Build a Loki query_range HTTP JSON response wrapping a syslog line."""
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"job": "syslog"},
                    "values": [["1716408741000000000", line]],
                }
            ],
        },
    }


_SAMPLE_LOG = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Down - BGP Notification received (VRF: network) (AS: 399077)"
)


# ---------------------------------------------------------------------------
# 1. test_ws_receives_log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_receives_log() -> None:
    """Mock WebSocket delivers a log line → callback is called with that line."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")

    msg = _make_loki_ws_message(_SAMPLE_LOG)

    # Build a fake async context manager for websockets.connect
    mock_ws = AsyncMock()
    mock_ws.__aiter__ = MagicMock(return_value=aiter_from_list([msg]))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("src.core.syslog_receiver.websockets.connect", return_value=mock_cm):
        receiver = SyslogReceiver(settings, callback)
        await receiver._ws_tail_once()  # noqa: SLF001

    assert received == [
        _SAMPLE_LOG
    ], f"Expected callback with log line, got: {received}"


# ---------------------------------------------------------------------------
# 2. test_ws_reconnect_on_disconnect
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_reconnect_on_disconnect() -> None:
    """Mock disconnect causes receiver to attempt a reconnect (call count >= 2)."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []
    connect_calls: list[int] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")

    call_count = 0

    def fake_connect(*args, **kwargs):  # noqa: ARG001
        nonlocal call_count
        call_count += 1
        connect_calls.append(call_count)

        if call_count == 1:
            # First call: return a context manager whose __aenter__ raises
            cm = MagicMock()
            cm.__aenter__ = AsyncMock(
                side_effect=ConnectionError("Mock WebSocket disconnect")
            )
            cm.__aexit__ = AsyncMock(return_value=None)
            return cm
        # Second call: deliver one message then return cleanly
        mock_ws = AsyncMock()
        mock_ws.__aiter__ = MagicMock(
            return_value=aiter_from_list([_make_loki_ws_message(_SAMPLE_LOG)])
        )
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=mock_ws)
        cm.__aexit__ = AsyncMock(return_value=None)
        return cm

    with patch("src.core.syslog_receiver.websockets.connect", new=fake_connect):
        receiver = SyslogReceiver(settings, callback)
        await receiver._ws_tail_attempts(max_attempts=2, base_delay=0)  # noqa: SLF001

    assert len(connect_calls) >= 2, "Receiver must retry after disconnect"
    assert _SAMPLE_LOG in received


# ---------------------------------------------------------------------------
# 3. test_http_poll_receives_logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_poll_receives_logs() -> None:
    """Mock HTTP response with Loki format → callback called with log line."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")

    loki_response = _make_loki_http_response(_SAMPLE_LOG)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = loki_response

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=mock_client):
        receiver = SyslogReceiver(settings, callback)
        await receiver._http_poll_once()  # noqa: SLF001

    assert received == [
        _SAMPLE_LOG
    ], f"Expected log line via HTTP poll, got: {received}"


# ---------------------------------------------------------------------------
# 4. test_http_poll_skips_empty_response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_poll_skips_empty_response() -> None:
    """HTTP poll with empty Loki result → callback not called."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")

    empty_response: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [],
        },
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = empty_response

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=mock_client):
        receiver = SyslogReceiver(settings, callback)
        await receiver._http_poll_once()  # noqa: SLF001

    assert received == [], "Empty Loki response must not trigger callback"


# ---------------------------------------------------------------------------
# 5. test_extract_lines_from_loki_ws_message
# ---------------------------------------------------------------------------


def test_extract_lines_from_loki_ws_message() -> None:
    """_extract_lines_from_ws correctly parses Loki tail JSON."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    msg = _make_loki_ws_message(_SAMPLE_LOG)
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    lines = receiver._extract_lines_from_ws(msg)  # noqa: SLF001
    assert lines == [_SAMPLE_LOG]


# ---------------------------------------------------------------------------
# 6. test_extract_lines_multi_stream
# ---------------------------------------------------------------------------


def test_extract_lines_multi_stream() -> None:
    """Multiple streams in a single Loki message → all lines extracted."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    line1 = "syslog line one"
    line2 = "syslog line two"
    msg = json.dumps(
        {
            "streams": [
                {
                    "stream": {"job": "syslog"},
                    "values": [
                        ["1716408741000000000", line1],
                        ["1716408742000000000", line2],
                    ],
                }
            ]
        }
    )
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    lines = receiver._extract_lines_from_ws(msg)  # noqa: SLF001
    assert line1 in lines
    assert line2 in lines


# ---------------------------------------------------------------------------
# 7. test_extract_lines_from_http_response
# ---------------------------------------------------------------------------


def test_extract_lines_from_http_response() -> None:
    """_extract_lines_from_http parses Loki query_range JSON correctly."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    resp = _make_loki_http_response(_SAMPLE_LOG)
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    lines = receiver._extract_lines_from_http(resp)  # noqa: SLF001
    assert lines == [_SAMPLE_LOG]


# ---------------------------------------------------------------------------
# 8. test_ws_tail_with_fallback_calls_http_on_ws_failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_tail_with_fallback_calls_http_on_ws_failure() -> None:
    """WS connection failure → _ws_tail_with_fallback falls back to HTTP poll."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, callback)

    # _ws_tail_once raises ConnectionError (WS unavailable)
    ws_fail = AsyncMock(side_effect=ConnectionError("WS unavailable"))

    loki_response = _make_loki_http_response(_SAMPLE_LOG)
    mock_http_resp = MagicMock()
    mock_http_resp.status_code = 200
    mock_http_resp.json.return_value = loki_response

    http_mock_client = AsyncMock()
    http_mock_client.get = AsyncMock(return_value=mock_http_resp)
    http_mock_client.__aenter__ = AsyncMock(return_value=http_mock_client)
    http_mock_client.__aexit__ = AsyncMock(return_value=None)

    # _http_poll_once succeeds; _ws_tail / _http_poll are replaced with no-ops
    # so _ws_tail_with_fallback doesn't run infinitely.
    async def noop_http_poll() -> None:
        pass

    async def noop_ws_tail() -> None:
        pass

    with (
        patch.object(receiver, "_ws_tail_once", ws_fail),
        patch.object(receiver, "_ws_tail", noop_ws_tail),
        patch.object(receiver, "_http_poll", noop_http_poll),
        patch(
            "src.core.syslog_receiver.httpx.AsyncClient",
            return_value=http_mock_client,
        ),
    ):
        await receiver._ws_tail_with_fallback()  # noqa: SLF001

    # HTTP poll once should have been called and delivered the log
    assert _SAMPLE_LOG in received


# ---------------------------------------------------------------------------
# 9. test_ws_tail_with_fallback_calls_udp_on_http_failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_tail_with_fallback_calls_udp_on_http_failure() -> None:
    """WS and HTTP both fail → _ws_tail_with_fallback falls back to UDP."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, callback)

    ws_fail = AsyncMock(side_effect=ConnectionError("WS unavailable"))
    http_fail = AsyncMock(side_effect=OSError("HTTP unavailable"))

    udp_called: list[bool] = []

    async def fake_udp_listen() -> None:
        udp_called.append(True)

    with (
        patch.object(receiver, "_ws_tail_once", ws_fail),
        patch.object(receiver, "_ws_tail", AsyncMock()),
        patch.object(receiver, "_http_poll_once", http_fail),
        patch.object(receiver, "_udp_listen", fake_udp_listen),
    ):
        await receiver._ws_tail_with_fallback()  # noqa: SLF001

    assert udp_called, "UDP fallback must be invoked when both WS and HTTP fail"


# ---------------------------------------------------------------------------
# 10. test_ws_tail_with_fallback_stays_on_ws_when_successful
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_tail_with_fallback_stays_on_ws_when_successful() -> None:
    """WS connects successfully → _ws_tail_with_fallback uses persistent _ws_tail."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, callback)

    msg = _make_loki_ws_message(_SAMPLE_LOG)
    mock_ws = AsyncMock()
    mock_ws.__aiter__ = MagicMock(return_value=aiter_from_list([msg]))

    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    http_poll_called: list[bool] = []

    async def track_http_poll_once() -> None:
        http_poll_called.append(True)

    persistent_ws_called: list[bool] = []

    async def track_ws_tail() -> None:
        persistent_ws_called.append(True)

    with (
        patch("src.core.syslog_receiver.websockets.connect", return_value=mock_cm),
        patch.object(receiver, "_ws_tail", track_ws_tail),
        patch.object(receiver, "_http_poll_once", track_http_poll_once),
    ):
        await receiver._ws_tail_with_fallback()  # noqa: SLF001

    assert persistent_ws_called, "Persistent _ws_tail must be called on WS success"
    assert not http_poll_called, "HTTP poll must NOT be called when WS succeeds"


# ---------------------------------------------------------------------------
# 11. test_ws_tail_with_fallback_websocket_exception_triggers_fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_tail_with_fallback_websocket_exception_triggers_fallback() -> None:
    """websockets.exceptions.WebSocketException → falls back to HTTP poll."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    ws_fail = AsyncMock(
        side_effect=websockets.exceptions.WebSocketException("bad handshake")
    )

    http_once_called: list[bool] = []

    async def track_http_once() -> None:
        http_once_called.append(True)

    async def noop_http_poll() -> None:
        pass

    with (
        patch.object(receiver, "_ws_tail_once", ws_fail),
        patch.object(receiver, "_ws_tail", AsyncMock()),
        patch.object(receiver, "_http_poll_once", track_http_once),
        patch.object(receiver, "_http_poll", noop_http_poll),
    ):
        await receiver._ws_tail_with_fallback()  # noqa: SLF001

    assert http_once_called, "HTTP poll must be attempted after WebSocketException"


# ---------------------------------------------------------------------------
# 12. test_http_client_reused_across_polls
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_client_reused_across_polls() -> None:
    """The same httpx.AsyncClient is reused across multiple _http_poll_once calls."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    loki_response = _make_loki_http_response(_SAMPLE_LOG)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = loki_response

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)

    constructor_calls = {"n": 0}
    original_return = mock_client

    def counting_constructor(**kwargs):  # noqa: ARG001
        constructor_calls["n"] += 1
        return original_return

    with patch(
        "src.core.syslog_receiver.httpx.AsyncClient",
        side_effect=counting_constructor,
    ):
        await receiver._http_poll_once()  # noqa: SLF001
        await receiver._http_poll_once()  # noqa: SLF001
        await receiver._http_poll_once()  # noqa: SLF001

    # The constructor should only be called once (lazy creation).
    assert constructor_calls["n"] == 1, (
        f"httpx.AsyncClient constructor called {constructor_calls['n']} times, "
        "expected 1 (client should be reused)"
    )


# ---------------------------------------------------------------------------
# 13. test_stop_closes_http_client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_closes_http_client() -> None:
    """stop() closes the persistent HTTP client if it was created."""
    from src.core.syslog_receiver import SyslogReceiver  # noqa: PLC0415

    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    mock_client = AsyncMock()
    mock_client.aclose = AsyncMock()
    receiver._http_client = mock_client  # noqa: SLF001

    await receiver.stop()

    mock_client.aclose.assert_awaited_once()
    assert receiver._http_client is None  # noqa: SLF001


# ---------------------------------------------------------------------------
# Utility: async iterator from list (needed for mock __aiter__)
# ---------------------------------------------------------------------------


def aiter_from_list(items: list[str]) -> AsyncIterator[str]:
    """Return an async iterator that yields each item in *items* then stops."""

    async def _gen() -> AsyncIterator[str]:
        for item in items:
            yield item

    return _gen()
