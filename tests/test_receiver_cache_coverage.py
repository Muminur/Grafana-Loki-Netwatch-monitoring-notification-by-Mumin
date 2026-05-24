"""Coverage-focused tests for ``src.database.as_cache`` and
``src.core.syslog_receiver``.

These exercise the external-lookup / cache-write branches of the AS cache
and the HTTP-poll / WebSocket-mode-selection / UDP / error paths of the
syslog receiver.  Every network boundary (httpx, websockets, UDP socket) is
mocked — no real I/O, no real sleeps, no real sockets.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
import websockets.exceptions
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.config import Settings
from src.core.syslog_receiver import SyslogReceiver
from src.database.as_cache import (
    cache_as_lookup,
    get_cached_as,
    resolve_as_name,
)
from src.database.migrations import create_tables, get_engine
from src.database.models import ASCache

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"

# An ASN that is NOT present in the static AS database, so resolve_as_name
# falls through to the cache / external-lookup branches.
_UNKNOWN_ASN = 65999


# ===========================================================================
# Fixtures
# ===========================================================================


@pytest_asyncio.fixture
async def session() -> AsyncIterator[AsyncSession]:
    """In-memory SQLite async session (never touches the real DB file)."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as _session:
        yield _session
    await engine.dispose()


def _aiter_from_list(items: list[str | bytes]) -> AsyncIterator[str | bytes]:
    """Async iterator yielding each item then stopping (for mock __aiter__)."""

    async def _gen() -> AsyncIterator[str | bytes]:
        for item in items:
            yield item

    return _gen()


def _http_payload(*lines: str, ts_start: int = 1_716_408_741_000_000_000) -> dict:
    """Build a Loki query_range JSON payload with one value per line."""
    values = [[str(ts_start + i), line] for i, line in enumerate(lines)]
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": values}],
        },
    }


def _mock_http_client(response: MagicMock) -> AsyncMock:
    """Build an async-context-manager httpx client returning *response*."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


# ===========================================================================
# as_cache: get_cached_as missing-record branch (line 45)
# ===========================================================================


@pytest.mark.asyncio
async def test_get_cached_as_returns_none_when_absent(session: AsyncSession) -> None:
    """No row for the ASN → returns None (covers the early ``return None``)."""
    result = await get_cached_as(session, asn=_UNKNOWN_ASN)
    assert result is None


# ===========================================================================
# as_cache: cache_as_lookup update-existing branch (lines 91-97)
# ===========================================================================


@pytest.mark.asyncio
async def test_cache_as_lookup_updates_existing_row(session: AsyncSession) -> None:
    """Caching the same ASN twice updates the row in-place (no duplicate)."""
    first = await cache_as_lookup(
        session, asn=64500, name="Old Name", as_type="t1", source="peeringdb"
    )
    assert first.name == "Old Name"

    updated = await cache_as_lookup(
        session, asn=64500, name="New Name", as_type="t2", source="bgpview"
    )

    # Same primary key, mutated fields, fresh timestamp.
    assert updated.asn == 64500
    assert updated.name == "New Name"
    assert updated.as_type == "t2"
    assert updated.source == "bgpview"

    # Only one row exists for the ASN.
    from sqlalchemy import func, select

    count = await session.scalar(
        select(func.count()).select_from(ASCache).where(ASCache.asn == 64500)
    )
    assert count == 1


# ===========================================================================
# as_cache: resolve_as_name — every branch (lines 124-163)
# ===========================================================================


@pytest.mark.asyncio
async def test_resolve_as_name_rejects_non_positive_asn(session: AsyncSession) -> None:
    """asn <= 0 short-circuits to "" (covers lines 124-125)."""
    assert await resolve_as_name(session, asn=0) == ""
    assert await resolve_as_name(session, asn=-7) == ""


@pytest.mark.asyncio
async def test_resolve_as_name_static_hit(session: AsyncSession) -> None:
    """Known ASN resolves from the static DB without touching cache/network."""
    # AS132602 == BSCCL in the static database.
    name = await resolve_as_name(session, asn=132602)
    assert name == "BSCCL"


@pytest.mark.asyncio
async def test_resolve_as_name_cache_hit(session: AsyncSession) -> None:
    """Unknown-to-static ASN that is already cached resolves from cache."""
    await cache_as_lookup(
        session,
        asn=_UNKNOWN_ASN,
        name="Cached Org",
        as_type="external",
        source="bigdatacloud",
    )

    # No api_key passed: if it tried the network it would return "".
    name = await resolve_as_name(session, asn=_UNKNOWN_ASN)
    assert name == "Cached Org"


@pytest.mark.asyncio
async def test_resolve_as_name_no_api_key_returns_empty(session: AsyncSession) -> None:
    """Unknown + uncached + no api_key → "" (covers lines 137-138)."""
    name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="")
    assert name == ""


@pytest.mark.asyncio
async def test_resolve_as_name_external_success_organisation(
    session: AsyncSession,
) -> None:
    """BigDataCloud success via ``organisation`` field → cached and returned."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"organisation": "Acme Networks Ltd"}
    client = _mock_http_client(resp)

    with patch("httpx.AsyncClient", return_value=client):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="KEY123")

    assert name == "Acme Networks Ltd"
    # Result must have been written to the cache (source=bigdatacloud).
    cached = await get_cached_as(session, asn=_UNKNOWN_ASN)
    assert cached is not None
    assert cached.name == "Acme Networks Ltd"
    assert cached.source == "bigdatacloud"


@pytest.mark.asyncio
async def test_resolve_as_name_external_success_name_fallback(
    session: AsyncSession,
) -> None:
    """When ``organisation`` is empty, falls back to the ``name`` field."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"organisation": "", "name": "Fallback Name AS"}
    client = _mock_http_client(resp)

    with patch("httpx.AsyncClient", return_value=client):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="KEY123")

    assert name == "Fallback Name AS"


@pytest.mark.asyncio
async def test_resolve_as_name_external_empty_org_returns_empty(
    session: AsyncSession,
) -> None:
    """Success response with no org/name → falls through to final ``return ''``."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"foo": "bar"}
    client = _mock_http_client(resp)

    with patch("httpx.AsyncClient", return_value=client):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="KEY123")

    assert name == ""
    # Nothing cached because org_name was empty.
    assert await get_cached_as(session, asn=_UNKNOWN_ASN) is None


@pytest.mark.asyncio
async def test_resolve_as_name_external_http_error_returns_empty(
    session: AsyncSession,
) -> None:
    """raise_for_status raising → exception branch logged, returns "" (160-163)."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )
    )
    client = _mock_http_client(resp)

    with patch("httpx.AsyncClient", return_value=client):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="KEY123")

    assert name == ""
    assert await get_cached_as(session, asn=_UNKNOWN_ASN) is None


@pytest.mark.asyncio
async def test_resolve_as_name_external_request_error_returns_empty(
    session: AsyncSession,
) -> None:
    """client.get raising a transport error → exception branch → "" (160-163)."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with patch("httpx.AsyncClient", return_value=client):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="KEY123")

    assert name == ""


# ===========================================================================
# syslog_receiver: start() mode selection (lines 81-96) + stop() (131-135)
# ===========================================================================


async def _spin_until_cancelled() -> None:
    """Long-lived no-op coroutine that only ends when its task is cancelled.

    Used to stand in for the receiver's background loops so ``start()`` has a
    real awaitable task to schedule and ``stop()`` has something to cancel,
    with no dangling un-awaited coroutine warnings.
    """
    try:
        while True:  # noqa: ASYNC110
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        return


@pytest.mark.asyncio
async def test_start_loki_ws_mode_schedules_ws_fallback() -> None:
    """syslog_mode='loki_ws' starts the WS-with-fallback task."""
    settings = Settings(monitor_host="127.0.0.1", syslog_mode="loki_ws")
    receiver = SyslogReceiver(settings, AsyncMock())

    with patch.object(receiver, "_ws_tail_with_fallback", new=_spin_until_cancelled):
        await receiver.start()
        assert receiver._running is True  # noqa: SLF001
        assert len(receiver._tasks) == 1  # noqa: SLF001
        await receiver.stop()

    assert receiver._running is False  # noqa: SLF001
    assert receiver._tasks == []  # noqa: SLF001


@pytest.mark.asyncio
async def test_start_loki_http_mode_schedules_http_poll() -> None:
    """syslog_mode='loki_http' starts the HTTP poll task."""
    settings = Settings(monitor_host="127.0.0.1", syslog_mode="loki_http")
    receiver = SyslogReceiver(settings, AsyncMock())

    with patch.object(receiver, "_http_poll", new=_spin_until_cancelled):
        await receiver.start()
        assert len(receiver._tasks) == 1  # noqa: SLF001
        await receiver.stop()


@pytest.mark.asyncio
async def test_start_udp_mode_schedules_udp_listen() -> None:
    """syslog_mode='udp' starts the UDP listen task."""
    settings = Settings(monitor_host="127.0.0.1", syslog_mode="udp")
    receiver = SyslogReceiver(settings, AsyncMock())

    with patch.object(receiver, "_udp_listen", new=_spin_until_cancelled):
        await receiver.start()
        assert len(receiver._tasks) == 1  # noqa: SLF001
        await receiver.stop()


@pytest.mark.asyncio
async def test_start_unknown_mode_defaults_to_ws_fallback() -> None:
    """Unknown syslog_mode falls back to the WS-with-fallback default branch."""
    settings = Settings(monitor_host="127.0.0.1", syslog_mode="something-else")
    receiver = SyslogReceiver(settings, AsyncMock())

    with patch.object(receiver, "_ws_tail_with_fallback", new=_spin_until_cancelled):
        await receiver.start()
        assert len(receiver._tasks) == 1  # noqa: SLF001
        await receiver.stop()


# ===========================================================================
# syslog_receiver: _ws_tail delegates to _ws_tail_attempts (line 143)
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_tail_delegates_to_attempts() -> None:
    """_ws_tail() calls _ws_tail_attempts(max_attempts=None, base_delay=1)."""
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    spy = AsyncMock()
    with patch.object(receiver, "_ws_tail_attempts", spy):
        await receiver._ws_tail()  # noqa: SLF001

    spy.assert_awaited_once_with(max_attempts=None, base_delay=1)


# ===========================================================================
# syslog_receiver: _ws_tail_attempts production lifetime via _running (167)
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_tail_attempts_stops_when_running_false() -> None:
    """With max_attempts=None, the loop is governed by self._running (line 167).

    First attempt fails (driving _running to False inside the mocked tail),
    so the ``return self._running`` continuation check ends the loop.
    """
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    attempts: list[int] = []

    async def fail_then_stop() -> None:
        attempts.append(1)
        receiver._running = False  # noqa: SLF001
        raise ConnectionError("boom")

    with (
        patch.object(receiver, "_ws_tail_once", fail_then_stop),
        patch("src.core.syslog_receiver.asyncio.sleep", new=AsyncMock()),
    ):
        await receiver._ws_tail_attempts(None, base_delay=0)  # noqa: SLF001

    assert attempts == [1]


# ===========================================================================
# syslog_receiver: _ws_tail_attempts break-on-max + sleep (lines 182, 185)
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_tail_attempts_breaks_on_max_after_sleep() -> None:
    """A positive base_delay exercises the sleep (185); max-attempt hit breaks (182).

    Two attempts both fail.  The first attempt sleeps (delay>0, attempt<max),
    the second hits ``attempt >= max_attempts`` and breaks.
    """
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    attempts: list[int] = []

    async def always_fail() -> None:
        attempts.append(1)
        raise websockets.exceptions.WebSocketException("disconnect")

    sleep_mock = AsyncMock()
    with (
        patch.object(receiver, "_ws_tail_once", always_fail),
        patch("src.core.syslog_receiver.asyncio.sleep", new=sleep_mock),
    ):
        await receiver._ws_tail_attempts(max_attempts=2, base_delay=1)  # noqa: SLF001

    assert len(attempts) == 2
    # Slept once (after attempt 1); attempt 2 broke before sleeping.
    sleep_mock.assert_awaited_once()


# ===========================================================================
# syslog_receiver: _ws_tail_once decodes bytes frames (line 195)
# ===========================================================================


@pytest.mark.asyncio
async def test_ws_tail_once_decodes_bytes_message() -> None:
    """A bytes WebSocket frame is decoded before parsing (covers line 195)."""
    settings = Settings(monitor_host="127.0.0.1")
    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    line = "May 22 21:12:21 192.168.203.1 bytes-frame log line"
    msg_bytes = json.dumps(
        {"streams": [{"stream": {}, "values": [["1716408741000000000", line]]}]}
    ).encode()

    mock_ws = AsyncMock()
    mock_ws.__aiter__ = MagicMock(return_value=_aiter_from_list([msg_bytes]))
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_ws)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("src.core.syslog_receiver.websockets.connect", return_value=mock_cm):
        receiver = SyslogReceiver(settings, callback)
        await receiver._ws_tail_once()  # noqa: SLF001

    assert received == [line]


# ===========================================================================
# syslog_receiver: _http_poll loop with pagination + exception (212-219)
# ===========================================================================


@pytest.mark.asyncio
async def test_http_poll_loop_paginates_then_stops() -> None:
    """_http_poll drains a full page (>= limit) then a short page, then stops.

    The first _http_poll_once returns _POLL_LIMIT (triggers the inner drain
    loop), the second returns a short count, after which we flip _running off
    inside the patched sleep so the outer ``while self._running`` loop exits.
    """
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    counts = iter([receiver._POLL_LIMIT, 3])  # noqa: SLF001

    async def fake_poll_once() -> int:
        return next(counts)

    async def stop_after(_delay: float) -> None:
        receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=fake_poll_once),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stop_after),
    ):
        await receiver._http_poll()  # noqa: SLF001

    # Both planned poll results were consumed (full page then short page).
    assert next(counts, "exhausted") == "exhausted"


@pytest.mark.asyncio
async def test_http_poll_loop_swallows_exception() -> None:
    """An exception from _http_poll_once is caught and logged (lines 217-218)."""
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    async def boom() -> int:
        raise RuntimeError("poll exploded")

    async def stop_after(_delay: float) -> None:
        receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=boom),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stop_after),
    ):
        # Must not raise — the except branch swallows it.
        await receiver._http_poll()  # noqa: SLF001

    assert receiver._running is False  # noqa: SLF001


# ===========================================================================
# syslog_receiver: _http_poll_once non-200 status (lines 248-249)
# ===========================================================================


@pytest.mark.asyncio
async def test_http_poll_once_non_200_returns_zero() -> None:
    """A non-200 Loki response logs a warning and returns 0 (no callback)."""
    settings = Settings(monitor_host="127.0.0.1")
    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    resp = MagicMock()
    resp.status_code = 503
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        receiver = SyslogReceiver(settings, callback)
        count = await receiver._http_poll_once()  # noqa: SLF001

    assert count == 0
    assert received == []


# ===========================================================================
# syslog_receiver: _http_poll_once pagination cursor advance (line 258)
# ===========================================================================


@pytest.mark.asyncio
async def test_http_poll_once_advances_cursor_on_full_page() -> None:
    """A full page (count == _POLL_LIMIT) advances _last_poll_ns to last_ts+1."""
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    base_ts = 1_716_408_741_000_000_000
    lines = [f"log line {i}" for i in range(limit)]
    payload = _http_payload(*lines, ts_start=base_ts)
    expected_last_ts = base_ts + (limit - 1)

    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = payload
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        count = await receiver._http_poll_once()  # noqa: SLF001

    assert count == limit
    # Cursor advanced to last entry's ts + 1 (NOT 'now') so the caller can
    # immediately drain the next backlog page.
    assert receiver._last_poll_ns == expected_last_ts + 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_http_poll_once_short_page_advances_to_now() -> None:
    """A short page sets the cursor to 'now' rather than the last-entry ts."""
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    payload = _http_payload("only one line")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = payload
    client = _mock_http_client(resp)

    before = receiver._last_poll_ns  # noqa: SLF001
    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        count = await receiver._http_poll_once()  # noqa: SLF001

    assert count == 1
    # Cursor jumped forward to ~now (a large nanosecond value), not the
    # entry timestamp + 1.
    assert receiver._last_poll_ns > before  # noqa: SLF001
    assert receiver._last_poll_ns > 1_716_408_741_000_000_001  # noqa: SLF001


# ===========================================================================
# syslog_receiver: _extract_lines_from_ws non-JSON branch (lines 326-328)
# ===========================================================================


def test_extract_lines_from_ws_non_json_returns_empty() -> None:
    """A non-JSON WebSocket message is skipped, returning an empty list."""
    settings = Settings(monitor_host="127.0.0.1")
    receiver = SyslogReceiver(settings, AsyncMock())

    lines = receiver._extract_lines_from_ws("this is not json {{{")  # noqa: SLF001
    assert lines == []


# ===========================================================================
# syslog_receiver: _udp_listen (lines 272-294)
# ===========================================================================


@pytest.mark.asyncio
async def test_udp_listen_receives_then_stops() -> None:
    """_udp_listen binds a (mocked) socket, dispatches one datagram, then exits.

    The real socket is replaced with a MagicMock.  ``run_in_executor`` is
    patched so the first call yields a datagram and the second raises OSError
    while _running is False, ending the loop and closing the socket.
    """
    settings = Settings(monitor_host="127.0.0.1", syslog_udp_port=15140)
    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    receiver = SyslogReceiver(settings, callback)
    receiver._running = True  # noqa: SLF001

    mock_sock = MagicMock()

    call_state = {"n": 0}

    async def fake_run_in_executor(_executor, _func):  # noqa: ANN001
        call_state["n"] += 1
        if call_state["n"] == 1:
            return (b"udp syslog line\n", ("10.0.0.9", 514))
        # Second pass: stop the loop, then raise OSError to hit the except.
        receiver._running = False  # noqa: SLF001
        raise OSError("socket closed")

    loop = MagicMock()
    loop.run_in_executor = fake_run_in_executor

    with (
        patch("src.core.syslog_receiver.socket.socket", return_value=mock_sock),
        patch(
            "src.core.syslog_receiver.asyncio.get_running_loop",
            return_value=loop,
        ),
    ):
        await receiver._udp_listen()  # noqa: SLF001

    assert received == ["udp syslog line"]
    mock_sock.bind.assert_called_once_with(("0.0.0.0", 15140))
    mock_sock.close.assert_called_once()


@pytest.mark.asyncio
async def test_udp_listen_oserror_while_running_continues() -> None:
    """OSError while still running does NOT break — loop continues until stopped.

    First recv raises OSError with _running True (the ``if not self._running``
    guard is False, so we loop again); second recv stops and raises again to
    exit.  Exercises both sides of the OSError guard at lines 290-292.
    """
    settings = Settings(monitor_host="127.0.0.1", syslog_udp_port=15141)
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    mock_sock = MagicMock()
    call_state = {"n": 0}

    async def fake_run_in_executor(_executor, _func):  # noqa: ANN001
        call_state["n"] += 1
        if call_state["n"] == 1:
            # transient error, still running -> loop continues
            raise OSError("transient")
        receiver._running = False  # noqa: SLF001
        raise OSError("shutdown")

    loop = MagicMock()
    loop.run_in_executor = fake_run_in_executor

    with (
        patch("src.core.syslog_receiver.socket.socket", return_value=mock_sock),
        patch(
            "src.core.syslog_receiver.asyncio.get_running_loop",
            return_value=loop,
        ),
    ):
        await receiver._udp_listen()  # noqa: SLF001

    # Two executor calls means the first OSError did NOT break the loop.
    assert call_state["n"] == 2
    mock_sock.close.assert_called_once()


# ===========================================================================
# as_cache: get_cached_as tz-naive fresh timestamp path
# ===========================================================================


@pytest.mark.asyncio
async def test_get_cached_as_naive_timestamp_fresh(session: AsyncSession) -> None:
    """A tz-naive but fresh cached_at is treated as UTC and returned."""
    naive_recent = datetime.now(tz=UTC).replace(tzinfo=None) - timedelta(minutes=5)
    record = ASCache(
        asn=64600,
        name="Naive Fresh",
        as_type="t",
        source="bgpview",
        cached_at=naive_recent,
    )
    session.add(record)
    await session.flush()

    got = await get_cached_as(session, asn=64600)
    assert got is not None
    assert got.name == "Naive Fresh"
