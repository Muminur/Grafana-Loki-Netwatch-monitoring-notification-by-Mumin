"""Resilience tests for ``src.core.syslog_receiver``.

Covers:
- Exponential back-off growth and reset on the HTTP poll error path
- Lag / consecutive-failure WARNING threshold
- Cursor safety when multiple entries share the same nanosecond timestamp
- ``health_status()`` correctness
- Credential masking in logged URLs

Every network boundary (httpx, websockets, UDP) is mocked.
``asyncio.sleep`` is always patched — no real sleeps.
"""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import Settings
from src.core.syslog_receiver import (
    _HTTP_BACKOFF_BASE,
    _HTTP_BACKOFF_CAP,
    _HTTP_POLL_FAIL_THRESHOLD,
    _HTTP_POLL_INTERVAL,
    _UDP_RATE_LIMIT_DEFAULT,
    _UDP_RATE_WARN_INTERVAL,
    ReceiverHealth,
    SyslogReceiver,
    TransportErrorCounters,
    _mask_url,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _settings(**kwargs: object) -> Settings:
    return Settings(monitor_host="127.0.0.1", **kwargs)  # type: ignore[arg-type]


def _http_payload(*lines: str, ts_start: int = 1_716_408_741_000_000_000) -> dict:  # type: ignore[type-arg]
    """Build a Loki query_range JSON payload with distinct timestamps per line."""
    values = [[str(ts_start + i), line] for i, line in enumerate(lines)]
    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": values}],
        },
    }


def _mock_http_client(response: MagicMock) -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _ok_response(payload: dict) -> MagicMock:  # type: ignore[type-arg]
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = payload
    return r


# ---------------------------------------------------------------------------
# 1. URL masking
# ---------------------------------------------------------------------------


def test_mask_url_replaces_api_key_value() -> None:
    """API key value in URL is replaced with *** while param name is kept."""
    url = "http://host:3000/loki?api_key=supersecret&limit=10"
    masked = _mask_url(url)
    assert "supersecret" not in masked
    assert "api_key=***" in masked
    assert "limit=10" in masked


def test_mask_url_no_key_unchanged() -> None:
    """URLs without an API key parameter are returned unchanged."""
    url = "http://host:3000/loki/api/v1/query_range"
    assert _mask_url(url) == url


def test_mask_url_case_insensitive() -> None:
    """Masking is case-insensitive (API_KEY, Api-Key, apikey all masked)."""
    for variant in ("API_KEY=abc", "Api-Key=abc", "apikey=abc"):
        assert "abc" not in _mask_url(f"http://host/?{variant}")


# ---------------------------------------------------------------------------
# 2. health_status() — basic contract
# ---------------------------------------------------------------------------


def test_health_status_initial_state() -> None:
    """Before start(), health reports idle/not-running with zero failures."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    h = receiver.health_status()
    assert isinstance(h, ReceiverHealth)
    assert h.running is False
    assert h.mode == "idle"
    assert h.last_poll_ns == 0
    assert h.consecutive_http_failures == 0


@pytest.mark.asyncio
async def test_health_status_reflects_active_mode() -> None:
    """health_status() reports mode='http' when started in loki_http mode."""
    receiver = SyslogReceiver(_settings(syslog_mode="loki_http"), AsyncMock())

    async def _spin() -> None:
        try:
            while True:  # noqa: ASYNC110
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            return

    with patch.object(receiver, "_http_poll", new=_spin):
        await receiver.start()
        # start() must set _active_mode directly for loki_http/udp modes
        h = receiver.health_status()
        assert h.running is True
        assert h.mode == "http"
        await receiver.stop()


@pytest.mark.asyncio
async def test_health_status_loki_http_mode_no_idle() -> None:
    """start(loki_http) sets mode='http', not 'idle', without going via WS fallback."""
    receiver = SyslogReceiver(_settings(syslog_mode="loki_http"), AsyncMock())

    async def _spin() -> None:
        try:
            while True:  # noqa: ASYNC110
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            return

    with patch.object(receiver, "_http_poll", new=_spin):
        await receiver.start()
        h = receiver.health_status()
        assert (
            h.mode == "http"
        ), f"Expected mode='http' for loki_http start, got '{h.mode}'"
        await receiver.stop()


@pytest.mark.asyncio
async def test_health_status_udp_mode_no_idle() -> None:
    """start(udp) sets mode='udp', not 'idle'."""
    receiver = SyslogReceiver(_settings(syslog_mode="udp"), AsyncMock())

    async def _spin() -> None:
        try:
            while True:  # noqa: ASYNC110
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            return

    with patch.object(receiver, "_udp_listen", new=_spin):
        await receiver.start()
        h = receiver.health_status()
        assert h.mode == "udp", f"Expected mode='udp' for udp start, got '{h.mode}'"
        await receiver.stop()


def test_health_status_reflects_failure_count() -> None:
    """health_status() exposes the current consecutive failure counter."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    receiver._http_fail_count = 7  # noqa: SLF001
    h = receiver.health_status()
    assert h.consecutive_http_failures == 7


def test_health_status_reflects_last_poll_ns() -> None:
    """health_status() reports the current _last_poll_ns cursor."""
    ts = 1_716_408_741_000_000_000
    receiver = SyslogReceiver(_settings(), AsyncMock(), resume_from_ns=ts)
    h = receiver.health_status()
    assert h.last_poll_ns == ts


# ---------------------------------------------------------------------------
# 3. Exponential back-off: growth and cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_poll_backoff_grows_exponentially() -> None:
    """HTTP poll sleep doubles on each consecutive failure up to the cap.

    We run 8 failure cycles and record every sleep duration, then assert
    the sequence matches 1→2→4→8→16→30→30→30 (cap enforced).
    """
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    max_failures = 8
    fail_count = {"n": 0}

    async def always_fail() -> int:
        fail_count["n"] += 1
        raise RuntimeError("loki down")

    sleep_durations: list[float] = []

    async def track_sleep(delay: float) -> None:
        sleep_durations.append(delay)
        if fail_count["n"] >= max_failures:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=always_fail),
        patch("src.core.syslog_receiver.asyncio.sleep", new=track_sleep),
    ):
        await receiver._http_poll()  # noqa: SLF001

    # Expected: 1, 2, 4, 8, 16, 30, 30, 30
    expected = [
        min(_HTTP_BACKOFF_BASE * (2**i), _HTTP_BACKOFF_CAP) for i in range(max_failures)
    ]
    assert (
        sleep_durations == expected
    ), f"Back-off sequence wrong.\nExpected: {expected}\nGot:      {sleep_durations}"


@pytest.mark.asyncio
async def test_http_poll_backoff_resets_on_success() -> None:
    """Back-off delay resets to base after a successful poll following failures.

    Sleep sequence:
      fail1  -> backoff 1 s
      fail2  -> backoff 2 s
      fail3  -> backoff 4 s
      success -> normal interval (2 s)
      fail4  -> backoff 1 s  <- must be base again, NOT continuing from 8 s
    """
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    # Sequence: fail x 3, succeed x 1, fail x 1 then stop.
    call_seq = iter(
        [
            RuntimeError("fail1"),
            RuntimeError("fail2"),
            RuntimeError("fail3"),
            None,  # success -- returns 0 entries
            RuntimeError("fail4"),
        ]
    )

    async def next_poll() -> int:
        exc = next(call_seq, None)
        if exc is None:
            return 0
        if isinstance(exc, Exception):
            raise exc
        return 0

    sleep_durations: list[float] = []
    # 5 sleeps expected: 3 backoff + 1 normal interval + 1 post-fail4 backoff
    stop_after = {"n": 5}

    async def track_sleep(delay: float) -> None:
        sleep_durations.append(delay)
        stop_after["n"] -= 1
        if stop_after["n"] <= 0:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=next_poll),
        patch("src.core.syslog_receiver.asyncio.sleep", new=track_sleep),
    ):
        await receiver._http_poll()  # noqa: SLF001

    # Failures 1-3: back-off 1->2->4 s
    assert sleep_durations[:3] == [
        1.0,
        2.0,
        4.0,
    ], f"Pre-recovery back-off delays wrong: {sleep_durations[:3]}"
    # After success: normal interval sleep
    assert sleep_durations[3] == float(_HTTP_POLL_INTERVAL), (
        f"Expected normal interval {_HTTP_POLL_INTERVAL} s after success, "
        f"got {sleep_durations[3]}"
    )
    # After fail4: back-off must restart from base (not continue from 8 s)
    assert (
        sleep_durations[4] == _HTTP_BACKOFF_BASE
    ), f"Back-off did not reset after success: sleep_durations[4]={sleep_durations[4]}"


@pytest.mark.asyncio
async def test_http_poll_failure_count_resets_on_success() -> None:
    """_http_fail_count is zeroed on the first successful poll after failures."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    calls = iter([RuntimeError("err"), RuntimeError("err"), None])

    async def next_poll() -> int:
        v = next(calls, None)
        if isinstance(v, Exception):
            raise v
        return 0

    stop_at = {"n": 3}

    async def stopper(_delay: float) -> None:
        stop_at["n"] -= 1
        if stop_at["n"] <= 0:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=next_poll),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stopper),
    ):
        await receiver._http_poll()  # noqa: SLF001

    assert receiver._http_fail_count == 0  # noqa: SLF001


# ---------------------------------------------------------------------------
# 4. Consecutive-failure WARNING threshold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_poll_warning_emitted_at_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A WARNING is logged when failures reach _HTTP_POLL_FAIL_THRESHOLD."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    call_count = {"n": 0}

    async def fail_then_stop() -> int:
        call_count["n"] += 1
        raise RuntimeError("loki down")

    async def stopper(_delay: float) -> None:
        if call_count["n"] >= _HTTP_POLL_FAIL_THRESHOLD:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=fail_then_stop),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stopper),
        caplog.at_level(logging.WARNING, logger="src.core.syslog_receiver"),
    ):
        await receiver._http_poll()  # noqa: SLF001

    warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    threshold_warnings = [
        m
        for m in warning_msgs
        if "consecutive" in m.lower() or "unreachable" in m.lower()
    ]
    assert threshold_warnings, (
        "Expected at least one WARNING about consecutive failures. "
        f"Got warnings: {warning_msgs}"
    )


@pytest.mark.asyncio
async def test_http_poll_no_threshold_warning_below_limit(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No threshold-breach WARNING when failures are below the threshold."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    fail_count = _HTTP_POLL_FAIL_THRESHOLD - 1
    call_count = {"n": 0}

    async def fail_n_times() -> int:
        call_count["n"] += 1
        raise RuntimeError("loki down")

    async def stopper(_delay: float) -> None:
        if call_count["n"] >= fail_count:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=fail_n_times),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stopper),
        caplog.at_level(logging.WARNING, logger="src.core.syslog_receiver"),
    ):
        await receiver._http_poll()  # noqa: SLF001

    threshold_warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING
        and ("consecutive" in r.message.lower() or "unreachable" in r.message.lower())
    ]
    assert (
        not threshold_warnings
    ), f"Unexpected threshold WARNING before limit: {threshold_warnings}"


# ---------------------------------------------------------------------------
# 5. Cursor safety at full-page boundaries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cursor_advances_safely_when_timestamps_unique() -> None:
    """Full page with distinct timestamps -> cursor = last_ts + 1."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    base_ts = 1_716_408_741_000_000_000
    lines = [f"log {i}" for i in range(limit)]
    payload = _http_payload(*lines, ts_start=base_ts)

    resp = _ok_response(payload)
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001

    expected_cursor = base_ts + (limit - 1) + 1
    assert receiver._last_poll_ns == expected_cursor  # noqa: SLF001
    assert receiver._seen_at_cursor == set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_cursor_stays_when_last_timestamp_shared() -> None:
    """Full page where several entries share last ts: cursor stays at that ts."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    shared_ts = 1_716_408_741_999_999_999
    # Build a page that fills the limit: first entry has a different ts,
    # the remaining (limit - 1) entries all share shared_ts.
    earlier_ts = shared_ts - 1
    values_earlier = [[str(earlier_ts), "log early"]]
    values_shared = [[str(shared_ts), f"log shared {i}"] for i in range(limit - 1)]
    all_values = values_earlier + values_shared

    payload: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": all_values}],
        },
    }

    resp = _ok_response(payload)
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001

    # Cursor must stay at the shared timestamp (not advance to +1).
    assert receiver._last_poll_ns == shared_ts  # noqa: SLF001
    # seen_at_cursor must contain all entries that share the last ts.
    assert len(receiver._seen_at_cursor) == limit - 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_cursor_advances_when_entire_page_shares_one_timestamp() -> None:
    """A full page where every entry shares one ts must advance, not loop.

    Staying at the shared ts would re-fetch the identical page forever (all
    entries already seen → zero progress). The cursor must move past it.
    """
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    shared_ts = 1_716_408_741_999_999_999
    all_values = [[str(shared_ts), f"log {i}"] for i in range(limit)]
    payload: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": all_values}],
        },
    }
    client = _mock_http_client(_ok_response(payload))

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001

    # Must advance past the shared ts and clear the seen-set (no infinite loop).
    assert receiver._last_poll_ns == shared_ts + 1  # noqa: SLF001
    assert receiver._seen_at_cursor == set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_cursor_deduplicates_on_refetch() -> None:
    """On re-fetch at shared ts, already-seen entries are not re-delivered."""
    settings = _settings()
    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    receiver = SyslogReceiver(settings, callback)
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    shared_ts = 1_716_408_741_999_999_999
    earlier_ts = shared_ts - 1
    shared_lines = [f"shared {i}" for i in range(limit - 1)]

    values_first_page = [[str(earlier_ts), "log early"]] + [
        [str(shared_ts), ln] for ln in shared_lines
    ]
    payload_first: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": values_first_page}],
        },
    }

    # Second page: same shared-ts entries plus one brand-new entry.
    new_line = "brand new entry"
    values_second_page = [[str(shared_ts), ln] for ln in shared_lines] + [
        [str(shared_ts + 1), new_line]
    ]
    payload_second: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": values_second_page}],
        },
    }

    resp1 = _ok_response(payload_first)
    resp2 = _ok_response(payload_second)

    call_count = {"n": 0}

    async def fake_get(*_args: object, **_kwargs: object) -> MagicMock:
        call_count["n"] += 1
        return resp1 if call_count["n"] == 1 else resp2

    client = AsyncMock()
    client.get = AsyncMock(side_effect=fake_get)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001  # first page
        await receiver._http_poll_once()  # noqa: SLF001  # second page (re-fetches shared_ts)

    # shared_lines should be delivered exactly once each, not duplicated.
    for ln in shared_lines:
        assert (
            received.count(ln) == 1
        ), f"Line '{ln}' delivered {received.count(ln)} times -- expected 1"
    # The brand-new entry must be delivered.
    assert new_line in received


@pytest.mark.asyncio
async def test_cursor_clears_seen_set_after_short_page() -> None:
    """After a short page the seen-cursor set is cleared (no stale dedup state)."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())

    # Seed a non-empty seen set from a previous full-page poll.
    receiver._seen_at_cursor = {(1234, "old line")}  # noqa: SLF001

    payload = _http_payload("only one line")
    resp = _ok_response(payload)
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001

    assert receiver._seen_at_cursor == set()  # noqa: SLF001


# ---------------------------------------------------------------------------
# 6. health_status() integration -- updates during HTTP poll lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_status_failure_count_increments() -> None:
    """Failure count in health_status() grows with each consecutive HTTP error."""
    target = 3
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    fail_count = {"n": 0}

    async def always_fail() -> int:
        fail_count["n"] += 1
        raise RuntimeError("down")

    async def stopper(_delay: float) -> None:
        if fail_count["n"] >= target:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=always_fail),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stopper),
    ):
        await receiver._http_poll()  # noqa: SLF001

    h = receiver.health_status()
    assert h.consecutive_http_failures == target


@pytest.mark.asyncio
async def test_health_status_last_poll_ns_updated() -> None:
    """last_poll_ns in health_status() reflects the cursor after a poll."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())

    payload = _http_payload("line1")
    resp = _ok_response(payload)
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        await receiver._http_poll_once()  # noqa: SLF001

    h = receiver.health_status()
    assert h.last_poll_ns > 0


# ---------------------------------------------------------------------------
# 7. Pagination drain correctness (raw count drives the loop)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_poll_once_returns_raw_count_for_pagination() -> None:
    """_http_poll_once returns the total Loki entry count, not the dedup count.

    The inner drain loop in _http_poll uses the return value to decide whether
    more backlog remains.  Returning len(new_entries) would break the loop when
    ALL entries on a page share the boundary timestamp (all already in
    seen_at_cursor), stopping the drain prematurely.
    """
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    limit = receiver._POLL_LIMIT  # noqa: SLF001

    shared_ts = 1_716_408_741_999_999_999
    # Full page: all entries share shared_ts so cursor stays and seen is populated.
    all_values = [[str(shared_ts), f"line {i}"] for i in range(limit)]
    payload_full: dict = {  # type: ignore[type-arg]
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [{"stream": {"job": "syslog"}, "values": all_values}],
        },
    }

    resp = _ok_response(payload_full)
    client = _mock_http_client(resp)

    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client):
        # First poll: seen_at_cursor empty, all 500 entries are new.
        count1 = await receiver._http_poll_once()  # noqa: SLF001

    assert (
        count1 == limit
    ), f"First full page should return raw count={limit}, got {count1}"

    # Now all 500 entries are in seen_at_cursor.
    # A second poll for the SAME page should still return raw count=500,
    # even though new_entries=0, so the pagination loop can correctly detect
    # a full page and continue draining (or let the caller decide).
    resp2 = _ok_response(payload_full)
    client2 = _mock_http_client(resp2)

    # Reset the cached HTTP client so the new mock is picked up.
    receiver._http_client = None  # noqa: SLF001
    with patch("src.core.syslog_receiver.httpx.AsyncClient", return_value=client2):
        count2 = await receiver._http_poll_once()  # noqa: SLF001

    assert count2 == limit, (
        f"Second poll of same full page must return raw count={limit} (not 0), "
        f"got {count2}. Returning 0 would prematurely break the drain loop."
    )


# ---------------------------------------------------------------------------
# 8. UDP rate limiting (token bucket)
# ---------------------------------------------------------------------------


def test_udp_allow_packet_initial_burst() -> None:
    """A fresh receiver accepts packets up to the configured rate limit."""
    receiver = SyslogReceiver(_settings(), AsyncMock(), udp_rate_limit=5)
    accepted = sum(1 for _ in range(10) if receiver._udp_allow_packet())  # noqa: SLF001
    # The bucket starts full (5 tokens), so the first 5 are accepted.
    assert accepted == 5


def test_udp_allow_packet_refills_over_time() -> None:
    """After draining the bucket, tokens refill when time advances."""
    receiver = SyslogReceiver(_settings(), AsyncMock(), udp_rate_limit=10)
    # Drain the bucket.
    for _ in range(10):
        receiver._udp_allow_packet()  # noqa: SLF001
    assert not receiver._udp_allow_packet()  # noqa: SLF001

    # Advance time by 0.5 seconds — should refill ~5 tokens (rate=10/s).
    receiver._udp_last_refill -= 0.5  # noqa: SLF001
    accepted = sum(1 for _ in range(10) if receiver._udp_allow_packet())  # noqa: SLF001
    assert 4 <= accepted <= 6  # Allow small float rounding margin


def test_udp_rate_limit_warning_logged(caplog: pytest.LogCaptureFixture) -> None:
    """Exceeding the rate limit logs a WARNING (at most once per interval)."""
    receiver = SyslogReceiver(_settings(), AsyncMock(), udp_rate_limit=2)
    # Drain the bucket completely.
    for _ in range(3):
        receiver._udp_allow_packet()  # noqa: SLF001

    with caplog.at_level(logging.WARNING, logger="src.core.syslog_receiver"):
        # This call should drop and emit a warning.
        result = receiver._udp_allow_packet()  # noqa: SLF001

    assert result is False
    rate_warnings = [r for r in caplog.records if "rate limit" in r.message.lower()]
    assert len(rate_warnings) == 1


def test_udp_rate_limit_warning_suppressed_within_interval(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A second rate-limit warning within the interval is suppressed."""
    receiver = SyslogReceiver(_settings(), AsyncMock(), udp_rate_limit=1)
    # Drain and trigger first warning.
    receiver._udp_allow_packet()  # noqa: SLF001

    with caplog.at_level(logging.WARNING, logger="src.core.syslog_receiver"):
        receiver._udp_allow_packet()  # noqa: SLF001  — first warning
        receiver._udp_allow_packet()  # noqa: SLF001  — should be suppressed

    rate_warnings = [r for r in caplog.records if "rate limit" in r.message.lower()]
    assert len(rate_warnings) == 1, (
        f"Expected exactly 1 rate-limit warning, got {len(rate_warnings)}"
    )


def test_udp_rate_limit_default_value() -> None:
    """Default rate limit matches the module constant."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    assert receiver._udp_rate_limit == _UDP_RATE_LIMIT_DEFAULT  # noqa: SLF001


def test_udp_rate_limit_minimum_is_one() -> None:
    """Rate limit is clamped to a minimum of 1 even if 0 is passed."""
    receiver = SyslogReceiver(_settings(), AsyncMock(), udp_rate_limit=0)
    assert receiver._udp_rate_limit >= 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_udp_listen_drops_when_rate_exceeded() -> None:
    """Packets exceeding the rate limit are dropped (callback not called)."""
    settings = _settings(syslog_udp_port=15142)
    received: list[str] = []

    async def callback(line: str) -> None:
        received.append(line)

    # Rate limit of 2 packets/second
    receiver = SyslogReceiver(settings, callback, udp_rate_limit=2)
    receiver._running = True  # noqa: SLF001

    mock_sock = MagicMock()
    call_state = {"n": 0}

    async def fake_run_in_executor(_executor, _func):  # type: ignore[no-untyped-def] # noqa: ANN001
        call_state["n"] += 1
        if call_state["n"] <= 5:
            return (f"line {call_state['n']}".encode(), ("10.0.0.1", 514))
        receiver._running = False  # noqa: SLF001
        raise OSError("done")

    loop_mock = MagicMock()
    loop_mock.run_in_executor = fake_run_in_executor

    with (
        patch("src.core.syslog_receiver.socket.socket", return_value=mock_sock),
        patch(
            "src.core.syslog_receiver.asyncio.get_running_loop",
            return_value=loop_mock,
        ),
    ):
        await receiver._udp_listen()  # noqa: SLF001

    # Only the first 2 packets should have been accepted (bucket size = 2).
    assert len(received) == 2
    mock_sock.close.assert_called_once()


# ---------------------------------------------------------------------------
# 9. Per-transport error counters
# ---------------------------------------------------------------------------


def test_error_counters_initial_zero() -> None:
    """Error counters start at zero for all transports."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    h = receiver.health_status()
    assert h.error_counters.ws == 0
    assert h.error_counters.http == 0
    assert h.error_counters.udp == 0


def test_record_error_increments_ws() -> None:
    """_record_error('ws') increments only the ws counter."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    receiver._record_error("ws")  # noqa: SLF001
    receiver._record_error("ws")  # noqa: SLF001
    h = receiver.health_status()
    assert h.error_counters.ws == 2
    assert h.error_counters.http == 0
    assert h.error_counters.udp == 0


def test_record_error_increments_http() -> None:
    """_record_error('http') increments only the http counter."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    receiver._record_error("http")  # noqa: SLF001
    h = receiver.health_status()
    assert h.error_counters.http == 1


def test_record_error_increments_udp() -> None:
    """_record_error('udp') increments only the udp counter."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    receiver._record_error("udp")  # noqa: SLF001
    h = receiver.health_status()
    assert h.error_counters.udp == 1


def test_error_counters_are_snapshot() -> None:
    """health_status() returns a snapshot — not a live reference."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    h1 = receiver.health_status()
    receiver._record_error("ws")  # noqa: SLF001
    h2 = receiver.health_status()
    assert h1.error_counters.ws == 0
    assert h2.error_counters.ws == 1


@pytest.mark.asyncio
async def test_http_poll_records_error_counter() -> None:
    """HTTP poll failures increment the http error counter."""
    settings = _settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    fail_count = {"n": 0}

    async def always_fail() -> int:
        fail_count["n"] += 1
        raise RuntimeError("loki down")

    async def stopper(_delay: float) -> None:
        if fail_count["n"] >= 3:
            receiver._running = False  # noqa: SLF001

    with (
        patch.object(receiver, "_http_poll_once", side_effect=always_fail),
        patch("src.core.syslog_receiver.asyncio.sleep", new=stopper),
    ):
        await receiver._http_poll()  # noqa: SLF001

    h = receiver.health_status()
    assert h.error_counters.http == 3


def test_record_error_logs_at_interval(caplog: pytest.LogCaptureFixture) -> None:
    """An INFO-level summary is emitted every _ERROR_LOG_INTERVAL errors."""
    receiver = SyslogReceiver(_settings(), AsyncMock())
    with caplog.at_level(logging.INFO, logger="src.core.syslog_receiver"):
        for _ in range(100):
            receiver._record_error("ws")  # noqa: SLF001

    info_summaries = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "Transport error totals" in r.message
    ]
    assert len(info_summaries) >= 1


# ---------------------------------------------------------------------------
# 10. Socket cleanup (try/finally)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_socket_closed_on_bind_error() -> None:
    """Socket is closed even if bind() raises an exception."""
    settings = _settings(syslog_udp_port=15143)
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    mock_sock = MagicMock()
    mock_sock.bind.side_effect = OSError("address in use")

    with (
        patch("src.core.syslog_receiver.socket.socket", return_value=mock_sock),
        pytest.raises(OSError, match="address in use"),
    ):
        await receiver._udp_listen()  # noqa: SLF001

    # The socket must be closed despite the bind failure.
    mock_sock.close.assert_called_once()


@pytest.mark.asyncio
async def test_udp_socket_closed_on_unexpected_exception() -> None:
    """Socket is closed if an unexpected (non-OSError) exception occurs."""
    settings = _settings(syslog_udp_port=15144)
    receiver = SyslogReceiver(settings, AsyncMock())
    receiver._running = True  # noqa: SLF001

    mock_sock = MagicMock()

    async def explode(_executor, _func):  # type: ignore[no-untyped-def] # noqa: ANN001
        raise RuntimeError("unexpected")

    loop_mock = MagicMock()
    loop_mock.run_in_executor = explode

    with (
        patch("src.core.syslog_receiver.socket.socket", return_value=mock_sock),
        patch(
            "src.core.syslog_receiver.asyncio.get_running_loop",
            return_value=loop_mock,
        ),
        pytest.raises(RuntimeError, match="unexpected"),
    ):
        await receiver._udp_listen()  # noqa: SLF001

    mock_sock.close.assert_called_once()
