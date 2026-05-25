"""Tests for hardened AS-cache external lookup (timeout, retry, TTL, secret masking).

All network calls are mocked — this test suite never touches real HTTP endpoints.
Uses in-memory SQLite for DB isolation.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.as_cache import (
    _HTTP_TIMEOUT,
    _MAX_RETRIES,
    _RETRYABLE_STATUS,
    TTL_HOURS,
    _safe_url,
    get_cached_as,
    resolve_as_name,
)
from src.database.migrations import create_tables, get_engine
from src.database.models import ASCache

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncEngine

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"
_UNKNOWN_ASN = 65998  # not in static DB


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Shared in-memory SQLite engine for tests that need cross-session checks."""
    eng = await get_engine(IN_MEMORY_URL)
    await create_tables(eng)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Fresh in-memory SQLite session for each test."""
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as _session:
        yield _session


def _mock_http_client(response: MagicMock) -> AsyncMock:
    """Async-context-manager httpx.AsyncClient that returns *response* for GET."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _ok_response(org: str = "Acme Networks", name: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"organisation": org, "name": name}
    return resp


# ---------------------------------------------------------------------------
# 1. Module constants: tight timeout and retry ceiling
# ---------------------------------------------------------------------------


def test_http_timeout_is_tight() -> None:
    """External HTTP timeout must be between 3 and 5 seconds (inclusive)."""
    assert (
        3.0 <= _HTTP_TIMEOUT <= 5.0
    ), f"_HTTP_TIMEOUT={_HTTP_TIMEOUT} is outside the expected 3-5 s range"


def test_max_retries_is_bounded() -> None:
    """Retry ceiling must be 1 or 2 (small bounded backoff)."""
    assert (
        1 <= _MAX_RETRIES <= 2
    ), f"_MAX_RETRIES={_MAX_RETRIES} is outside the expected 1-2 range"


# ---------------------------------------------------------------------------
# 2. _safe_url redacts 'key' parameter
# ---------------------------------------------------------------------------


def test_safe_url_redacts_key_param() -> None:
    """_safe_url must replace the 'key' param value with '<redacted>'."""
    url = "https://api-bdc.net/data/asn-info"
    params = {"asn": "AS65998", "localityLanguage": "en", "key": "MY_SECRET_KEY"}
    result = _safe_url(url, params)
    assert "MY_SECRET_KEY" not in result
    assert "<redacted>" in result


def test_safe_url_preserves_non_secret_params() -> None:
    """Non-secret parameters must appear unmodified in the safe URL."""
    url = "https://api-bdc.net/data/asn-info"
    params = {"asn": "AS65998", "localityLanguage": "en", "key": "SECRET"}
    result = _safe_url(url, params)
    assert "AS65998" in result
    assert "en" in result


def test_safe_url_empty_params() -> None:
    """An empty params dict produces a URL with no query string."""
    result = _safe_url("https://example.com/path", {})
    assert result == "https://example.com/path"


# ---------------------------------------------------------------------------
# 3. Success path: normal HTTP 200 response
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_success_path(session: AsyncSession) -> None:
    """200 response → org name returned and written to cache."""
    resp = _ok_response(org="Test Networks Ltd")
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="TEST_KEY")

    assert name == "Test Networks Ltd"
    cached = await get_cached_as(session, asn=_UNKNOWN_ASN)
    assert cached is not None
    assert cached.name == "Test Networks Ltd"


@pytest.mark.asyncio
async def test_resolve_success_name_fallback(session: AsyncSession) -> None:
    """When 'organisation' is empty the 'name' field is used as fallback."""
    resp = _ok_response(org="", name="Fallback Name AS")
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == "Fallback Name AS"


# ---------------------------------------------------------------------------
# 4. Timeout → returns "" without raising
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_returns_empty_never_raises(session: AsyncSession) -> None:
    """TimeoutException on every attempt → returns '' (never raises)."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == ""


@pytest.mark.asyncio
async def test_connect_error_returns_empty(session: AsyncSession) -> None:
    """ConnectError on every attempt → returns '' (never raises)."""
    client = AsyncMock()
    client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == ""


# ---------------------------------------------------------------------------
# 5. Retry behaviour for transient errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_transient_timeout_then_success_uses_retry(session: AsyncSession) -> None:
    """First attempt times out, second attempt succeeds — retry is exercised."""
    fail_resp = MagicMock()
    fail_resp.get = AsyncMock(side_effect=httpx.TimeoutException("slow"))

    success_resp = _ok_response(org="Retry Success Org")

    call_count = {"n": 0}

    async def fake_get(url: str, *, params: dict) -> MagicMock:  # noqa: ARG001
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise httpx.TimeoutException("slow")
        return success_resp

    client = AsyncMock()
    client.get = fake_get
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    sleep_mock = AsyncMock()
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", sleep_mock),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == "Retry Success Org"
    # Exactly one sleep between attempt 1 and 2.
    sleep_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_retryable_429_then_success(session: AsyncSession) -> None:
    """HTTP 429 on first attempt, 200 on second — retry path exercised."""
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.raise_for_status = MagicMock()

    resp_200 = _ok_response(org="After 429")

    call_count = {"n": 0}

    async def fake_get(url: str, *, params: dict) -> MagicMock:  # noqa: ARG001
        call_count["n"] += 1
        if call_count["n"] == 1:
            return resp_429
        return resp_200

    client = AsyncMock()
    client.get = fake_get
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    sleep_mock = AsyncMock()
    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", sleep_mock),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == "After 429"
    sleep_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_429_exhausts_all_retries_returns_empty(session: AsyncSession) -> None:
    """429 on every attempt → returns '' after exhausting all retries."""
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.raise_for_status = MagicMock()
    client = _mock_http_client(resp_429)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == ""


@pytest.mark.asyncio
async def test_5xx_exhausts_all_retries_returns_empty(session: AsyncSession) -> None:
    """HTTP 503 on every attempt → returns '' after exhausting all retries."""
    resp_503 = MagicMock()
    resp_503.status_code = 503
    resp_503.raise_for_status = MagicMock()
    client = _mock_http_client(resp_503)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == ""


def test_retryable_status_set_contains_expected_codes() -> None:
    """429 and common 5xx codes must be in _RETRYABLE_STATUS."""
    for code in (429, 500, 502, 503, 504):
        assert code in _RETRYABLE_STATUS, f"{code} missing from _RETRYABLE_STATUS"


# ---------------------------------------------------------------------------
# 6. Non-retryable HTTP error (e.g. 404) → returns "" immediately
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_404_returns_empty(session: AsyncSession) -> None:
    """HTTP 404 is not retryable — raise_for_status fires and '' is returned."""
    resp = MagicMock()
    resp.status_code = 404
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "Not Found", request=MagicMock(), response=MagicMock()
        )
    )
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        name = await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    assert name == ""


# ---------------------------------------------------------------------------
# 7. TTL boundary: exactly at expiry threshold returns None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ttl_exactly_at_boundary_returns_none(session: AsyncSession) -> None:
    """A record cached exactly TTL_HOURS ago is considered expired (boundary)."""
    # Set cached_at to exactly TTL_HOURS ago (at the threshold, not inside it)
    exactly_expired = datetime.now(tz=UTC) - timedelta(hours=TTL_HOURS)
    record = ASCache(
        asn=64700,
        name="Boundary Org",
        as_type="t",
        source="test",
        cached_at=exactly_expired,
    )
    session.add(record)
    await session.flush()

    result = await get_cached_as(session, asn=64700)
    assert result is None, "Record at exact TTL boundary must be expired"


@pytest.mark.asyncio
async def test_ttl_one_second_before_expiry_returns_record(
    session: AsyncSession,
) -> None:
    """A record cached just under TTL_HOURS ago is still fresh."""
    # 1 second before expiry
    fresh = datetime.now(tz=UTC) - timedelta(hours=TTL_HOURS) + timedelta(seconds=1)
    record = ASCache(
        asn=64701,
        name="Fresh Org",
        as_type="t",
        source="test",
        cached_at=fresh,
    )
    session.add(record)
    await session.flush()

    result = await get_cached_as(session, asn=64701)
    assert result is not None, "Record just inside TTL must be returned"
    assert result.name == "Fresh Org"


@pytest.mark.asyncio
async def test_ttl_naive_boundary_comparison(session: AsyncSession) -> None:
    """Tz-naive stored timestamp at boundary is handled correctly (UTC assumed)."""
    # Store as naive datetime exactly at the expiry threshold
    naive_expired = (datetime.now(tz=UTC) - timedelta(hours=TTL_HOURS)).replace(
        tzinfo=None
    )
    record = ASCache(
        asn=64702,
        name="Naive Boundary",
        as_type="t",
        source="test",
        cached_at=naive_expired,
    )
    session.add(record)
    await session.flush()

    result = await get_cached_as(session, asn=64702)
    assert result is None, "Naive timestamp at boundary must be treated as expired"


# ---------------------------------------------------------------------------
# 8. Secrets never appear in logs or exceptions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timeout_log_does_not_contain_api_key(
    session: AsyncSession, caplog: pytest.LogCaptureFixture
) -> None:
    """When a timeout occurs, the api_key must not appear anywhere in log output."""
    secret = "SUPER_SECRET_API_KEY_12345"  # noqa: S105

    client = AsyncMock()
    client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
        caplog.at_level(logging.WARNING, logger="src.database.as_cache"),
    ):
        await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key=secret)

    for record in caplog.records:
        assert (
            secret not in record.getMessage()
        ), f"api_key leaked in log record: {record.getMessage()!r}"


@pytest.mark.asyncio
async def test_http_error_log_does_not_contain_api_key(
    session: AsyncSession, caplog: pytest.LogCaptureFixture
) -> None:
    """On HTTP error, logged URL must not contain the raw api_key."""
    secret = "ANOTHER_SECRET_KEY_ABCDE"  # noqa: S105

    resp = MagicMock()
    resp.status_code = 500
    resp.raise_for_status = MagicMock()
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
        caplog.at_level(logging.WARNING, logger="src.database.as_cache"),
    ):
        await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key=secret)

    for record in caplog.records:
        assert (
            secret not in record.getMessage()
        ), f"api_key leaked in log record: {record.getMessage()!r}"


@pytest.mark.asyncio
async def test_success_log_does_not_contain_api_key(
    session: AsyncSession, caplog: pytest.LogCaptureFixture
) -> None:
    """Even on success, the INFO log must not contain the api_key."""
    secret = "SUCCESS_SECRET_KEY_XYZ"  # noqa: S105
    resp = _ok_response(org="Logged Org")
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client),
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
        caplog.at_level(logging.INFO, logger="src.database.as_cache"),
    ):
        await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key=secret)

    for record in caplog.records:
        assert (
            secret not in record.getMessage()
        ), f"api_key leaked in log record: {record.getMessage()!r}"


# ---------------------------------------------------------------------------
# 9. Timeout value is actually passed to httpx.AsyncClient
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_client_receives_tight_timeout(session: AsyncSession) -> None:
    """httpx.AsyncClient must be constructed with the tight _HTTP_TIMEOUT value."""
    resp = _ok_response(org="Timeout Test Org")
    client = _mock_http_client(resp)

    with (
        patch("httpx.AsyncClient", return_value=client) as mock_class,
        patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
    ):
        await resolve_as_name(session, asn=_UNKNOWN_ASN, api_key="K")

    # Verify AsyncClient was constructed with the correct timeout keyword.
    all_args = mock_class.call_args_list[0]
    timeout_val = all_args.kwargs.get(
        "timeout", all_args.args[0] if all_args.args else None
    )
    assert (
        timeout_val == _HTTP_TIMEOUT
    ), f"AsyncClient timeout={timeout_val!r} != _HTTP_TIMEOUT={_HTTP_TIMEOUT}"


# ---------------------------------------------------------------------------
# 10. Cache commit: data persists across sessions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_persists_across_sessions(engine: AsyncEngine) -> None:
    """resolve_as_name must commit the cache write so a new session can read it."""
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Session 1: resolve and cache
    async with factory() as session1:
        resp = _ok_response(org="Persistent Org")
        client = _mock_http_client(resp)

        with (
            patch("httpx.AsyncClient", return_value=client),
            patch("src.database.as_cache.asyncio.sleep", new=AsyncMock()),
        ):
            name = await resolve_as_name(session1, asn=64800, api_key="K")

        assert name == "Persistent Org"

    # Session 2: read back — must find the cached entry without any HTTP call
    async with factory() as session2:
        cached = await get_cached_as(session2, asn=64800)
        assert (
            cached is not None
        ), "Cache entry was not committed — lost across sessions"
        assert cached.name == "Persistent Org"
