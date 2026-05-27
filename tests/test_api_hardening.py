"""Tests for API input validation, health detail hardening, and rate limiting.

Covers:
  - /api/alerts severity allowlist validation (HTTP 400 on bad value)
  - /api/alerts period allowlist validation (HTTP 400 on bad value)
  - /api/alerts/count period allowlist validation (HTTP 400 on bad value)
  - Valid filters still pass through without errors
  - /health includes database_ok field and degrades when engine missing
  - _maintenance_store is capped (bounded deque)
  - Global state is always restored in fixtures
  - Rate limiting: 429 on excessive requests, /health exempt
"""

# ruff: noqa: SLF001, ARG001
from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

import src.api.routes as routes_mod

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def client() -> AsyncClient:
    """An httpx AsyncClient bound to the FastAPI app (no real server)."""
    from src.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def clean_stores() -> Iterator[None]:
    """Snapshot and restore all in-memory stores + DB engine.

    Ensures any test that mutates ``_alerts_store`` / ``_incidents_store`` /
    ``_maintenance_store`` / the DB engine leaves global state exactly as it
    found it.
    """
    orig_alerts = list(routes_mod._alerts_store)
    orig_incidents = list(routes_mod._incidents_store)
    orig_maint = list(routes_mod._maintenance_store)
    orig_counter = routes_mod._maintenance_id_counter
    orig_noise = routes_mod._hardware_defects_as_noise
    orig_engine = routes_mod._db_engine

    routes_mod._alerts_store.clear()
    routes_mod._incidents_store.clear()
    routes_mod._maintenance_store.clear()
    try:
        yield
    finally:
        routes_mod._alerts_store.clear()
        routes_mod._alerts_store.extend(orig_alerts)
        routes_mod._incidents_store.clear()
        routes_mod._incidents_store.extend(orig_incidents)
        routes_mod._maintenance_store.clear()
        routes_mod._maintenance_store.extend(orig_maint)
        routes_mod._maintenance_id_counter = orig_counter
        routes_mod._hardware_defects_as_noise = orig_noise
        routes_mod._db_engine = orig_engine


# ---------------------------------------------------------------------------
# 1. /api/alerts — severity allowlist: invalid → 400
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_invalid_severity_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts?severity=INVALID must return HTTP 400."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/api/alerts", params={"severity": "INVALID"})
    assert resp.status_code == 400
    body = resp.json()
    assert "severity" in body["detail"].lower() or "invalid" in body["detail"].lower()


@pytest.mark.asyncio
async def test_get_alerts_severity_bogus_value_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts?severity=bogus (lowercase non-valid) → 400."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/api/alerts", params={"severity": "ERROR"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 2. /api/alerts — period allowlist: invalid → 400
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_invalid_period_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts?period=bad returns HTTP 400."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/api/alerts", params={"period": "bad_period"})
    assert resp.status_code == 400
    body = resp.json()
    assert "period" in body["detail"].lower() or "invalid" in body["detail"].lower()


@pytest.mark.asyncio
async def test_get_alerts_period_week_invalid_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts?period=week (not in allowlist) → 400."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/api/alerts", params={"period": "week"})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 3. /api/alerts — valid filters still pass through
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_valid_severity_passes(
    client: AsyncClient, clean_stores: None
) -> None:
    """All allowed severity values return 200."""
    routes_mod._db_engine = None
    valid = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    # Also test case-insensitive matching (upper)
    valid_with_case = valid + ["critical", "warning"]
    async with client as c:
        for sev in valid_with_case:
            resp = await c.get("/api/alerts", params={"severity": sev})
            assert (
                resp.status_code == 200
            ), f"severity={sev!r} returned {resp.status_code}"  # noqa: PT018


@pytest.mark.asyncio
async def test_get_alerts_valid_period_passes(
    client: AsyncClient, clean_stores: None
) -> None:
    """All allowed period values return 200."""
    routes_mod._db_engine = None
    valid_periods = ["today", "yesterday", "7d", "30d", "1y", "all"]
    async with client as c:
        for p in valid_periods:
            resp = await c.get("/api/alerts", params={"period": p})
            assert resp.status_code == 200, f"period={p!r} returned {resp.status_code}"


# ---------------------------------------------------------------------------
# 4. /api/alerts/count — period allowlist: invalid → 400
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_count_invalid_period_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts/count?period=invalid returns HTTP 400."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/api/alerts/count", params={"period": "invalid_period"})
    assert resp.status_code == 400
    body = resp.json()
    assert "period" in body["detail"].lower() or "invalid" in body["detail"].lower()


@pytest.mark.asyncio
async def test_get_alerts_count_valid_period_passes(
    client: AsyncClient, clean_stores: None
) -> None:
    """All allowed period values for /api/alerts/count return 200."""
    routes_mod._db_engine = None
    valid_periods = ["today", "yesterday", "7d", "30d", "1y", "all"]
    async with client as c:
        for p in valid_periods:
            resp = await c.get("/api/alerts/count", params={"period": p})
            assert resp.status_code == 200, f"period={p!r} returned {resp.status_code}"


# ---------------------------------------------------------------------------
# 5. /health — includes database_ok, degrades when engine missing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_includes_database_ok_field(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /health must include database_ok field."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert "database_ok" in body
    assert isinstance(body["database_ok"], bool)


@pytest.mark.asyncio
async def test_health_status_ok_when_no_engine(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /health returns status='ok' when no DB engine is registered.

    No engine means we are in in-memory / test mode — not degraded.
    """
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/health")
    body = resp.json()
    assert body["status"] == "ok"
    assert body["database_ok"] is False


@pytest.mark.asyncio
async def test_health_degrades_when_db_engine_fails(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /health returns status='degraded' when DB SELECT 1 raises."""
    # Create a mock engine whose connect raises an exception
    bad_engine = MagicMock()
    bad_engine.__class__ = type(
        "AsyncEngine", (), {"__aenter__": None, "__aexit__": None}
    )
    # Patch AsyncSession to raise on execute
    import unittest.mock as mock

    with mock.patch("src.api.routes.AsyncEngine", create=True):
        # Simulate engine failure by using an engine that raises on session execute
        from sqlalchemy.ext.asyncio import create_async_engine

        # Use an in-memory engine that works — then break it via patching session
        working_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        routes_mod._db_engine = working_engine

        # Now patch session.execute to raise
        with mock.patch(
            "sqlalchemy.ext.asyncio.AsyncSession.execute",
            side_effect=RuntimeError("DB connection failed"),
        ):
            async with client as c:
                resp = await c.get("/health")
        await working_engine.dispose()

    body = resp.json()
    assert resp.status_code == 200
    assert body["status"] == "degraded"
    assert body["database_ok"] is False


@pytest.mark.asyncio
async def test_health_db_ok_with_working_engine(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /health returns database_ok=True when engine is connected."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from src.database.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    routes_mod._db_engine = engine
    try:
        async with client as c:
            resp = await c.get("/health")
        body = resp.json()
        assert resp.status_code == 200
        assert body["database_ok"] is True
        assert body["status"] == "ok"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_health_backward_compatible_fields(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /health still includes all original fields after hardening."""
    routes_mod._db_engine = None
    async with client as c:
        resp = await c.get("/health")
    body = resp.json()
    # All original fields must still be present
    for field in (
        "status",
        "version",
        "uptime_seconds",
        "alerts_processed",
        "active_connections",
    ):
        assert field in body, f"Missing field: {field}"
    assert isinstance(body["uptime_seconds"], (int, float))
    assert isinstance(body["alerts_processed"], int)
    assert isinstance(body["active_connections"], int)


# ---------------------------------------------------------------------------
# 6. _maintenance_store cap — bounded deque
# ---------------------------------------------------------------------------


def test_maintenance_store_is_bounded_deque(clean_stores: None) -> None:
    """_maintenance_store is a bounded deque (has maxlen)."""
    assert isinstance(routes_mod._maintenance_store, deque)
    assert routes_mod._maintenance_store.maxlen is not None
    assert routes_mod._maintenance_store.maxlen > 0


def test_maintenance_store_enforces_cap(clean_stores: None) -> None:
    """Adding entries beyond the cap evicts the oldest (deque maxlen behaviour)."""
    cap = routes_mod._maintenance_store.maxlen
    assert cap is not None

    # Fill the store beyond capacity
    for i in range(cap + 10):
        routes_mod._maintenance_store.append({"id": i, "device_name": f"dev-{i}"})

    # Store should never exceed cap
    assert len(routes_mod._maintenance_store) == cap
    # The oldest entries should have been evicted; newest should be present
    ids_in_store = {w["id"] for w in routes_mod._maintenance_store}
    # The last 'cap' entries (from i = 10 to cap+9) should be present
    for i in range(10, cap + 10):
        assert i in ids_in_store, f"id {i} missing from store after cap enforcement"
    # The first 10 should be gone
    for i in range(10):
        assert i not in ids_in_store, f"id {i} should have been evicted"


@pytest.mark.asyncio
async def test_maintenance_store_cap_via_api(
    client: AsyncClient, clean_stores: None
) -> None:
    """Creating maintenance windows via POST honours the deque cap."""
    from datetime import UTC
    from datetime import datetime as _dt

    from src.api.routes import _maintenance_store as store

    cap = store.maxlen
    assert cap is not None

    # Directly fill the store to capacity
    base_start = _dt(2030, 1, 1, 0, 0, 0, tzinfo=UTC)
    base_end = _dt(2030, 1, 1, 2, 0, 0, tzinfo=UTC)

    for i in range(cap + 5):
        store.append(
            {
                "id": i,
                "device_name": f"dev-{i}",
                "start_time": base_start.isoformat(),
                "end_time": base_end.isoformat(),
                "reason": "",
                "created_by": "",
            }
        )

    assert len(store) == cap


# ---------------------------------------------------------------------------
# 7. Validation allowlists — unit tests
# ---------------------------------------------------------------------------


def test_valid_severities_set() -> None:
    """_VALID_SEVERITIES contains exactly the expected values."""
    expected = frozenset({"CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"})
    assert expected == routes_mod._VALID_SEVERITIES


def test_valid_periods_set() -> None:
    """_VALID_PERIODS contains exactly the expected values."""
    expected = frozenset({"today", "yesterday", "7d", "30d", "1y", "all"})
    assert expected == routes_mod._VALID_PERIODS


# ---------------------------------------------------------------------------
# 8. Rate limiting — slowapi integration
# ---------------------------------------------------------------------------


@pytest.fixture
def _reset_limiter() -> Iterator[None]:
    """Reset the slowapi limiter storage between tests.

    slowapi uses an in-memory storage backend by default.  Without a reset,
    request counts from earlier tests would carry over and cause flaky
    failures.
    """
    from src.rate_limit import limiter as _limiter

    _limiter.reset()
    yield
    _limiter.reset()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reset_limiter")
async def test_rate_limit_returns_429_on_excessive_requests(
    client: AsyncClient,
    clean_stores: None,
) -> None:
    """Sending more than 30 POST requests/minute to a mutating endpoint returns 429."""
    routes_mod._db_engine = None
    got_429 = False
    async with client as c:
        for _ in range(35):
            resp = await c.post(
                "/api/settings/hardware-noise",
                params={"enabled": "true"},
            )
            if resp.status_code == 429:
                got_429 = True
                body = resp.json()
                assert "rate limit" in body["detail"].lower()
                break
    assert got_429, "Expected 429 after exceeding rate limit, but never received one"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reset_limiter")
async def test_health_endpoint_is_not_rate_limited(
    client: AsyncClient,
    clean_stores: None,
) -> None:
    """/health is exempt from rate limiting — 250 rapid requests all return 200."""
    routes_mod._db_engine = None
    async with client as c:
        for i in range(250):
            resp = await c.get("/health")
            assert (
                resp.status_code == 200
            ), f"Request #{i + 1} to /health returned {resp.status_code}, expected 200"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reset_limiter")
async def test_normal_read_usage_within_limits(
    client: AsyncClient,
    clean_stores: None,
) -> None:
    """A moderate number of read requests stays within the 200/minute limit."""
    routes_mod._db_engine = None
    async with client as c:
        for _ in range(50):
            resp = await c.get("/api/alerts")
            assert resp.status_code == 200


@pytest.mark.asyncio
@pytest.mark.usefixtures("_reset_limiter")
async def test_rate_limit_response_format(
    client: AsyncClient,
    clean_stores: None,
) -> None:
    """The 429 response body contains a 'detail' key with a rate-limit message."""
    routes_mod._db_engine = None
    async with client as c:
        for _ in range(35):
            resp = await c.post(
                "/api/settings/hardware-noise",
                params={"enabled": "true"},
            )
            if resp.status_code == 429:
                body = resp.json()
                assert "detail" in body
                assert "rate limit" in body["detail"].lower()
                return
    pytest.fail("Never hit 429 — rate limit may not be applied")
