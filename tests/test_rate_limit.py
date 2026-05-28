"""Dedicated tests for the rate_limit module.

Covers:
  - Module-level assertions: limiter type, constant formats, relative limits
  - Integration: 429 returned after exceeding RATE_LIMIT_MUTATING on POST endpoint
  - Integration: /health and /metrics are exempt from rate limiting
  - Integration: GET endpoints governed by RATE_LIMIT_READ (no 429 on moderate use)
  - Integration: POST endpoints governed by RATE_LIMIT_MUTATING (triggers on mutating)
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient
from slowapi import Limiter

import src.api.routes as routes_mod

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_rate_limit(rate_str: str) -> tuple[int, str]:
    """Parse ``"N/unit"`` into ``(N, unit)``.

    Raises ``ValueError`` if the string does not match the expected format.
    """
    m = re.fullmatch(r"(\d+)/(minute|second|hour|day)", rate_str)
    if m is None:
        raise ValueError(f"Invalid rate limit string: {rate_str!r}")
    return int(m.group(1)), m.group(2)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def _reset_limiter() -> Iterator[None]:
    """Clear the slowapi in-memory counter store before and after each test.

    Without this, request counts from earlier tests carry over and cause
    flaky failures when running the full suite.
    """
    from src.rate_limit import limiter as _limiter

    _limiter.reset()
    yield
    _limiter.reset()


@pytest.fixture
def clean_stores() -> Iterator[None]:
    """Snapshot and restore all in-memory route stores and the DB engine."""
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    orig_incidents = list(routes_mod._incidents_store)  # noqa: SLF001
    orig_maint = list(routes_mod._maintenance_store)  # noqa: SLF001
    orig_counter = routes_mod._maintenance_id_counter  # noqa: SLF001
    orig_noise = routes_mod._hardware_defects_as_noise  # noqa: SLF001
    orig_engine = routes_mod._db_engine  # noqa: SLF001

    yield

    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001
    routes_mod._incidents_store.clear()  # noqa: SLF001
    routes_mod._incidents_store.extend(orig_incidents)  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001
    routes_mod._maintenance_store.extend(orig_maint)  # noqa: SLF001
    routes_mod._maintenance_id_counter = orig_counter  # noqa: SLF001
    routes_mod._hardware_defects_as_noise = orig_noise  # noqa: SLF001
    routes_mod._db_engine = orig_engine  # noqa: SLF001


# ---------------------------------------------------------------------------
# Module-level tests — no HTTP calls needed
# ---------------------------------------------------------------------------


def test_limiter_is_slowapi_limiter_instance() -> None:
    """``limiter`` must be a ``slowapi.Limiter`` instance."""
    from src.rate_limit import limiter

    assert isinstance(limiter, Limiter)


def test_rate_limit_mutating_is_nonempty_string() -> None:
    """``RATE_LIMIT_MUTATING`` must be a non-empty string."""
    from src.rate_limit import RATE_LIMIT_MUTATING

    assert isinstance(RATE_LIMIT_MUTATING, str)
    assert RATE_LIMIT_MUTATING.strip() != ""


def test_rate_limit_read_is_nonempty_string() -> None:
    """``RATE_LIMIT_READ`` must be a non-empty string."""
    from src.rate_limit import RATE_LIMIT_READ

    assert isinstance(RATE_LIMIT_READ, str)
    assert RATE_LIMIT_READ.strip() != ""


def test_rate_limit_mutating_matches_expected_format() -> None:
    """``RATE_LIMIT_MUTATING`` must match the ``"N/unit"`` format."""
    from src.rate_limit import RATE_LIMIT_MUTATING

    count, unit = _parse_rate_limit(RATE_LIMIT_MUTATING)
    assert count > 0
    assert unit in {"second", "minute", "hour", "day"}


def test_rate_limit_read_matches_expected_format() -> None:
    """``RATE_LIMIT_READ`` must match the ``"N/unit"`` format."""
    from src.rate_limit import RATE_LIMIT_READ

    count, unit = _parse_rate_limit(RATE_LIMIT_READ)
    assert count > 0
    assert unit in {"second", "minute", "hour", "day"}


def test_rate_limit_read_allows_more_than_mutating() -> None:
    """Read endpoints must be allowed more requests per unit than mutating ones.

    Both limits must use the same unit so the comparison is meaningful.
    """
    from src.rate_limit import RATE_LIMIT_MUTATING, RATE_LIMIT_READ

    read_count, read_unit = _parse_rate_limit(RATE_LIMIT_READ)
    mutating_count, mutating_unit = _parse_rate_limit(RATE_LIMIT_MUTATING)

    assert read_unit == mutating_unit, (
        f"Both limits should use the same time unit for a fair comparison, "
        f"but RATE_LIMIT_READ uses {read_unit!r} and RATE_LIMIT_MUTATING uses "
        f"{mutating_unit!r}"
    )
    assert read_count > mutating_count, (
        f"RATE_LIMIT_READ ({RATE_LIMIT_READ}) should allow more requests per "
        f"{read_unit} than RATE_LIMIT_MUTATING ({RATE_LIMIT_MUTATING})"
    )


def test_rate_limit_mutating_value_is_30_per_minute() -> None:
    """``RATE_LIMIT_MUTATING`` must be exactly ``"30/minute"`` per the PRD."""
    from src.rate_limit import RATE_LIMIT_MUTATING

    assert RATE_LIMIT_MUTATING == "30/minute"


def test_rate_limit_read_value_is_200_per_minute() -> None:
    """``RATE_LIMIT_READ`` must be exactly ``"200/minute"`` per the PRD."""
    from src.rate_limit import RATE_LIMIT_READ

    assert RATE_LIMIT_READ == "200/minute"


def test_limiter_key_func_is_get_remote_address() -> None:
    """The limiter's key function must be ``get_remote_address``."""
    from slowapi.util import get_remote_address

    from src.rate_limit import limiter

    # Access the internal _key_func attribute that slowapi stores on Limiter
    assert limiter._key_func is get_remote_address  # noqa: SLF001


# ---------------------------------------------------------------------------
# Integration tests — ASGI TestClient
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_post_endpoint_returns_429_after_exceeding_mutating_limit() -> None:
    """Exceeding RATE_LIMIT_MUTATING on a POST endpoint yields HTTP 429.

    Sends 35 requests to /api/settings/hardware-noise (guarded by
    RATE_LIMIT_MUTATING = "30/minute") and asserts that at least one returns 429.
    """
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001
    got_429 = False
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(35):
            resp = await client.post(
                "/api/settings/hardware-noise",
                params={"enabled": "true"},
            )
            if resp.status_code == 429:
                got_429 = True
                break

    assert got_429, "Expected HTTP 429 after exceeding RATE_LIMIT_MUTATING, got none"


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_429_response_body_contains_detail_with_rate_limit_message() -> None:
    """When rate-limited, the JSON body must contain ``detail`` with 'rate limit'."""
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(35):
            resp = await client.post(
                "/api/settings/hardware-noise",
                params={"enabled": "true"},
            )
            if resp.status_code == 429:
                body = resp.json()
                assert "detail" in body
                assert "rate limit" in body["detail"].lower()
                return

    pytest.fail("Never received HTTP 429 — rate limiter may not be active")


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_health_endpoint_is_exempt_from_rate_limiting() -> None:
    """/health must be exempt: 250 rapid requests all return 200, never 429."""
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(250):
            resp = await client.get("/health")
            assert resp.status_code == 200, (
                f"Request #{i + 1} to /health returned {resp.status_code} "
                f"— endpoint must be exempt from rate limiting"
            )


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_metrics_endpoint_is_exempt_from_rate_limiting() -> None:
    """/metrics must be exempt: 250 rapid requests all return 200, never 429."""
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(250):
            resp = await client.get("/metrics")
            assert resp.status_code == 200, (
                f"Request #{i + 1} to /metrics returned {resp.status_code} "
                f"— endpoint must be exempt from rate limiting"
            )


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_get_alerts_uses_read_limit_does_not_trigger_on_moderate_use() -> None:
    """GET /api/alerts must not 429 for requests well within RATE_LIMIT_READ.

    RATE_LIMIT_READ = "200/minute" so 50 rapid requests should never trigger 429.
    """
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for i in range(50):
            resp = await client.get("/api/alerts")
            assert resp.status_code in {200, 400}, (
                f"Request #{i + 1} to /api/alerts returned {resp.status_code}; "
                f"should not be rate-limited within first 50 requests "
                f"(RATE_LIMIT_READ = 200/minute)"
            )
            assert resp.status_code != 429


@pytest.mark.usefixtures("_reset_limiter", "clean_stores")
async def test_get_endpoints_use_higher_limit_than_post_endpoints() -> None:
    """POST endpoint hits 429 well before GET endpoint with same request count.

    This confirms that GET uses RATE_LIMIT_READ (200/min) and POST uses
    RATE_LIMIT_MUTATING (30/min): 35 GET requests should all succeed, while
    35 POST requests should trigger at least one 429.
    """
    from src.main import app

    routes_mod._db_engine = None  # noqa: SLF001

    # 35 GET requests: none should 429 (limit = 200/minute)
    get_429_count = 0
    post_429_count = 0

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(35):
            resp = await client.get("/api/alerts")
            if resp.status_code == 429:
                get_429_count += 1

    # Reset limiter and repeat for POST
    from src.rate_limit import limiter as _limiter

    _limiter.reset()

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        for _ in range(35):
            resp = await client.post(
                "/api/settings/hardware-noise",
                params={"enabled": "true"},
            )
            if resp.status_code == 429:
                post_429_count += 1

    assert get_429_count == 0, (
        f"GET /api/alerts was rate-limited {get_429_count} times in 35 requests — "
        f"expected 0 (RATE_LIMIT_READ = 200/minute)"
    )
    assert post_429_count > 0, (
        "POST /api/settings/hardware-noise was never rate-limited in 35 requests — "
        "expected at least 1 (RATE_LIMIT_MUTATING = 30/minute)"
    )
