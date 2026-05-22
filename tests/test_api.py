"""Tests for REST API endpoints.

TDD: tests written BEFORE implementation (RED phase).
Uses httpx.AsyncClient with the FastAPI app (no real server started).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ---------------------------------------------------------------------------
# 1. test_health_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_returns_200() -> None:
    """GET /health must return HTTP 200 with status ok."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 2. test_health_has_version
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_has_version() -> None:
    """GET /health response body must include a 'version' field."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert "version" in body
    assert body["version"]  # non-empty string


# ---------------------------------------------------------------------------
# 3. test_health_has_uptime_and_alerts_processed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_has_uptime_and_alerts_processed() -> None:
    """GET /health must include uptime_seconds, alerts_processed, active_connections."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    body = response.json()
    assert "uptime_seconds" in body
    assert "alerts_processed" in body
    assert "active_connections" in body
    assert isinstance(body["uptime_seconds"], (int, float))
    assert isinstance(body["alerts_processed"], int)
    assert isinstance(body["active_connections"], int)


# ---------------------------------------------------------------------------
# 4. test_unknown_route_returns_404
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_route_returns_404() -> None:
    """GET /nonexistent must return 404."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/nonexistent-endpoint-xyz")

    assert response.status_code == 404
