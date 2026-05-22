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


# ---------------------------------------------------------------------------
# 5. test_dashboard_page_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_page_returns_200() -> None:
    """GET / must return HTTP 200 with valid HTML containing 'BSCCL'."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "BSCCL" in response.text
    assert "text/html" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 6. test_statistics_page_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_statistics_page_returns_200() -> None:
    """GET /statistics must return HTTP 200."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/statistics")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 7. test_settings_page_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_settings_page_returns_200() -> None:
    """GET /settings must return HTTP 200."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# 8. test_get_alerts_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_returns_json() -> None:
    """GET /api/alerts must return HTTP 200 with a JSON list."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/alerts")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


# ---------------------------------------------------------------------------
# 9. test_get_incidents_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incidents_returns_json() -> None:
    """GET /api/incidents must return HTTP 200 with a JSON list."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/incidents")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


# ---------------------------------------------------------------------------
# 10. test_get_devices_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_devices_returns_json() -> None:
    """GET /api/devices must return HTTP 200 with a list of device dicts."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/devices")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert len(body) > 0
    # Each device should have name and location
    first = body[0]
    assert "name" in first
    assert "location" in first


# ---------------------------------------------------------------------------
# 11. test_get_topology_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_topology_returns_json() -> None:
    """GET /api/topology must return HTTP 200 with nodes and links."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/topology")

    assert response.status_code == 200
    body = response.json()
    assert "nodes" in body
    assert "links" in body
    assert isinstance(body["nodes"], list)
    assert isinstance(body["links"], list)
    assert len(body["nodes"]) > 0


# ---------------------------------------------------------------------------
# 12. test_get_stats_daily_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_daily_returns_json() -> None:
    """GET /api/stats/daily must return HTTP 200 with stats dict."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/stats/daily")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)


# ---------------------------------------------------------------------------
# 13. test_get_stats_weekly_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_weekly_returns_json() -> None:
    """GET /api/stats/weekly must return HTTP 200 with stats dict."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/stats/weekly")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)


# ---------------------------------------------------------------------------
# 14. test_get_bgp_peers_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_bgp_peers_returns_json() -> None:
    """GET /api/bgp/peers must return HTTP 200 with a list."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/bgp/peers")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


# ---------------------------------------------------------------------------
# 15. test_get_alert_by_id_returns_404_for_unknown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alert_by_id_returns_404_for_unknown() -> None:
    """GET /api/alerts/nonexistent must return 404."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/alerts/nonexistent-id-99999")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 16. test_get_incident_by_id_returns_404_for_unknown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incident_by_id_returns_404_for_unknown() -> None:
    """GET /api/incidents/nonexistent must return 404."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/incidents/nonexistent-id-99999")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 17. test_acknowledge_incident_returns_404_for_unknown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledge_incident_returns_404_for_unknown() -> None:
    """POST /api/incidents/nonexistent/acknowledge must return 404."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/api/incidents/nonexistent-id-99999/acknowledge")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 18. test_get_alerts_supports_severity_filter
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_supports_severity_filter() -> None:
    """GET /api/alerts?severity=CRITICAL must return HTTP 200."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/alerts", params={"severity": "CRITICAL"})

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
