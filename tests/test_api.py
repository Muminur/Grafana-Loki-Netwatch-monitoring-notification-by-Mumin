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


# ---------------------------------------------------------------------------
# 19. test_get_stats_monthly_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_monthly_returns_json() -> None:
    """GET /api/stats/monthly must return HTTP 200 with period='monthly'."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/stats/monthly")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body["period"] == "monthly"
    assert "months" in body
    assert "total" in body
    assert isinstance(body["months"], list)
    assert isinstance(body["total"], int)


# ---------------------------------------------------------------------------
# 20. test_get_stats_monthly_groups_by_month
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_monthly_groups_by_month() -> None:
    """Monthly stats with two alerts in different months → two month entries."""
    import src.api.routes as routes_mod
    from src.main import app

    # Seed two alerts in different months
    original_store = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "CRITICAL", "timestamp": "2026-01-15T10:00:00"}
    )
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "WARNING", "timestamp": "2026-02-20T10:00:00"}
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/stats/monthly")

        body = response.json()
        assert response.status_code == 200
        assert len(body["months"]) == 2
        keys = [m["month"] for m in body["months"]]
        assert "2026-01" in keys
        assert "2026-02" in keys
    finally:
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(original_store)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 21. test_get_stats_monthly_handles_bad_timestamp
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_monthly_handles_bad_timestamp() -> None:
    """Monthly stats with a malformed timestamp → falls into 'unknown' bucket."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "INFO", "timestamp": "not-a-date"}
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/stats/monthly")

        body = response.json()
        assert response.status_code == 200
        keys = [m["month"] for m in body["months"]]
        assert "unknown" in keys
    finally:
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(original_store)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 22. test_get_stats_yearly_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_yearly_returns_json() -> None:
    """GET /api/stats/yearly must return HTTP 200 with period='yearly'."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/stats/yearly")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, dict)
    assert body["period"] == "yearly"
    assert "years" in body
    assert "total" in body
    assert isinstance(body["years"], list)
    assert isinstance(body["total"], int)


# ---------------------------------------------------------------------------
# 23. test_get_stats_yearly_groups_by_year
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_yearly_groups_by_year() -> None:
    """Yearly stats with alerts in two different years → two year entries."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "CRITICAL", "timestamp": "2025-06-01T00:00:00"}
    )
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "WARNING", "timestamp": "2026-01-01T00:00:00"}
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/stats/yearly")

        body = response.json()
        assert response.status_code == 200
        assert len(body["years"]) == 2
        year_keys = [y["year"] for y in body["years"]]
        assert "2025" in year_keys
        assert "2026" in year_keys
    finally:
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(original_store)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 24. test_get_stats_yearly_handles_bad_timestamp
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_stats_yearly_handles_bad_timestamp() -> None:
    """Yearly stats with malformed timestamp → falls into 'unknown' bucket."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"classification": "NOISE", "timestamp": None}
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/stats/yearly")

        body = response.json()
        assert response.status_code == 200
        year_keys = [y["year"] for y in body["years"]]
        assert "unknown" in year_keys
    finally:
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(original_store)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 25. test_get_maintenance_windows_returns_json
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_maintenance_windows_returns_json() -> None:
    """GET /api/maintenance must return HTTP 200 with a JSON list."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/api/maintenance")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)


# ---------------------------------------------------------------------------
# 26. test_create_maintenance_window_returns_201
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_maintenance_window_returns_201() -> None:
    """POST /api/maintenance with valid body → 201 with the created record."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/api/maintenance",
                json={
                    "device_name": "EQ-RTR-01",
                    "start_time": "2026-06-01T00:00:00+00:00",
                    "end_time": "2026-06-01T02:00:00+00:00",
                    "reason": "Planned upgrade",
                    "created_by": "noc-ops",
                },
            )

        assert response.status_code == 201
        body = response.json()
        assert body["device_name"] == "EQ-RTR-01"
        assert body["reason"] == "Planned upgrade"
        assert body["created_by"] == "noc-ops"
        assert "id" in body
        assert isinstance(body["id"], int)
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(original_store)  # noqa: SLF001


# ---------------------------------------------------------------------------
# 27. test_create_maintenance_window_missing_fields_returns_422
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_maintenance_window_missing_fields_returns_422() -> None:
    """POST /api/maintenance with missing required fields → 422 Unprocessable Entity."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/maintenance",
            json={"reason": "only reason, no device or times"},
        )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# 28. test_delete_maintenance_window_returns_200
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_maintenance_window_returns_200() -> None:
    """DELETE /api/maintenance/{id} for existing window → 200 with deleted status."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    original_counter = routes_mod._maintenance_id_counter  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001

    # Manually insert a window with a known ID
    test_window: dict = {  # type: ignore[type-arg]
        "id": 9999,
        "device_name": "COX-Core-01",
        "start_time": "2026-06-01T00:00:00+00:00",
        "end_time": "2026-06-01T04:00:00+00:00",
        "reason": "Test window",
        "created_by": "test",
    }
    routes_mod._maintenance_store.append(test_window)  # noqa: SLF001

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.delete("/api/maintenance/9999")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "deleted"
        assert body["id"] == 9999
        # Verify removed from store
        assert not any(  # noqa: PT018
            w["id"] == 9999 for w in routes_mod._maintenance_store  # noqa: SLF001
        )
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(original_store)  # noqa: SLF001
        routes_mod._maintenance_id_counter = original_counter  # noqa: SLF001


# ---------------------------------------------------------------------------
# 29. test_delete_maintenance_window_returns_404_for_unknown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_maintenance_window_returns_404_for_unknown() -> None:
    """DELETE /api/maintenance/99998 for nonexistent window → 404."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.delete("/api/maintenance/99998")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 30. test_get_maintenance_windows_filters_expired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_maintenance_windows_filters_expired() -> None:
    """GET /api/maintenance only returns windows whose end_time is in the future."""
    import src.api.routes as routes_mod
    from src.main import app

    original_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001

    # Expired window (end_time in the past)
    routes_mod._maintenance_store.append(  # noqa: SLF001
        {
            "id": 1,
            "device_name": "EQ-RTR-01",
            "start_time": "2020-01-01T00:00:00+00:00",
            "end_time": "2020-01-01T02:00:00+00:00",
            "reason": "Old window",
            "created_by": "ops",
        }
    )
    # Active window (end_time in the far future)
    routes_mod._maintenance_store.append(  # noqa: SLF001
        {
            "id": 2,
            "device_name": "KKT-Core-01",
            "start_time": "2030-01-01T00:00:00+00:00",
            "end_time": "2030-01-01T04:00:00+00:00",
            "reason": "Future window",
            "created_by": "ops",
        }
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/maintenance")

        assert response.status_code == 200
        body = response.json()
        # Only the future window should appear
        ids = [w["id"] for w in body]
        assert 2 in ids
        assert 1 not in ids
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(original_store)  # noqa: SLF001
