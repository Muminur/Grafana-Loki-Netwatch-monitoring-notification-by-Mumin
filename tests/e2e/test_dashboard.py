"""End-to-end tests for the dashboard HTML output.

TDD: tests written BEFORE implementation (RED phase).
Verifies that rendered HTML pages contain expected structural elements.
"""

from __future__ import annotations

import pytest
from httpx import (  # noqa: F401 (unused but required by httpx pattern)
    ASGITransport,
    AsyncClient,
)

# ---------------------------------------------------------------------------
# 1. test_dashboard_has_critical_tab
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_critical_tab() -> None:
    """Dashboard HTML must contain a tab for CRITICAL alerts."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "CRITICAL" in response.text


# ---------------------------------------------------------------------------
# 2. test_dashboard_has_neon_theme
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_neon_theme() -> None:
    """Dashboard HTML must link to neon-theme.css."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "neon-theme.css" in response.text


# ---------------------------------------------------------------------------
# 3. test_dashboard_includes_scripts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_includes_scripts() -> None:
    """Dashboard HTML must include websocket.js and dashboard.js script tags."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "websocket.js" in response.text
    assert "dashboard.js" in response.text


# ---------------------------------------------------------------------------
# 4. test_dashboard_has_severity_cards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_severity_cards() -> None:
    """Dashboard HTML must contain severity counter cards."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    html = response.text
    # All 5 severity levels should be present
    for severity in ("CRITICAL", "WARNING", "INFO", "NOISE", "LOGIN"):
        assert severity in html, f"Missing severity card: {severity}"


# ---------------------------------------------------------------------------
# 5. test_dashboard_has_nav_header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_nav_header() -> None:
    """Dashboard HTML must contain the BSCCL NETWATCH nav header."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "NETWATCH" in response.text


# ---------------------------------------------------------------------------
# 6. test_dashboard_has_orbitron_font
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_orbitron_font() -> None:
    """Base template must load the Orbitron font from Google Fonts."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "Orbitron" in response.text


# ---------------------------------------------------------------------------
# 7. test_statistics_page_has_charts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_statistics_page_has_charts() -> None:
    """Statistics page HTML must reference charts.js."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/statistics")

    assert response.status_code == 200
    assert "charts.js" in response.text


# ---------------------------------------------------------------------------
# 8. test_settings_page_has_form
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_settings_page_has_form() -> None:
    """Settings page HTML must contain a form element."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/settings")

    assert response.status_code == 200
    assert "<form" in response.text


# ---------------------------------------------------------------------------
# 9. test_dashboard_has_chartjs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_chartjs() -> None:
    """Dashboard HTML must include Chart.js CDN script."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "chart.js" in response.text.lower() or "Chart.js" in response.text


# ---------------------------------------------------------------------------
# 10. test_dashboard_has_live_indicator
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_has_live_indicator() -> None:
    """Dashboard HTML must contain LIVE indicator element."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/")

    assert response.status_code == 200
    assert "LIVE" in response.text
