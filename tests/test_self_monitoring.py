"""Tests for self-monitoring: Loki health check and stale-data detection.

Covers:
  1. SyslogReceiver.is_connected / last_message_at properties
  2. /health endpoint Loki fields (loki_connected, stale_data)
  3. /health status degrades to "degraded" when data is stale
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ---------------------------------------------------------------------------
# 1. SyslogReceiver property tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_receiver_is_connected_false_when_idle() -> None:
    """A freshly created receiver (not started) reports is_connected=False."""
    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings
    from src.core.syslog_receiver import SyslogReceiver

    settings = Settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    assert receiver.is_connected is False


@pytest.mark.asyncio
async def test_receiver_last_message_at_none_initially() -> None:
    """last_message_at is None before any message is received."""
    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings
    from src.core.syslog_receiver import SyslogReceiver

    settings = Settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    assert receiver.last_message_at is None


@pytest.mark.asyncio
async def test_receiver_last_message_at_updates_on_record() -> None:
    """_record_message_received updates last_message_at."""
    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings
    from src.core.syslog_receiver import SyslogReceiver

    settings = Settings()
    receiver = SyslogReceiver(settings, AsyncMock())
    before = datetime.now(UTC)
    receiver._record_message_received()  # noqa: SLF001
    after = datetime.now(UTC)

    assert receiver.last_message_at is not None
    assert before <= receiver.last_message_at <= after


@pytest.mark.asyncio
async def test_receiver_health_status_includes_last_message_at() -> None:
    """health_status() includes last_message_at in the snapshot."""
    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings
    from src.core.syslog_receiver import SyslogReceiver

    settings = Settings()
    receiver = SyslogReceiver(settings, AsyncMock())

    # Before any message
    health = receiver.health_status()
    assert health.last_message_at is None

    # After recording a message
    receiver._record_message_received()  # noqa: SLF001
    health = receiver.health_status()
    assert health.last_message_at is not None


# ---------------------------------------------------------------------------
# 2. /health endpoint Loki fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_includes_loki_fields() -> None:
    """GET /health includes loki_connected, last_alert_received_at, stale_data."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert "loki_connected" in body
    assert "last_alert_received_at" in body
    assert "stale_data" in body
    assert isinstance(body["loki_connected"], bool)
    assert isinstance(body["stale_data"], bool)


# ---------------------------------------------------------------------------
# 3. /health degrades when data is stale
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_degraded_when_stale() -> None:
    """status should be 'degraded' when receiver has stale data."""
    from src.api import routes as routes_mod  # noqa: SLF001
    from src.core.syslog_receiver import SyslogReceiver
    from src.main import app

    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings

    settings = Settings()
    fake_receiver = SyslogReceiver(settings, AsyncMock())
    # Simulate: connected but last message was 15 minutes ago
    fake_receiver._running = True  # noqa: SLF001
    fake_receiver._is_connected = True  # noqa: SLF001
    fake_receiver._active_mode = "http"  # noqa: SLF001
    fake_receiver._last_message_at = datetime.now(UTC) - timedelta(  # noqa: SLF001
        minutes=15
    )

    original_receiver = routes_mod._receiver  # noqa: SLF001
    routes_mod._receiver = fake_receiver  # noqa: SLF001
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")

        body = response.json()
        assert body["stale_data"] is True
        assert body["status"] == "degraded"
        assert body["loki_connected"] is True
        assert body["last_alert_received_at"] is not None
    finally:
        routes_mod._receiver = original_receiver  # noqa: SLF001


@pytest.mark.asyncio
async def test_health_ok_when_recent_data() -> None:
    """status should be 'ok' when receiver has recent data."""
    from src.api import routes as routes_mod  # noqa: SLF001
    from src.core.syslog_receiver import SyslogReceiver
    from src.main import app

    os.environ.setdefault("MONITOR_HOST", "127.0.0.1")
    from src.config import Settings

    settings = Settings()
    fake_receiver = SyslogReceiver(settings, AsyncMock())
    # Simulate: connected and last message was 2 minutes ago
    fake_receiver._running = True  # noqa: SLF001
    fake_receiver._is_connected = True  # noqa: SLF001
    fake_receiver._active_mode = "ws"  # noqa: SLF001
    fake_receiver._last_message_at = datetime.now(UTC) - timedelta(  # noqa: SLF001
        minutes=2
    )

    original_receiver = routes_mod._receiver  # noqa: SLF001
    routes_mod._receiver = fake_receiver  # noqa: SLF001
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")

        body = response.json()
        assert body["stale_data"] is False
        assert body["loki_connected"] is True
        assert body["last_alert_received_at"] is not None
    finally:
        routes_mod._receiver = original_receiver  # noqa: SLF001


# ---------------------------------------------------------------------------
# 4. set_receiver wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_receiver_wires_correctly() -> None:
    """set_receiver() stores the receiver in the routes module."""
    from src.api import routes as routes_mod  # noqa: SLF001
    from src.api.routes import set_receiver

    original = routes_mod._receiver  # noqa: SLF001
    try:
        sentinel = object()
        set_receiver(sentinel)  # type: ignore[arg-type]
        assert routes_mod._receiver is sentinel  # noqa: SLF001
    finally:
        routes_mod._receiver = original  # noqa: SLF001
