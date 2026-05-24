"""Tests for optional API-key authentication (src/auth.py).

Covers:
  (a) AUTH DISABLED (API_KEY unset / empty): mutating endpoints succeed with
      no X-API-Key header — backward-compatible default.
  (b) AUTH ENABLED (API_KEY set): mutating endpoint with no header → 401;
      wrong header → 401; correct header → success.
  (c) Read-only GET and /health endpoints remain open even when auth is
      enabled — NOC reads and scrapers must never be blocked.

All tests use FastAPI TestClient in-process (no port binding).  Settings
cache is cleared before and after each auth-enabled test so the monkeypatched
env var takes effect, and restored in teardown.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MAINT_BODY = {
    "device_name": "EQ-RTR-01",
    "start_time": "2030-06-01T00:00:00+00:00",
    "end_time": "2030-06-01T02:00:00+00:00",
    "reason": "auth test",
    "created_by": "test",
}


# ---------------------------------------------------------------------------
# (a) AUTH DISABLED — backward-compat: all mutating endpoints open
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_post_maintenance_no_header_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is unset, POST /api/maintenance succeeds with no auth header."""
    import src.api.routes as routes_mod
    from src.main import app

    monkeypatch.delenv("API_KEY", raising=False)

    orig_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    orig_counter = routes_mod._maintenance_id_counter  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/maintenance", json=_MAINT_BODY)
        assert resp.status_code == 201
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(orig_store)  # noqa: SLF001
        routes_mod._maintenance_id_counter = orig_counter  # noqa: SLF001


@pytest.mark.asyncio
async def test_disabled_delete_maintenance_no_header_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is unset, DELETE /api/maintenance/{id} succeeds with no header."""
    import src.api.routes as routes_mod
    from src.main import app

    monkeypatch.delenv("API_KEY", raising=False)

    orig_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001
    routes_mod._maintenance_store.append(  # noqa: SLF001
        {
            "id": 7777,
            "device_name": "EQ-RTR-01",
            "start_time": "2030-06-01T00:00:00+00:00",
            "end_time": "2030-06-01T02:00:00+00:00",
            "reason": "",
            "created_by": "",
        }
    )

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete("/api/maintenance/7777")
        assert resp.status_code == 200
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(orig_store)  # noqa: SLF001


@pytest.mark.asyncio
async def test_disabled_post_hardware_noise_no_header_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is unset, POST /api/settings/hardware-noise succeeds."""
    import src.api.routes as routes_mod
    from src.main import app

    monkeypatch.delenv("API_KEY", raising=False)

    orig_noise = routes_mod._hardware_defects_as_noise  # noqa: SLF001
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/settings/hardware-noise", params={"enabled": True}
            )
        assert resp.status_code == 200
    finally:
        routes_mod._hardware_defects_as_noise = orig_noise  # noqa: SLF001


@pytest.mark.asyncio
async def test_disabled_acknowledge_incident_no_header_returns_404_not_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is unset, POST /api/incidents/{id}/acknowledge proceeds to 404.

    The endpoint is reached (not blocked by auth), so an unknown ID returns 404
    rather than 401, proving authentication is disabled.
    """
    import src.api.routes as routes_mod
    from src.main import app

    monkeypatch.delenv("API_KEY", raising=False)

    orig_incidents = list(routes_mod._incidents_store)  # noqa: SLF001
    routes_mod._incidents_store.clear()  # noqa: SLF001
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/incidents/no-such-id/acknowledge")
        # 404 means auth was bypassed (not blocked by 401)
        assert resp.status_code == 404
    finally:
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_incidents)  # noqa: SLF001


# ---------------------------------------------------------------------------
# (b) AUTH ENABLED — 401 on missing/wrong header; 2xx on correct header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enabled_post_maintenance_no_header_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, POST /api/maintenance with no header → 401."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/maintenance", json=_MAINT_BODY)
        assert resp.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_post_maintenance_wrong_header_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, POST /api/maintenance with wrong key → 401."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "correct-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/maintenance",
                json=_MAINT_BODY,
                headers={"X-API-Key": "wrong-key"},
            )
        assert resp.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_post_maintenance_correct_header_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, POST /api/maintenance with correct key → 201."""
    import src.api.routes as routes_mod
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "correct-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()

    orig_store = list(routes_mod._maintenance_store)  # noqa: SLF001
    orig_counter = routes_mod._maintenance_id_counter  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001

    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/maintenance",
                json=_MAINT_BODY,
                headers={"X-API-Key": "correct-key"},
            )
        assert resp.status_code == 201
    finally:
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(orig_store)  # noqa: SLF001
        routes_mod._maintenance_id_counter = orig_counter  # noqa: SLF001
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_delete_maintenance_no_header_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, DELETE /api/maintenance/{id} with no header → 401."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete("/api/maintenance/1")
        assert resp.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_post_hardware_noise_wrong_header_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When API_KEY is set, POST /api/settings/hardware-noise with wrong key → 401."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "correct-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/settings/hardware-noise",
                params={"enabled": True},
                headers={"X-API-Key": "bad-key"},
            )
        assert resp.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_acknowledge_incident_no_header_returns_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST acknowledge with no header returns 401 when auth is enabled."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post("/api/incidents/any-id/acknowledge")
        assert resp.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# (c) Read-only GET endpoints and /health remain open when auth is enabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enabled_health_open_no_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /health is always open — no key required even when API_KEY is set."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_get_alerts_open_no_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /api/alerts is always open — no key required even when API_KEY is set."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/alerts")
        assert resp.status_code == 200
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_get_incidents_open_no_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /api/incidents is always open — no key required even when API_KEY is set."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/incidents")
        assert resp.status_code == 200
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


@pytest.mark.asyncio
async def test_enabled_get_hardware_noise_open_no_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /api/settings/hardware-noise is open (read-only) even when API_KEY is set."""
    from src.config import get_settings
    from src.main import app

    monkeypatch.setenv("API_KEY", "test-secret-key")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/settings/hardware-noise")
        assert resp.status_code == 200
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Unit tests for auth dependency itself
# ---------------------------------------------------------------------------


def test_require_api_key_disabled_allows_any_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """require_api_key returns None when API_KEY is empty (auth disabled)."""
    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.delenv("API_KEY", raising=False)
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    # Should not raise — any value (or None) is accepted when auth is disabled.
    try:
        result = require_api_key(x_api_key=None)
        assert result is None
        result = require_api_key(x_api_key="anything")
        assert result is None
    finally:
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


def test_require_api_key_enabled_correct_key_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """require_api_key returns None (no error) when the correct key is provided."""
    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.setenv("API_KEY", "secret-abc")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        result = require_api_key(x_api_key="secret-abc")
        assert result is None
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


def test_require_api_key_enabled_wrong_key_raises_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """require_api_key raises HTTP 401 when the key does not match."""
    from fastapi import HTTPException

    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.setenv("API_KEY", "secret-abc")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        with pytest.raises(HTTPException) as exc_info:
            require_api_key(x_api_key="wrong-key")
        assert exc_info.value.status_code == 401
        # The error detail must NOT echo the provided or expected key.
        detail = exc_info.value.detail
        assert "wrong-key" not in detail
        assert "secret-abc" not in detail
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


def test_require_api_key_enabled_missing_key_raises_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """require_api_key raises HTTP 401 when the header is missing (None)."""
    from fastapi import HTTPException

    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.setenv("API_KEY", "secret-abc")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        with pytest.raises(HTTPException) as exc_info:
            require_api_key(x_api_key=None)
        assert exc_info.value.status_code == 401
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


def test_whitespace_only_key_disables_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whitespace-only API_KEY resolves to disabled (safe misconfig default)."""
    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.setenv("API_KEY", "   ")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        # Must NOT raise: a whitespace-only key is treated as unset/disabled
        # rather than enabling auth with a trivially guessable key.
        require_api_key(x_api_key=None)
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()


def test_401_sets_www_authenticate_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 401 challenge includes a WWW-Authenticate header (RFC 9110)."""
    from fastapi import HTTPException

    from src.auth import require_api_key
    from src.config import get_settings

    monkeypatch.setenv("API_KEY", "secret-xyz")
    if hasattr(get_settings, "cache_clear"):
        get_settings.cache_clear()
    try:
        with pytest.raises(HTTPException) as exc_info:
            require_api_key(x_api_key=None)
        assert exc_info.value.status_code == 401
        assert exc_info.value.headers == {"WWW-Authenticate": "ApiKey"}
    finally:
        monkeypatch.delenv("API_KEY", raising=False)
        if hasattr(get_settings, "cache_clear"):
            get_settings.cache_clear()
