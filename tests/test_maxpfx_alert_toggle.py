"""Tests for the MAXPFX alert mute toggle.

When the operator turns MAXPFX alerts OFF, MAXPFX events must be muted across
every live surface -- Discord/Telegram, audio, active-incident card, and the live
dashboard feed -- while still being written to the database for audit/history.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import src.api.routes as routes_mod
import src.main as main_mod
from src.config import Settings
from src.database.crud import set_app_setting as _set_app_setting
from src.database.models import AlertLog, Base

if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Task 1 -- Unit tests for the accessor helper
# ---------------------------------------------------------------------------


class TestIsMaxpfxAlertsEnabled:
    """The ``is_maxpfx_alerts_enabled`` accessor reflects the module flag."""

    def test_default_is_enabled(self) -> None:
        assert routes_mod.is_maxpfx_alerts_enabled() is True

    def test_reflects_disabled_flag(self) -> None:
        orig = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001
        try:
            routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001
            assert routes_mod.is_maxpfx_alerts_enabled() is False
        finally:
            routes_mod._maxpfx_alerts_enabled = orig  # noqa: SLF001


# ---------------------------------------------------------------------------
# Task 2 -- Integration tests: pipeline mute gate
# ---------------------------------------------------------------------------


def _settings() -> Settings:
    """Minimal Settings stub carrying only what the notify path reads."""
    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", True)
    object.__setattr__(s, "telegram_enabled", False)
    object.__setattr__(s, "notify_severity", "CRITICAL")
    return s


@pytest.fixture
def _isolated_pipeline() -> Iterator[None]:
    """Force minimal globals so a parsed line reaches the gates cleanly.

    _dedup=None      -> should_send=True
    _correlator=None -> independent event, incident_id=""
    _engine=None     -> DB writes skipped
    _escalation=None -> escalation skipped

    Snapshots and restores the globals + stores so the changes cannot leak
    into other tests (no cross-test global poisoning).
    """
    orig = (
        main_mod._dedup,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._engine,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    orig_inc = list(routes_mod._incidents_store)  # noqa: SLF001
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._engine = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001
    routes_mod._incidents_store.clear()  # noqa: SLF001
    routes_mod._alerts_store.clear()  # noqa: SLF001
    try:
        yield
    finally:
        (
            main_mod._dedup,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._engine,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = orig
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_inc)  # noqa: SLF001
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001


@pytest.mark.usefixtures("_isolated_pipeline")
class TestMaxpfxMuteGate:
    """Toggling MAXPFX OFF mutes notify + incident card + live broadcast."""

    def setup_method(self) -> None:
        self._orig = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001

    def teardown_method(self) -> None:
        routes_mod._maxpfx_alerts_enabled = self._orig  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_muted_maxpfx_suppresses_everything_live(
        self, sample_maxpfx_log: str
    ) -> None:
        routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
            patch.object(
                main_mod._ws_manager,  # noqa: SLF001
                "broadcast_filtered",
                new_callable=AsyncMock,
            ) as mock_bcast,
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001

        mock_discord.assert_not_called()
        mock_bcast.assert_not_called()
        assert len(routes_mod._incidents_store) == 0  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_enabled_maxpfx_still_notifies(self, sample_maxpfx_log: str) -> None:
        routes_mod._maxpfx_alerts_enabled = True  # noqa: SLF001
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
            patch.object(
                main_mod._ws_manager,  # noqa: SLF001
                "broadcast_filtered",
                new_callable=AsyncMock,
            ),
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001

        mock_discord.assert_called_once()
        assert len(routes_mod._incidents_store) == 1  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_mute_does_not_affect_other_critical(
        self, sample_maxpfx_log: str, sample_bgp_down_log: str
    ) -> None:
        """A non-MAXPFX CRITICAL must still notify while MAXPFX is muted."""
        routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch(
                "src.main.send_discord_alert", new_callable=AsyncMock
            ) as mock_discord,
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001
            await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

        mock_discord.assert_called_once()


# ---------------------------------------------------------------------------
# Task 3 -- "Still in DB when muted" guarantee
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_muted_maxpfx_is_still_written_to_db(sample_maxpfx_log: str) -> None:
    """Muted MAXPFX must NOT be dropped from the DB (audit/history intact)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    orig_flag = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001
    orig_engine = main_mod._engine  # noqa: SLF001
    orig_dedup = main_mod._dedup  # noqa: SLF001
    orig_corr = main_mod._correlator  # noqa: SLF001
    orig_esc = main_mod._escalation  # noqa: SLF001
    try:
        routes_mod._maxpfx_alerts_enabled = False  # noqa: SLF001
        main_mod._engine = engine  # noqa: SLF001
        main_mod._dedup = None  # noqa: SLF001
        main_mod._correlator = None  # noqa: SLF001
        main_mod._escalation = None  # noqa: SLF001
        with (
            patch("src.main.get_settings", return_value=_settings()),
            patch("src.main.send_discord_alert", new_callable=AsyncMock),
            patch("src.main.send_telegram_alert", new_callable=AsyncMock),
            patch.object(
                main_mod._ws_manager,  # noqa: SLF001
                "broadcast_filtered",
                new_callable=AsyncMock,
            ),
        ):
            await main_mod._on_syslog_line(sample_maxpfx_log)  # noqa: SLF001

        async with AsyncSession(engine) as session:
            count = await session.scalar(select(func.count()).select_from(AlertLog))
        assert count == 1
    finally:
        routes_mod._maxpfx_alerts_enabled = orig_flag  # noqa: SLF001
        main_mod._engine = orig_engine  # noqa: SLF001
        main_mod._dedup = orig_dedup  # noqa: SLF001
        main_mod._correlator = orig_corr  # noqa: SLF001
        main_mod._escalation = orig_esc  # noqa: SLF001
        await engine.dispose()


# ---------------------------------------------------------------------------
# Task 4 -- API endpoint tests + startup restore
# ---------------------------------------------------------------------------


@pytest.fixture
def maxpfx_client() -> AsyncClient:
    """httpx AsyncClient bound to the FastAPI app (no real server)."""
    from src.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestMaxpfxAlertsEndpoint:
    """GET/POST /api/settings/maxpfx-alerts round-trip + prune-on-OFF."""

    def setup_method(self) -> None:
        self._orig_flag = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001
        self._orig_inc = list(routes_mod._incidents_store)  # noqa: SLF001
        self._orig_engine = routes_mod._db_engine  # noqa: SLF001
        routes_mod._db_engine = None  # noqa: SLF001
        routes_mod._incidents_store.clear()  # noqa: SLF001

    def teardown_method(self) -> None:
        routes_mod._maxpfx_alerts_enabled = self._orig_flag  # noqa: SLF001
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(self._orig_inc)  # noqa: SLF001
        routes_mod._db_engine = self._orig_engine  # noqa: SLF001

    @pytest.mark.asyncio
    async def test_get_reflects_state(self, maxpfx_client: AsyncClient) -> None:
        async with maxpfx_client as c:
            resp = await c.get("/api/settings/maxpfx-alerts")
        assert resp.status_code == 200
        assert "maxpfx_alerts_enabled" in resp.json()

    @pytest.mark.asyncio
    async def test_post_toggles_flag(self, maxpfx_client: AsyncClient) -> None:
        async with maxpfx_client as c:
            off = await c.post("/api/settings/maxpfx-alerts", params={"enabled": False})
            assert off.status_code == 200
            assert off.json()["maxpfx_alerts_enabled"] is False
            assert routes_mod._maxpfx_alerts_enabled is False  # noqa: SLF001

            on = await c.post("/api/settings/maxpfx-alerts", params={"enabled": True})
            assert on.json()["maxpfx_alerts_enabled"] is True

    @pytest.mark.asyncio
    async def test_post_off_prunes_existing_maxpfx_incident(
        self, maxpfx_client: AsyncClient
    ) -> None:
        routes_mod._incidents_store.append(  # noqa: SLF001
            {
                "id": "ALERT-1",
                "device": "KKT-Core-2",
                "mnemonic": "MAXPFX",
                "message": "reached 782, max 1000",
                "status": "active",
            }
        )
        async with maxpfx_client as c:
            resp = await c.post(
                "/api/settings/maxpfx-alerts", params={"enabled": False}
            )
        assert resp.status_code == 200
        remaining = [i["id"] for i in routes_mod._incidents_store]  # noqa: SLF001
        assert "ALERT-1" not in remaining


@pytest.mark.asyncio
async def test_startup_restores_persisted_flag() -> None:
    """load_persisted_state seeds the flag from the app_setting table."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSession(engine) as session:
        await _set_app_setting(session, "maxpfx_alerts_enabled", "false")
        await session.commit()

    orig = routes_mod._maxpfx_alerts_enabled  # noqa: SLF001
    try:
        routes_mod._maxpfx_alerts_enabled = True  # noqa: SLF001
        await routes_mod.load_persisted_state(engine)
        assert routes_mod._maxpfx_alerts_enabled is False  # noqa: SLF001
    finally:
        routes_mod._maxpfx_alerts_enabled = orig  # noqa: SLF001
        await engine.dispose()
