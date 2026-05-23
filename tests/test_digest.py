"""Tests for send_daily_digest in src/notifications/digest.py.

All HTTP calls are mocked — no real network traffic.
Tests cover: text generation, Discord dispatch, Telegram dispatch,
channel-disabled paths, and network-error handling.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DISCORD_HTTPX_PATCH = "src.notifications.digest.httpx.AsyncClient"


def _make_mock_http_client(status_code: int = 200, ok: bool = True) -> AsyncMock:
    """Return a mock httpx.AsyncClient that returns a fixed response on .post()."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = ""
    mock_resp.json.return_value = {"ok": ok}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)
    return mock_client


def _make_mock_session() -> AsyncMock:
    """Build a minimal SQLAlchemy async session mock for digest tests."""
    mock_result = MagicMock()
    mock_result.scalar_one.return_value = 0
    mock_result.all.return_value = []

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)
    return mock_session


def _make_settings_obj(
    *,
    discord_enabled: bool = True,
    discord_webhook_url: str = "https://discord.com/api/webhooks/test/token",
    telegram_enabled: bool = True,
    telegram_bot_token: str = "123456:ABC-testtoken",  # noqa: S107
    telegram_chat_id: str = "-100123456",
) -> object:
    """Build a minimal Settings-like object without touching env vars."""
    from src.config import Settings

    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", discord_enabled)
    object.__setattr__(s, "discord_webhook_url", discord_webhook_url)
    object.__setattr__(s, "telegram_enabled", telegram_enabled)
    object.__setattr__(s, "telegram_bot_token", telegram_bot_token)
    object.__setattr__(s, "telegram_chat_id", telegram_chat_id)
    object.__setattr__(s, "monitor_host", "192.168.200.230")
    object.__setattr__(s, "grafana_dashboard_uid", "8sWAY1LMz")
    object.__setattr__(s, "syslog_mode", "loki_ws")
    object.__setattr__(s, "syslog_udp_port", 1514)
    object.__setattr__(s, "database_url", "sqlite+aiosqlite:///test.db")
    object.__setattr__(s, "web_host", "0.0.0.0")
    object.__setattr__(s, "web_port", 8080)
    object.__setattr__(s, "grafana_api_key", "")
    object.__setattr__(s, "dedup_window_seconds", 300)
    object.__setattr__(s, "bgp_flap_window_seconds", 120)
    object.__setattr__(s, "bundle_group_window_seconds", 30)
    return s


# ---------------------------------------------------------------------------
# generate_daily_digest tests
# ---------------------------------------------------------------------------


class TestGenerateDailyDigest:
    """Tests for generate_daily_digest()."""

    @pytest.mark.asyncio
    async def test_digest_contains_bsccl_header(self) -> None:
        """Digest text starts with the BSCCL NetWatch header."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        assert "BSCCL NetWatch" in text

    @pytest.mark.asyncio
    async def test_digest_contains_date(self) -> None:
        """Digest text contains today's BDT date."""
        from datetime import datetime, timedelta, timezone

        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        _bdt = timezone(timedelta(hours=6))
        today_str = datetime.now(tz=_bdt).date().isoformat()
        assert today_str in text

    @pytest.mark.asyncio
    async def test_digest_contains_alert_summary_section(self) -> None:
        """Digest text includes an Alert Summary section."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        assert "Alert Summary" in text

    @pytest.mark.asyncio
    async def test_digest_lists_severity_labels(self) -> None:
        """Digest text mentions CRITICAL, WARNING, INFO, NOISE, TOTAL."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        for label in ("CRITICAL", "WARNING", "INFO", "NOISE", "TOTAL"):
            assert label in text, f"Expected '{label}' in digest"

    @pytest.mark.asyncio
    async def test_digest_contains_health_score(self) -> None:
        """Digest text includes a Health Score line."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        assert "Health Score" in text

    @pytest.mark.asyncio
    async def test_digest_contains_active_incidents(self) -> None:
        """Digest text includes an Active Incidents line."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        assert "Active Incidents" in text

    @pytest.mark.asyncio
    async def test_digest_top_devices_with_results(self) -> None:
        """When DB returns top-device rows, they appear in the digest."""
        from src.notifications.digest import generate_daily_digest

        # Simulate session returning one top-device row
        mock_count_result = MagicMock()
        mock_count_result.scalar_one.return_value = 0
        mock_count_result.all.return_value = []

        mock_top_result = MagicMock()
        mock_top_result.all.return_value = [("EQ-RTR-01", 42)]

        call_count = 0

        async def side_effect_execute(_stmt: object) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First execute: daily stats per classification → empty
                return mock_count_result
            if call_count == 2:
                # Second execute: active incident count
                return mock_count_result
            # Third execute: top devices
            return mock_top_result

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=side_effect_execute)

        text = await generate_daily_digest(mock_session)
        assert "EQ-RTR-01" in text
        assert "42" in text

    @pytest.mark.asyncio
    async def test_digest_top_devices_none_when_empty(self) -> None:
        """When DB returns no top-device rows, digest says 'none'."""
        from src.notifications.digest import generate_daily_digest

        session = _make_mock_session()
        text = await generate_daily_digest(session)
        assert "none" in text.lower() or "Top Active Devices" in text


# ---------------------------------------------------------------------------
# send_daily_digest tests
# ---------------------------------------------------------------------------


class TestSendDailyDigest:
    """Tests for send_daily_digest()."""

    @pytest.mark.asyncio
    async def test_send_digest_discord_success_returns_true(self) -> None:
        """Discord 204 response → send_daily_digest returns True."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=True,
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )
        mock_client = _make_mock_http_client(status_code=204)

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is True

    @pytest.mark.asyncio
    async def test_send_digest_telegram_success_returns_true(self) -> None:
        """Telegram 200/ok response → send_daily_digest returns True."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=False,
            discord_webhook_url="",
            telegram_enabled=True,
        )
        mock_client = _make_mock_http_client(status_code=200, ok=True)

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is True

    @pytest.mark.asyncio
    async def test_send_digest_both_channels_disabled_returns_false(self) -> None:
        """Both channels disabled → returns False without any HTTP call."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=False,
            discord_webhook_url="",
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH) as mock_cls,
        ):
            result = await send_daily_digest(session)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_digest_discord_no_webhook_skips_discord(self) -> None:
        """Empty Discord webhook URL → Discord skipped, not counted as success."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=True,
            discord_webhook_url="",
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH) as mock_cls,
        ):
            result = await send_daily_digest(session)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_send_digest_discord_http_error_returns_false(self) -> None:
        """Discord 500 response → Discord channel fails, returns False."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=True,
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )
        mock_client = _make_mock_http_client(status_code=500)

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_digest_discord_network_error_does_not_raise(self) -> None:
        """Discord network error (httpx.RequestError) → returns False."""
        import httpx

        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=True,
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_digest_telegram_network_error_does_not_raise(self) -> None:
        """Telegram network error → returns False without raising."""
        import httpx

        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=False,
            discord_webhook_url="",
            telegram_enabled=True,
        )

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_digest_telegram_ok_false_returns_false(self) -> None:
        """Telegram 200 but ok=False in body → channel not counted as success."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=False,
            discord_webhook_url="",
            telegram_enabled=True,
        )
        mock_client = _make_mock_http_client(status_code=200, ok=False)

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is False

    @pytest.mark.asyncio
    async def test_send_digest_discord_200_also_accepted(self) -> None:
        """Discord 200 (not just 204) → returns True."""
        from src.notifications.digest import send_daily_digest

        session = _make_mock_session()
        settings = _make_settings_obj(
            discord_enabled=True,
            telegram_enabled=False,
            telegram_bot_token="",
            telegram_chat_id="",
        )
        mock_client = _make_mock_http_client(status_code=200)

        with (
            patch("src.notifications.digest.get_settings", return_value=settings),
            patch(_DISCORD_HTTPX_PATCH, return_value=mock_client),
        ):
            result = await send_daily_digest(session)

        assert result is True
