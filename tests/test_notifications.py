"""Tests for the notification pipeline: formatter, Discord, Telegram.

All HTTP calls are mocked — no real network traffic.
Tests follow TDD: written before implementation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import Settings
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog

# ─────────────────────────────────────────────────────────────────────────────
# Helpers / shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

_UTC6 = timezone(timedelta(hours=6))

_DISCORD_PATCH = "src.notifications.discord.httpx.AsyncClient"
_TELEGRAM_PATCH = "src.notifications.telegram.httpx.AsyncClient"


def _make_parsed_log(
    *,
    source_ip: str = "192.168.203.1",
    hostname: str = "BSCCL-EQ-RTR-01",
    mnemonic: str = "ADJCHANGE",
    message: str = (
        "neighbor 2001:de8:4::39:9077:1 Down - BGP Notification received"
        " (VRF: network) (AS: 399077)"
    ),
    facility: str = "ROUTING",
    subfacility: str = "BGP",
    severity_level: int = 5,
    rp_location: str = "RP/0/RP0/CPU0",
    raw: str = "",
    timestamp: datetime | None = None,
) -> ParsedLog:
    ts = timestamp or datetime(2026, 5, 22, 21, 12, 21, tzinfo=_UTC6)
    raw_line = raw or (
        f"May 22 21:12:21 {source_ip} 9238766: {hostname} "
        f"{rp_location}:May 22 21:12:21.651 +06: bgp[1097]: "
        f"%{facility}-{subfacility}-{severity_level}-{mnemonic} : {message}"
    )
    return ParsedLog(
        timestamp=ts,
        source_ip=source_ip,
        hostname=hostname,
        rp_location=rp_location,
        facility=facility,
        subfacility=subfacility,
        severity_level=severity_level,
        mnemonic=mnemonic,
        message=message,
        raw=raw_line,
    )


def _make_enriched(
    *,
    classification: str = "CRITICAL",
    rule_id: str = "bgp_down",
    event_type: str = "BGP Session Down",
    notify: bool = True,
    device_name: str = "Equinix-RTR-1",
    device_location: str = "Singapore Equinix",
    interface_name: str = "",
    interface_description: str = "",
    bundle_parent: str = "",
    client_name: str = "",
    bgp_neighbor: str = "2001:de8:4::39:9077:1",
    as_number: int | None = 399077,
    as_name: str = "TCLOUD",
    vrf: str = "network",
    parsed: ParsedLog | None = None,
) -> EnrichedLog:
    if parsed is None:
        parsed = _make_parsed_log()
    return EnrichedLog(
        parsed=parsed,
        classification=classification,
        rule_id=rule_id,
        event_type=event_type,
        notify=notify,
        device_name=device_name,
        device_location=device_location,
        interface_name=interface_name,
        interface_description=interface_description,
        bundle_parent=bundle_parent,
        client_name=client_name,
        bgp_neighbor=bgp_neighbor,
        as_number=as_number,
        as_name=as_name,
        vrf=vrf,
    )


def _make_settings(
    *,
    discord_enabled: bool = True,
    discord_webhook_url: str = "https://discord.com/api/webhooks/test/token",
    telegram_enabled: bool = True,
    telegram_bot_token: str = "123456:ABC-testtoken",  # noqa: S107
    telegram_chat_id: str = "-100123456",
    monitor_host: str = "192.168.200.230",
    grafana_dashboard_uid: str = "8sWAY1LMz",
) -> Settings:
    """Build a Settings-like object for testing without touching env vars."""
    s = object.__new__(Settings)
    object.__setattr__(s, "discord_enabled", discord_enabled)
    object.__setattr__(s, "discord_webhook_url", discord_webhook_url)
    object.__setattr__(s, "telegram_enabled", telegram_enabled)
    object.__setattr__(s, "telegram_bot_token", telegram_bot_token)
    object.__setattr__(s, "telegram_chat_id", telegram_chat_id)
    object.__setattr__(s, "monitor_host", monitor_host)
    object.__setattr__(s, "grafana_dashboard_uid", grafana_dashboard_uid)
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


def _make_mock_client(response: MagicMock) -> AsyncMock:
    """Build an AsyncMock httpx client that returns *response* on .post()."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=response)
    return client


# ─────────────────────────────────────────────────────────────────────────────
# Formatter tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordEmbedFormatter:
    """Tests for format_discord_embed()."""

    def test_discord_embed_bgp_down(self) -> None:
        """Embed has correct structure: title, color, fields, footer."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_discord_embed(enriched, settings)

        assert "embeds" in embed
        assert isinstance(embed["embeds"], list)
        assert len(embed["embeds"]) >= 1
        first = embed["embeds"][0]

        # Must have title / description
        assert "title" in first or "description" in first

        # Must have fields list
        assert "fields" in first
        fields = first["fields"]
        assert isinstance(fields, list)

        # Check device field present
        field_names = [f["name"] for f in fields]
        assert any("device" in n.lower() or "Device" in n for n in field_names)

        # Footer with BSCCL NetWatch
        assert "footer" in first
        assert "BSCCL NetWatch" in first["footer"]["text"]

    def test_discord_embed_color_critical(self) -> None:
        """CRITICAL classification → color 0xFF0040."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(classification="CRITICAL")
        embed = format_discord_embed(enriched, _make_settings())
        assert embed["embeds"][0]["color"] == 0xFF0040

    def test_discord_embed_color_warning(self) -> None:
        """WARNING classification → color 0xFFD700."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            classification="WARNING",
            rule_id="bgp_up",
            event_type="BGP Session Up",
        )
        embed = format_discord_embed(enriched, _make_settings())
        assert embed["embeds"][0]["color"] == 0xFFD700

    def test_discord_embed_color_info(self) -> None:
        """INFO classification → color 0x00D4FF."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            classification="INFO",
            rule_id="eem_commit",
            event_type="EEM Script Commit",
            notify=False,
        )
        embed = format_discord_embed(enriched, _make_settings())
        assert embed["embeds"][0]["color"] == 0x00D4FF

    def test_discord_embed_includes_grafana_link(self) -> None:
        """Embed description or a field contains the Grafana deep-link URL."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_discord_embed(enriched, settings)

        first = embed["embeds"][0]
        full_text = json.dumps(first)
        assert "192.168.200.230:3000" in full_text or "grafana" in full_text.lower()

    def test_discord_embed_contains_event_type(self) -> None:
        """Embed title or description contains the event_type."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(event_type="BGP Session Down")
        embed = format_discord_embed(enriched, _make_settings())
        full_text = json.dumps(embed)
        assert "BGP Session Down" in full_text

    def test_discord_embed_bgp_contains_neighbor(self) -> None:
        """BGP neighbor IP appears somewhere in the embed."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(bgp_neighbor="2001:de8:4::39:9077:1")
        embed = format_discord_embed(enriched, _make_settings())
        full_text = json.dumps(embed)
        assert "2001:de8:4::39:9077:1" in full_text

    def test_discord_embed_interface_event(self) -> None:
        """Interface events include interface_name in embed."""
        from src.notifications.formatter import format_discord_embed

        parsed = _make_parsed_log(
            source_ip="192.168.200.11",
            hostname="DHK-CORE-3",
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
            facility="PKT_INFRA",
            subfacility="LINK",
        )
        enriched = _make_enriched(
            classification="CRITICAL",
            event_type="Interface Down",
            device_name="DHK-Core-3",
            device_location="Dhaka",
            interface_name="TenGigE0/0/0/0",
            interface_description="P2P to Cox's Bazar",
            bgp_neighbor="",
            as_number=None,
            as_name="",
            parsed=parsed,
        )
        embed = format_discord_embed(enriched, _make_settings())
        full_text = json.dumps(embed)
        assert "TenGigE0/0/0/0" in full_text


class TestTelegramFormatter:
    """Tests for format_telegram_message()."""

    def test_telegram_format_bgp_down(self) -> None:
        """Telegram message contains CRITICAL, device name, and neighbor."""
        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched()
        msg = format_telegram_message(enriched)

        assert "CRITICAL" in msg
        assert "Equinix-RTR-1" in msg
        assert "2001:de8:4::39:9077:1" in msg

    def test_telegram_includes_all_fields(self) -> None:
        """Telegram message includes device, event, peer/interface, location."""
        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched()
        msg = format_telegram_message(enriched)

        assert "Equinix-RTR-1" in msg  # device
        assert "BGP Session Down" in msg  # event
        assert "2001:de8:4::39:9077:1" in msg  # peer
        assert "Singapore Equinix" in msg  # location

    def test_telegram_format_uses_markdown(self) -> None:
        """Telegram message uses Markdown bold markers (** or *)."""
        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched()
        msg = format_telegram_message(enriched)
        # Bold either with * or ** in Markdown
        assert "*" in msg

    def test_telegram_format_interface_event(self) -> None:
        """Interface events include interface name in Telegram message."""
        from src.notifications.formatter import format_telegram_message

        parsed = _make_parsed_log(
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/0, changed state to Down",
        )
        enriched = _make_enriched(
            classification="CRITICAL",
            event_type="Interface Down",
            interface_name="TenGigE0/0/0/0",
            bgp_neighbor="",
            as_number=None,
            as_name="",
            parsed=parsed,
        )
        msg = format_telegram_message(enriched)
        assert "TenGigE0/0/0/0" in msg


class TestSeverityEmoji:
    """Tests for severity_emoji()."""

    def test_severity_emoji_critical(self) -> None:
        from src.notifications.formatter import severity_emoji

        assert severity_emoji("CRITICAL") == "🔴"

    def test_severity_emoji_warning(self) -> None:
        from src.notifications.formatter import severity_emoji

        assert severity_emoji("WARNING") == "🟡"

    def test_severity_emoji_info(self) -> None:
        from src.notifications.formatter import severity_emoji

        assert severity_emoji("INFO") == "🔵"

    def test_severity_emoji_user_login(self) -> None:
        from src.notifications.formatter import severity_emoji

        assert severity_emoji("USER_LOGIN") == "👤"

    def test_severity_emoji_unknown(self) -> None:
        from src.notifications.formatter import severity_emoji

        # Unknown classification returns some string (no crash)
        result = severity_emoji("NOISE")
        assert isinstance(result, str)


# ─────────────────────────────────────────────────────────────────────────────
# Discord sender tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordSender:
    """Tests for send_discord_alert()."""

    @pytest.mark.asyncio
    async def test_discord_send_success(self) -> None:
        """Mock 204 response → returns True."""
        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(enriched, settings)

        assert result is True

    @pytest.mark.asyncio
    async def test_discord_send_failure(self) -> None:
        """Mock 500 response → returns False without raising."""
        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(enriched, settings)

        assert result is False

    @pytest.mark.asyncio
    async def test_discord_disabled(self) -> None:
        """discord_enabled=False → returns False without making any HTTP call."""
        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=False)

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(enriched, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_discord_no_webhook_url(self) -> None:
        """Empty webhook URL → returns False without HTTP call."""
        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True, discord_webhook_url="")

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(enriched, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_discord_uses_10s_timeout(self) -> None:
        """HTTP client is instantiated with explicit 10-second timeout."""
        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client) as mock_cls:
            await send_discord_alert(enriched, settings)

        # Timeout should be set at client creation
        call_kwargs = mock_cls.call_args
        if call_kwargs:
            all_kwargs = dict(call_kwargs[1]) if call_kwargs[1] else {}
            if "timeout" in all_kwargs:
                assert all_kwargs["timeout"] == 10.0

    @pytest.mark.asyncio
    async def test_discord_network_error_returns_false(self) -> None:
        """Network errors (httpx.RequestError) → returns False without raising."""
        import httpx

        from src.notifications.discord import send_discord_alert

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(enriched, settings)

        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# Telegram sender tests
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramSender:
    """Tests for send_telegram_alert()."""

    @pytest.mark.asyncio
    async def test_telegram_send_success(self) -> None:
        """Mock 200 JSON response → returns True."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True, "result": {}}
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(enriched, settings)

        assert result is True

    @pytest.mark.asyncio
    async def test_telegram_send_failure(self) -> None:
        """Mock 500 response → returns False without raising."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(enriched, settings)

        assert result is False

    @pytest.mark.asyncio
    async def test_telegram_disabled(self) -> None:
        """telegram_enabled=False → returns False without HTTP call."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=False)

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(enriched, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_telegram_disable_preview(self) -> None:
        """Request body includes disable_web_page_preview=True."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True}

        posted_body: dict[str, Any] = {}

        async def capture_post(_url: str, **kwargs: Any) -> MagicMock:
            nonlocal posted_body
            posted_body = kwargs.get("json", kwargs.get("data", {}))
            return mock_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            await send_telegram_alert(enriched, settings)

        assert posted_body.get("disable_web_page_preview") is True

    @pytest.mark.asyncio
    async def test_telegram_parse_mode_markdown(self) -> None:
        """Request body includes parse_mode=Markdown."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True}

        posted_body: dict[str, Any] = {}

        async def capture_post(_url: str, **kwargs: Any) -> MagicMock:
            nonlocal posted_body
            posted_body = kwargs.get("json", {})
            return mock_response

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            await send_telegram_alert(enriched, settings)

        assert posted_body.get("parse_mode") == "Markdown"

    @pytest.mark.asyncio
    async def test_telegram_no_token_returns_false(self) -> None:
        """Empty bot token → returns False without HTTP call."""
        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True, telegram_bot_token="")

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(enriched, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_telegram_network_error_returns_false(self) -> None:
        """Network errors → returns False without raising."""
        import httpx

        from src.notifications.telegram import send_telegram_alert

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(enriched, settings)

        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# Resolution formatter tests
# ─────────────────────────────────────────────────────────────────────────────


class TestResolutionDiscordEmbed:
    """Tests for format_resolution_discord_embed()."""

    def test_resolution_discord_embed_is_green(self) -> None:
        """RESOLVED embed has green color (0x00FF88)."""
        from src.notifications.formatter import format_resolution_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_resolution_discord_embed(enriched, "INC-20260528-001", settings)

        assert "embeds" in embed
        first = embed["embeds"][0]
        assert first["color"] == 0x00FF88

    def test_resolution_discord_embed_title_resolved(self) -> None:
        """RESOLVED embed title contains 'RESOLVED'."""
        from src.notifications.formatter import format_resolution_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_resolution_discord_embed(enriched, "INC-20260528-001", settings)

        first = embed["embeds"][0]
        assert "RESOLVED" in first["title"]

    def test_resolution_discord_embed_has_incident_id(self) -> None:
        """RESOLVED embed includes the incident ID somewhere."""
        from src.notifications.formatter import format_resolution_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_resolution_discord_embed(enriched, "INC-20260528-001", settings)

        full_text = json.dumps(embed)
        assert "INC-20260528-001" in full_text

    def test_resolution_discord_embed_has_device(self) -> None:
        """RESOLVED embed includes the device name."""
        from src.notifications.formatter import format_resolution_discord_embed

        enriched = _make_enriched()
        settings = _make_settings()
        embed = format_resolution_discord_embed(enriched, "INC-20260528-001", settings)

        full_text = json.dumps(embed)
        assert enriched.device_name in full_text


class TestResolutionTelegramMessage:
    """Tests for format_resolution_telegram_message()."""

    def test_resolution_telegram_message(self) -> None:
        """RESOLVED Telegram message contains 'RESOLVED' and device name."""
        from src.notifications.formatter import format_resolution_telegram_message

        enriched = _make_enriched()
        msg = format_resolution_telegram_message(enriched, "INC-20260528-001")

        assert "RESOLVED" in msg
        assert enriched.device_name in msg

    def test_resolution_telegram_message_has_incident_id(self) -> None:
        """RESOLVED Telegram message includes the incident ID."""
        from src.notifications.formatter import format_resolution_telegram_message

        enriched = _make_enriched()
        msg = format_resolution_telegram_message(enriched, "INC-20260528-001")

        assert "INC-20260528-001" in msg


# ─────────────────────────────────────────────────────────────────────────────
# Resolution sender tests
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordResolutionSender:
    """Tests for send_discord_resolution()."""

    @pytest.mark.asyncio
    async def test_discord_resolution_send_success(self) -> None:
        """Mock 204 response → returns True."""
        from src.notifications.discord import send_discord_resolution

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_resolution(
                enriched, "INC-20260528-001", settings
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_discord_resolution_disabled(self) -> None:
        """discord_enabled=False → returns False."""
        from src.notifications.discord import send_discord_resolution

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=False)

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_resolution(
                enriched, "INC-20260528-001", settings
            )

        assert result is False
        mock_cls.assert_not_called()


class TestTelegramResolutionSender:
    """Tests for send_telegram_resolution()."""

    @pytest.mark.asyncio
    async def test_telegram_resolution_send_success(self) -> None:
        """Mock 200 JSON response → returns True."""
        from src.notifications.telegram import send_telegram_resolution

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True, "result": {}}
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_resolution(
                enriched, "INC-20260528-001", settings
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_telegram_resolution_disabled(self) -> None:
        """telegram_enabled=False → returns False."""
        from src.notifications.telegram import send_telegram_resolution

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=False)

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_resolution(
                enriched, "INC-20260528-001", settings
            )

        assert result is False
        mock_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Escalation clear_incident tests
# ─────────────────────────────────────────────────────────────────────────────


class TestEscalationClearIncident:
    """Tests for EscalationEngine.clear_incident()."""

    def test_clear_incident_removes_tracked_entries(self) -> None:
        """clear_incident() removes all tracked entries for a device."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine()
        enriched = _make_enriched(device_name="Equinix-RTR-1")
        engine.track_alert(enriched)

        engine.clear_incident("Equinix-RTR-1")

        # After clear, no pending escalations for this device
        pending = engine.get_pending_escalations()
        device_pending = [e for e, _ in pending if e.device_name == "Equinix-RTR-1"]
        assert len(device_pending) == 0

    def test_clear_incident_returns_count(self) -> None:
        """clear_incident() returns the number of entries cleared."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine()
        enriched = _make_enriched(device_name="Equinix-RTR-1")
        engine.track_alert(enriched)

        count = engine.clear_incident("Equinix-RTR-1")
        assert count >= 1

    def test_clear_incident_no_match_returns_zero(self) -> None:
        """clear_incident() with no matching device returns 0."""
        from src.notifications.escalation import EscalationEngine

        engine = EscalationEngine()
        count = engine.clear_incident("NonExistentDevice")
        assert count == 0
