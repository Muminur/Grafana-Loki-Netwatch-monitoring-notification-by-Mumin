"""Tests for escalation notification dispatch.

Covers:
- Escalation sends Discord notification when discord_enabled=True.
- Escalation sends Telegram notification when telegram_enabled=True.
- Escalation marks alert as escalated so it is not re-sent.
- Escalation skips sending when discord_enabled=False.
- Escalation skips sending when telegram_enabled=False.
- EscalationEngine.mark_escalated() suppresses repeat escalations.
- Escalation formatter output structure (Discord embed, Telegram text).

All HTTP calls are mocked — no real network traffic.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.config import Settings
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog
from src.notifications.escalation import EscalationEngine

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UTC6 = timezone(timedelta(hours=6))

_DISCORD_PATCH = "src.notifications.discord.httpx.AsyncClient"
_TELEGRAM_PATCH = "src.notifications.telegram.httpx.AsyncClient"

# A real parseable CRITICAL syslog (BGP Down on EQ-RTR-01)
_BGP_DOWN_RAW = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Down - BGP Notification received, maximum number of prefixes "
    "reached (VRF: network) (AS: 399077)"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    timestamp: datetime | None = None,
) -> ParsedLog:
    ts = timestamp or datetime(2026, 5, 22, 21, 12, 21, tzinfo=_UTC6)
    raw_line = (
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
    device_name: str = "EQ-RTR-01",
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
    discord_webhook_url: str = (
        "https://discord.com/api/webhooks/123456789/testtoken-valid"
    ),
    telegram_enabled: bool = True,
    telegram_bot_token: str = "123456:ABC-testtoken",  # noqa: S107
    telegram_chat_id: str = "-100123456",
    monitor_host: str = "192.168.200.230",
    grafana_dashboard_uid: str = "8sWAY1LMz",
) -> Settings:
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


def _make_mock_discord_client(status_code: int = 204) -> AsyncMock:
    """Build an AsyncMock httpx client that returns a Discord-style response."""
    response = MagicMock()
    response.status_code = status_code
    response.text = ""
    response.headers = {}

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=response)
    return client


def _make_mock_telegram_client(ok: bool = True) -> AsyncMock:
    """Build an AsyncMock httpx client that returns a Telegram-style response."""
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"ok": ok}
    response.text = ""
    response.headers = {}

    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=response)
    return client


def _now_utc6() -> datetime:
    return datetime.now(_UTC6)


# ---------------------------------------------------------------------------
# EscalationEngine.mark_escalated() unit tests
# ---------------------------------------------------------------------------


class TestMarkEscalated:
    """Tests for EscalationEngine.mark_escalated()."""

    def test_mark_escalated_suppresses_pending_escalation(self) -> None:
        """mark_escalated() removes the alert from future get_pending_escalations()."""
        eng = EscalationEngine()
        enriched = _make_enriched()

        # Track with an old timestamp so it is already pending
        old_ts = _now_utc6() - timedelta(minutes=20)
        discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, discriminator)
        eng._tracked[key] = (enriched, old_ts)  # noqa: SLF001

        # Confirm it is pending before marking
        pending_before = eng.get_pending_escalations()
        assert len(pending_before) == 1

        # Mark as escalated
        result = eng.mark_escalated(enriched.device_name, enriched.parsed.mnemonic)
        assert result is True

        # Now it must not appear in pending escalations
        pending_after = eng.get_pending_escalations()
        assert pending_after == []

    def test_mark_escalated_returns_false_for_unknown_alert(self) -> None:
        """mark_escalated() returns False when no matching alert is tracked."""
        eng = EscalationEngine()
        result = eng.mark_escalated("UNKNOWN-DEVICE", "UNKNOWN-MNEMONIC")
        assert result is False

    def test_mark_escalated_does_not_affect_other_alerts(self) -> None:
        """mark_escalated() only suppresses the matching alert, not others."""
        eng = EscalationEngine()
        enriched1 = _make_enriched(device_name="DEV-A", bgp_neighbor="1.1.1.1")
        enriched2 = _make_enriched(device_name="DEV-B", bgp_neighbor="2.2.2.2")

        old_ts = _now_utc6() - timedelta(minutes=20)
        for e in (enriched1, enriched2):
            disc = e.bgp_neighbor or e.interface_name or ""
            key = (e.device_name, e.parsed.mnemonic, disc)
            eng._tracked[key] = (e, old_ts)  # noqa: SLF001

        eng.mark_escalated(enriched1.device_name, enriched1.parsed.mnemonic)

        pending = eng.get_pending_escalations()
        assert len(pending) == 1
        alert, _elapsed = pending[0]
        assert alert.device_name == "DEV-B"

    def test_mark_escalated_is_idempotent(self) -> None:
        """Calling mark_escalated() twice does not raise; alert stays suppressed."""
        eng = EscalationEngine()
        enriched = _make_enriched()

        old_ts = _now_utc6() - timedelta(minutes=20)
        disc = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, disc)
        eng._tracked[key] = (enriched, old_ts)  # noqa: SLF001

        eng.mark_escalated(enriched.device_name, enriched.parsed.mnemonic)
        eng.mark_escalated(enriched.device_name, enriched.parsed.mnemonic)

        assert eng.get_pending_escalations() == []


# ---------------------------------------------------------------------------
# EscalationEngine.get_pending_escalations() return-type tests
# ---------------------------------------------------------------------------


class TestGetPendingEscalationsReturnType:
    """get_pending_escalations() returns (EnrichedLog, int) tuples."""

    def test_returns_tuple_with_elapsed_minutes(self) -> None:
        """Each pending item is a (EnrichedLog, int) tuple with correct minutes."""
        eng = EscalationEngine()
        enriched = _make_enriched()

        # 25 minutes ago
        old_ts = _now_utc6() - timedelta(minutes=25)
        disc = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, disc)
        eng._tracked[key] = (enriched, old_ts)  # noqa: SLF001

        pending = eng.get_pending_escalations()
        assert len(pending) == 1
        alert, elapsed_minutes = pending[0]
        assert alert is enriched
        assert 24 <= elapsed_minutes <= 26  # allow ±1 minute tolerance

    def test_recent_alert_not_in_pending(self) -> None:
        """An alert tracked 5 minutes ago is not yet pending (below threshold)."""
        eng = EscalationEngine()
        enriched = _make_enriched()

        recent_ts = _now_utc6() - timedelta(minutes=5)
        disc = enriched.bgp_neighbor or enriched.interface_name or ""
        key = (enriched.device_name, enriched.parsed.mnemonic, disc)
        eng._tracked[key] = (enriched, recent_ts)  # noqa: SLF001

        pending = eng.get_pending_escalations()
        assert pending == []


# ---------------------------------------------------------------------------
# send_discord_escalation() tests
# ---------------------------------------------------------------------------


class TestDiscordEscalationSender:
    """Tests for send_discord_escalation()."""

    @pytest.mark.asyncio
    async def test_sends_discord_when_enabled(self) -> None:
        """send_discord_escalation returns True and makes HTTP call when enabled."""
        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)
        mock_client = _make_mock_discord_client(status_code=204)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_escalation(enriched, 20, settings)

        assert result is True
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_discord_when_disabled(self) -> None:
        """send_discord_escalation returns False without HTTP call when disabled."""
        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=False)

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_discord_with_empty_webhook_url(self) -> None:
        """send_discord_escalation returns False when discord_webhook_url is empty."""
        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True, discord_webhook_url="")

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_discord_with_invalid_webhook_url(self) -> None:
        """send_discord_escalation returns False for invalid webhook URL."""
        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(
            discord_enabled=True,
            discord_webhook_url="https://evil.com/api/webhooks/123/abc",
        )

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_escalation_payload_uses_pure_red_color(self) -> None:
        """Discord escalation embed uses 0xFF0000 (pure red), not regular 0xFF0040."""
        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        captured_payload: dict = {}

        async def capture_post(_url: str, **kwargs) -> MagicMock:  # type: ignore[no-untyped-def]
            nonlocal captured_payload
            captured_payload = kwargs.get("json", {})
            resp = MagicMock()
            resp.status_code = 204
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_DISCORD_PATCH, return_value=mock_client):
            await send_discord_escalation(enriched, 20, settings)

        embeds = captured_payload.get("embeds", [])
        assert len(embeds) >= 1
        assert embeds[0]["color"] == 0xFF0000

    @pytest.mark.asyncio
    async def test_escalation_payload_includes_elapsed_minutes(self) -> None:
        """Discord escalation embed mentions the elapsed minutes."""
        import json

        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        captured_payload: dict = {}

        async def capture_post(_url: str, **kwargs) -> MagicMock:  # type: ignore[no-untyped-def]
            nonlocal captured_payload
            captured_payload = kwargs.get("json", {})
            resp = MagicMock()
            resp.status_code = 204
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_DISCORD_PATCH, return_value=mock_client):
            await send_discord_escalation(enriched, 23, settings)

        full_text = json.dumps(captured_payload)
        assert "23" in full_text

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self) -> None:
        """Network errors (httpx.RequestError) -> returns False without raising."""
        import httpx

        from src.notifications.discord import send_discord_escalation

        enriched = _make_enriched()
        settings = _make_settings(discord_enabled=True)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_escalation(enriched, 20, settings)

        assert result is False


# ---------------------------------------------------------------------------
# send_telegram_escalation() tests
# ---------------------------------------------------------------------------


class TestTelegramEscalationSender:
    """Tests for send_telegram_escalation()."""

    @pytest.mark.asyncio
    async def test_sends_telegram_when_enabled(self) -> None:
        """send_telegram_escalation returns True and makes HTTP call when enabled."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)
        mock_client = _make_mock_telegram_client(ok=True)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_escalation(enriched, 20, settings)

        assert result is True
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_telegram_when_disabled(self) -> None:
        """send_telegram_escalation returns False without HTTP call when disabled."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=False)

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_telegram_with_empty_token(self) -> None:
        """send_telegram_escalation returns False when bot token is empty."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True, telegram_bot_token="")

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_telegram_with_empty_chat_id(self) -> None:
        """send_telegram_escalation returns False when chat_id is empty."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True, telegram_chat_id="")

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_escalation(enriched, 20, settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_escalation_message_contains_escalation_marker(self) -> None:
        """Telegram escalation message contains 'ESCALATION' marker text."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        captured_payload: dict = {}

        async def capture_post(_url: str, **kwargs) -> MagicMock:  # type: ignore[no-untyped-def]
            nonlocal captured_payload
            captured_payload = kwargs.get("json", {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"ok": True}
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            await send_telegram_escalation(enriched, 20, settings)

        text = captured_payload.get("text", "")
        assert "ESCALATION" in text

    @pytest.mark.asyncio
    async def test_escalation_message_contains_elapsed_minutes(self) -> None:
        """Telegram escalation message includes the elapsed minutes count."""
        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        captured_payload: dict = {}

        async def capture_post(_url: str, **kwargs) -> MagicMock:  # type: ignore[no-untyped-def]
            nonlocal captured_payload
            captured_payload = kwargs.get("json", {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"ok": True}
            return resp

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = capture_post

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            await send_telegram_escalation(enriched, 17, settings)

        text = captured_payload.get("text", "")
        assert "17" in text

    @pytest.mark.asyncio
    async def test_network_error_returns_false(self) -> None:
        """Network errors -> returns False without raising."""
        import httpx

        from src.notifications.telegram import send_telegram_escalation

        enriched = _make_enriched()
        settings = _make_settings(telegram_enabled=True)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_escalation(enriched, 20, settings)

        assert result is False


# ---------------------------------------------------------------------------
# Escalation formatter unit tests
# ---------------------------------------------------------------------------


class TestEscalationFormatters:
    """Unit tests for format_escalation_discord_embed and format_escalation_telegram_message."""  # noqa: E501

    def test_discord_escalation_embed_structure(self) -> None:
        """format_escalation_discord_embed returns a valid Discord payload dict."""
        from src.notifications.formatter import format_escalation_discord_embed

        enriched = _make_enriched()
        payload = format_escalation_discord_embed(enriched, 20)

        assert "embeds" in payload
        assert isinstance(payload["embeds"], list)
        assert len(payload["embeds"]) >= 1
        embed = payload["embeds"][0]
        assert "title" in embed
        assert "color" in embed
        assert embed["color"] == 0xFF0000  # pure red, not 0xFF0040
        assert "footer" in embed

    def test_discord_escalation_embed_contains_device_name(self) -> None:
        """Discord escalation embed includes the device name."""
        import json

        from src.notifications.formatter import format_escalation_discord_embed

        enriched = _make_enriched(device_name="EQ-RTR-01")
        payload = format_escalation_discord_embed(enriched, 20)
        full_text = json.dumps(payload)
        assert "EQ-RTR-01" in full_text

    def test_discord_escalation_embed_contains_elapsed_time(self) -> None:
        """Discord escalation embed mentions elapsed minutes."""
        import json

        from src.notifications.formatter import format_escalation_discord_embed

        enriched = _make_enriched()
        payload = format_escalation_discord_embed(enriched, 18)
        full_text = json.dumps(payload)
        assert "18" in full_text

    def test_discord_escalation_embed_contains_unacknowledged_marker(self) -> None:
        """Discord escalation embed mentions UNACKNOWLEDGED status."""
        import json

        from src.notifications.formatter import format_escalation_discord_embed

        enriched = _make_enriched()
        payload = format_escalation_discord_embed(enriched, 20)
        full_text = json.dumps(payload)
        assert "UNACKNOWLEDGED" in full_text or "Unacknowledged" in full_text

    def test_telegram_escalation_message_contains_escalation_prefix(self) -> None:
        """format_escalation_telegram_message starts with ESCALATION marker."""
        from src.notifications.formatter import format_escalation_telegram_message

        enriched = _make_enriched()
        msg = format_escalation_telegram_message(enriched, 20)
        assert "ESCALATION" in msg

    def test_telegram_escalation_message_contains_device_name(self) -> None:
        """Telegram escalation message includes the device name."""
        from src.notifications.formatter import format_escalation_telegram_message

        enriched = _make_enriched(device_name="COX-CORE-01")
        msg = format_escalation_telegram_message(enriched, 20)
        assert "COX-CORE-01" in msg

    def test_telegram_escalation_message_contains_elapsed_minutes(self) -> None:
        """Telegram escalation message contains the elapsed minute count."""
        from src.notifications.formatter import format_escalation_telegram_message

        enriched = _make_enriched()
        msg = format_escalation_telegram_message(enriched, 22)
        assert "22" in msg

    def test_telegram_escalation_message_uses_markdown_bold(self) -> None:
        """Telegram escalation message uses Markdown bold markers."""
        from src.notifications.formatter import format_escalation_telegram_message

        enriched = _make_enriched()
        msg = format_escalation_telegram_message(enriched, 20)
        assert "*" in msg

    def test_telegram_escalation_is_json_serialisable(self) -> None:
        """Telegram escalation message must be JSON-serialisable."""
        import json

        from src.notifications.formatter import format_escalation_telegram_message

        enriched = _make_enriched()
        msg = format_escalation_telegram_message(enriched, 20)
        serialised = json.dumps({"text": msg})
        assert isinstance(serialised, str)

    def test_discord_escalation_is_json_serialisable(self) -> None:
        """Discord escalation payload must be JSON-serialisable."""
        import json

        from src.notifications.formatter import format_escalation_discord_embed

        enriched = _make_enriched()
        payload = format_escalation_discord_embed(enriched, 20)
        serialised = json.dumps(payload)
        assert isinstance(serialised, str)
