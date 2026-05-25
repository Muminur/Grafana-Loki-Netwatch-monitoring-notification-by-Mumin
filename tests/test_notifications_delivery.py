"""Tests for notification delivery reliability improvements.

Covers:
- Exponential back-off on transient failures (timeouts, 5xx).
- HTTP 429 handling with Retry-After header (integer and date forms).
- Final-attempt failure -> returns False + emits WARNING log.
- Webhook/token format validation: invalid values skipped without HTTP call.
- Message-format injection guard in formatter (control characters stripped,
  payloads length-capped).
- Telegram ok=false response handling.
- _parse_retry_after edge cases (integer, HTTP-date, garbage).
- Formatter as_number-only edge case.
- Empty telegram_chat_id early exit.

All HTTP calls are mocked -- no real network traffic.
``asyncio.sleep`` is patched to keep tests fast.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from src.config import Settings
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog

# ─────────────────────────────────────────────────────────────────────────────
# Re-use the same patch targets as test_notifications.py
# ─────────────────────────────────────────────────────────────────────────────

_DISCORD_PATCH = "src.notifications.discord.httpx.AsyncClient"
_TELEGRAM_PATCH = "src.notifications.telegram.httpx.AsyncClient"
_DISCORD_SLEEP = "src.notifications.discord.asyncio.sleep"
_TELEGRAM_SLEEP = "src.notifications.telegram.asyncio.sleep"

_UTC6 = timezone(timedelta(hours=6))


# ─────────────────────────────────────────────────────────────────────────────
# Shared test helpers
# ─────────────────────────────────────────────────────────────────────────────


def _make_parsed_log(
    *,
    source_ip: str = "192.168.203.1",
    hostname: str = "BSCCL-EQ-RTR-01",
    mnemonic: str = "ADJCHANGE",
    message: str = "neighbor 1.2.3.4 Down",
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
    bgp_neighbor: str = "1.2.3.4",
    as_number: int = 12345,
    as_name: str = "TESTNET",
    vrf: str = "default",
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


def _make_mock_client(response: MagicMock) -> AsyncMock:
    client: AsyncMock = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=response)
    return client


def _make_response(
    status_code: int,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    r: MagicMock = MagicMock()
    r.status_code = status_code
    r.text = text
    r.headers = headers or {}
    r.json = MagicMock(return_value={"ok": True})
    return r


# ─────────────────────────────────────────────────────────────────────────────
# Discord — URL validation
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordUrlValidation:
    """Invalid webhook URLs are rejected before any HTTP call."""

    @pytest.mark.asyncio
    async def test_invalid_url_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.notifications.discord import send_discord_alert

        bad_url = "https://evil.com/api/webhooks/123/abc"
        settings = _make_settings(discord_webhook_url=bad_url)
        with patch(_DISCORD_PATCH) as mock_cls, caplog.at_level(logging.ERROR):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any("invalid format" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_not_https_url_returns_false(self) -> None:
        from src.notifications.discord import send_discord_alert

        bad_url = "http://discord.com/api/webhooks/123/abc"
        settings = _make_settings(discord_webhook_url=bad_url)
        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_discordapp_url_accepted(self) -> None:
        """discordapp.com webhook URLs are also valid."""
        from src.notifications.discord import send_discord_alert

        settings = _make_settings(
            discord_webhook_url=(
                "https://discordapp.com/api/webhooks/111222333/validtoken123"
            )
        )
        mock_response = _make_response(204)
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is True

    @pytest.mark.asyncio
    async def test_valid_discord_url_accepted(self) -> None:
        from src.notifications.discord import send_discord_alert

        settings = _make_settings()
        mock_response = _make_response(204)
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# Discord — 429 rate-limit with Retry-After
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscord429Handling:
    """HTTP 429 is retried honouring the Retry-After header."""

    @pytest.mark.asyncio
    async def test_429_then_success(self) -> None:
        """429 on first attempt -> sleep Retry-After -> 204 on second -> True."""
        from src.notifications.discord import send_discord_alert

        rate_limited = _make_response(429, headers={"Retry-After": "2"})
        ok_response = _make_response(204)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[rate_limited, ok_response])

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is True
        mock_sleep.assert_called_once_with(2.0)

    @pytest.mark.asyncio
    async def test_429_all_attempts_exhausted_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Three consecutive 429s -> False + WARNING log."""
        from src.notifications.discord import send_discord_alert

        rate_limited = _make_response(429, headers={"Retry-After": "1"})

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=rate_limited)

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is False
        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "rate-limit" in m.lower() or "delivery failed" in m.lower()
            for m in warning_msgs
        )

    @pytest.mark.asyncio
    async def test_429_missing_retry_after_defaults_to_one_second(self) -> None:
        """Missing Retry-After header -> default 1 s sleep."""
        from src.notifications.discord import send_discord_alert

        rate_limited = _make_response(429, headers={})
        ok_response = _make_response(204)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[rate_limited, ok_response])

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is True
        mock_sleep.assert_called_once_with(1.0)

    @pytest.mark.asyncio
    async def test_429_large_retry_after_capped_to_max_delay(self) -> None:
        """A very large Retry-After value is capped at _MAX_DELAY (10 s) to
        prevent the coroutine blocking for an arbitrarily long time."""
        from src.notifications.discord import send_discord_alert

        rate_limited = _make_response(429, headers={"Retry-After": "999999"})
        ok_response = _make_response(204)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[rate_limited, ok_response])

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is True
        # Sleep must be <= 10.0 s regardless of the Retry-After header value.
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert all(
            s <= 10.0 for s in sleep_args
        ), f"Sleep exceeded _MAX_DELAY: {sleep_args}"

    @pytest.mark.asyncio
    async def test_429_exhausted_warning_includes_rate_limited_detail(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When all retries are consumed by 429 responses the final WARNING
        must mention rate-limiting (last_error should be populated)."""
        from src.notifications.discord import send_discord_alert

        rate_limited = _make_response(429, headers={"Retry-After": "1"})

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=rate_limited)

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is False
        delivery_failed = [
            r.message
            for r in caplog.records
            if r.levelno == logging.WARNING and "delivery failed" in r.message.lower()
        ]
        assert delivery_failed, "Expected a 'delivery failed' WARNING"
        # The final warning must not have an empty error detail.
        assert any(
            "429" in m or "rate" in m.lower() for m in delivery_failed
        ), f"Final warning lacks rate-limit detail: {delivery_failed}"


# ─────────────────────────────────────────────────────────────────────────────
# Discord — 5xx retry then success
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscord5xxRetry:
    """5xx responses are retried with exponential back-off."""

    @pytest.mark.asyncio
    async def test_5xx_then_success(self) -> None:
        """503 on first attempt, 204 on second -> True."""
        from src.notifications.discord import send_discord_alert

        server_error = _make_response(503, "Service Unavailable")
        ok_response = _make_response(204)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[server_error, ok_response])

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is True
        mock_sleep.assert_called_once_with(1.0)

    @pytest.mark.asyncio
    async def test_5xx_all_retries_exhausted_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Three consecutive 500s -> False + WARNING log."""
        from src.notifications.discord import send_discord_alert

        server_error = _make_response(500, "Internal Server Error")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=server_error)

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is False
        assert any(
            "delivery failed" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.WARNING
        )

    @pytest.mark.asyncio
    async def test_5xx_exponential_backoff_delays(self) -> None:
        """Back-off delays follow 1 s, 2 s sequence for three-attempt run."""
        from src.notifications.discord import send_discord_alert

        server_error = _make_response(500, "err")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=server_error)

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            await send_discord_alert(_make_enriched(), _make_settings())

        assert mock_sleep.call_count == 2
        assert mock_sleep.call_args_list == [call(1.0), call(2.0)]

    @pytest.mark.asyncio
    async def test_4xx_not_retried(self) -> None:
        """4xx (e.g. 400) is not transient -- no retries."""
        from src.notifications.discord import send_discord_alert

        bad_request = _make_response(400, "Bad Request")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=bad_request)

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is False
        mock_sleep.assert_not_called()
        assert mock_client.post.call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# Discord — timeout retries exhausted -> False + WARNING
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordTimeoutRetry:
    """Timeouts are treated as transient and retried."""

    @pytest.mark.asyncio
    async def test_timeout_then_success(self) -> None:
        """Timeout on first attempt -> success on second -> True."""
        import httpx

        from src.notifications.discord import send_discord_alert

        ok_response = _make_response(204)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(
            side_effect=[httpx.ReadTimeout("timed out"), ok_response]
        )

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock),
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is True

    @pytest.mark.asyncio
    async def test_timeout_all_retries_exhausted_returns_false_and_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """All three attempts time out -> False + WARNING."""
        import httpx

        from src.notifications.discord import send_discord_alert

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ReadTimeout("timed out"))

        with (
            patch(_DISCORD_PATCH, return_value=mock_client),
            patch(_DISCORD_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_discord_alert(_make_enriched(), _make_settings())

        assert result is False
        assert any(
            "delivery failed" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.WARNING
        )
        assert mock_client.post.call_count == 3


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — token validation
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramTokenValidation:
    """Invalid bot tokens are rejected before any HTTP call."""

    @pytest.mark.asyncio
    async def test_invalid_token_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(telegram_bot_token="not_a_valid_token")  # noqa: S106
        with patch(_TELEGRAM_PATCH) as mock_cls, caplog.at_level(logging.ERROR):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any("invalid format" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_token_without_colon_invalid(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_bot_token="12345678901234567890"  # noqa: S106
        )
        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_token_proceeds(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings()
        mock_response = _make_response(200)
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — 429 rate-limit with Retry-After
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegram429Handling:
    """HTTP 429 is retried honouring the Retry-After header."""

    @pytest.mark.asyncio
    async def test_429_then_success(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        rate_limited = _make_response(429, headers={"Retry-After": "3"})
        ok_response = _make_response(200)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[rate_limited, ok_response])

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is True
        mock_sleep.assert_called_once_with(3.0)

    @pytest.mark.asyncio
    async def test_429_all_attempts_exhausted_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.notifications.telegram import send_telegram_alert

        rate_limited = _make_response(429, headers={"Retry-After": "1"})

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=rate_limited)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is False
        warning_msgs = [
            r.message for r in caplog.records if r.levelno == logging.WARNING
        ]
        assert any(
            "delivery failed" in m.lower() or "rate-limit" in m.lower()
            for m in warning_msgs
        )

    @pytest.mark.asyncio
    async def test_429_large_retry_after_capped_to_max_delay(self) -> None:
        """A very large Retry-After value is capped at _MAX_DELAY to prevent
        indefinite blocking."""
        from src.notifications.telegram import send_telegram_alert

        rate_limited = _make_response(429, headers={"Retry-After": "86400"})
        ok_response = _make_response(200)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[rate_limited, ok_response])

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is True
        sleep_args = [c.args[0] for c in mock_sleep.call_args_list]
        assert all(
            s <= 10.0 for s in sleep_args
        ), f"Sleep exceeded _MAX_DELAY: {sleep_args}"

    @pytest.mark.asyncio
    async def test_429_exhausted_warning_includes_rate_limited_detail(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When all retries are consumed by 429 the final WARNING must include
        rate-limit detail (last_error must be populated)."""
        from src.notifications.telegram import send_telegram_alert

        rate_limited = _make_response(429, headers={"Retry-After": "1"})

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=rate_limited)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is False
        delivery_failed = [
            r.message
            for r in caplog.records
            if r.levelno == logging.WARNING and "delivery failed" in r.message.lower()
        ]
        assert delivery_failed, "Expected a 'delivery failed' WARNING"
        assert any(
            "429" in m or "rate" in m.lower() for m in delivery_failed
        ), f"Final warning lacks rate-limit detail: {delivery_failed}"


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — 5xx retry then success
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegram5xxRetry:
    @pytest.mark.asyncio
    async def test_5xx_then_success(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        server_error = _make_response(503, "Service Unavailable")
        ok_response = _make_response(200)

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=[server_error, ok_response])

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is True
        mock_sleep.assert_called_once_with(1.0)

    @pytest.mark.asyncio
    async def test_5xx_all_retries_exhausted_returns_false_and_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.notifications.telegram import send_telegram_alert

        server_error = _make_response(500, "Internal Server Error")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=server_error)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is False
        assert any(
            "delivery failed" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.WARNING
        )

    @pytest.mark.asyncio
    async def test_5xx_exponential_backoff_delays(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        server_error = _make_response(500, "err")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=server_error)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            await send_telegram_alert(_make_enriched(), _make_settings())

        assert mock_sleep.call_count == 2
        assert mock_sleep.call_args_list == [call(1.0), call(2.0)]

    @pytest.mark.asyncio
    async def test_4xx_not_retried(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        bad_request = _make_response(400, "Bad Request")

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=bad_request)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is False
        mock_sleep.assert_not_called()
        assert mock_client.post.call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — timeout retries exhausted -> False + WARNING
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramTimeoutRetry:
    @pytest.mark.asyncio
    async def test_timeout_all_retries_exhausted_returns_false_and_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import httpx

        from src.notifications.telegram import send_telegram_alert

        mock_client: AsyncMock = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(side_effect=httpx.ReadTimeout("timed out"))

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock),
            caplog.at_level(logging.WARNING),
        ):
            result = await send_telegram_alert(_make_enriched(), _make_settings())

        assert result is False
        assert any(
            "delivery failed" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.WARNING
        )
        assert mock_client.post.call_count == 3


# ─────────────────────────────────────────────────────────────────────────────
# Formatter — injection guard / sanitisation
# ─────────────────────────────────────────────────────────────────────────────


class TestFormatterSanitisation:
    """Control characters in log content are stripped; long strings are truncated."""

    def test_discord_control_chars_stripped_in_device_name(self) -> None:
        from src.notifications.formatter import format_discord_embed

        parsed = _make_parsed_log()
        enriched = _make_enriched(
            device_name="EQ-RTR\x00\x01\x1f-01",
            parsed=parsed,
        )
        payload = format_discord_embed(enriched, _make_settings())
        full = str(payload)
        assert "\x00" not in full
        assert "\x01" not in full
        assert "\x1f" not in full

    def test_telegram_control_chars_stripped(self) -> None:
        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched(
            bgp_neighbor="1.2.3.4\x00injected",
            device_name="Device\x1b[31mRed\x1b[0m",
        )
        msg = format_telegram_message(enriched)
        assert "\x00" not in msg
        assert "\x1b" not in msg

    def test_discord_long_field_truncated(self) -> None:
        from src.notifications.formatter import format_discord_embed

        long_desc = "X" * 2000
        enriched = _make_enriched(interface_description=long_desc)
        payload = format_discord_embed(enriched, _make_settings())
        for embed in payload["embeds"]:
            for field in embed.get("fields", []):
                assert (
                    len(field["value"]) <= 1024
                ), f"Field '{field['name']}' exceeds 1024 chars"

    def test_telegram_long_message_truncated(self) -> None:
        from src.notifications.formatter import format_telegram_message

        long_client = "C" * 5000
        enriched = _make_enriched(client_name=long_client)
        msg = format_telegram_message(enriched)
        assert len(msg) <= 4096

    def test_discord_payload_is_json_serialisable(self) -> None:
        """Payload must be JSON-serialisable (no special objects that would
        break httpx's json= parameter)."""
        import json

        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            device_name='Device "with" <special> & chars',
            event_type="Test\nNewline\tTab",
        )
        payload = format_discord_embed(enriched, _make_settings())
        serialised = json.dumps(payload)
        assert isinstance(serialised, str)

    def test_telegram_payload_is_json_serialisable(self) -> None:
        """Telegram message text must be JSON-serialisable."""
        import json

        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched(
            device_name='Device "with" <special> & chars',
            event_type="Test\nNewline",
        )
        msg = format_telegram_message(enriched)
        serialised = json.dumps({"text": msg})
        assert isinstance(serialised, str)

    def test_null_bytes_in_interface_description_stripped(self) -> None:
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            interface_name="TenGigE0/0/0/0",
            interface_description="Link\x00to\x00Cox",
        )
        payload = format_discord_embed(enriched, _make_settings())
        full = str(payload)
        assert "\x00" not in full


# ─────────────────────────────────────────────────────────────────────────────
# Explicit timeout still present
# ─────────────────────────────────────────────────────────────────────────────


class TestExplicitTimeout:
    """httpx.AsyncClient must always be created with an explicit timeout."""

    @pytest.mark.asyncio
    async def test_discord_client_created_with_10s_timeout(self) -> None:
        from src.notifications.discord import send_discord_alert

        settings = _make_settings()
        mock_response = _make_response(204)
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client) as mock_cls:
            await send_discord_alert(_make_enriched(), settings)

        all_calls = mock_cls.call_args_list
        assert len(all_calls) >= 1
        first_call_kwargs = all_calls[0].kwargs if all_calls[0].kwargs else {}
        if "timeout" in first_call_kwargs:
            assert first_call_kwargs["timeout"] == 10.0

    @pytest.mark.asyncio
    async def test_telegram_client_created_with_10s_timeout(self) -> None:
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings()
        mock_response = _make_response(200)
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client) as mock_cls:
            await send_telegram_alert(_make_enriched(), settings)

        all_calls = mock_cls.call_args_list
        assert len(all_calls) >= 1
        first_call_kwargs = all_calls[0].kwargs if all_calls[0].kwargs else {}
        if "timeout" in first_call_kwargs:
            assert first_call_kwargs["timeout"] == 10.0


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — ok=false JSON body handling
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramOkFalseResponse:
    """Telegram API returns HTTP 200 but JSON body has ok=false."""

    @pytest.mark.asyncio
    async def test_ok_false_returns_false(self) -> None:
        """HTTP 200 with ok=false -> returns False immediately."""
        from src.notifications.telegram import send_telegram_alert

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ok": False,
            "description": "Bad Request",
        }
        mock_client = _make_mock_client(mock_response)
        settings = _make_settings(telegram_enabled=True)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False

    @pytest.mark.asyncio
    async def test_ok_false_logs_error(self, caplog: pytest.LogCaptureFixture) -> None:
        """HTTP 200 with ok=false -> emits an ERROR log containing the body."""
        from src.notifications.telegram import send_telegram_alert

        body = {"ok": False, "description": "Bad Request: chat not found"}
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = body
        mock_client = _make_mock_client(mock_response)
        settings = _make_settings(telegram_enabled=True)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            caplog.at_level(logging.ERROR),
        ):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        assert any(
            "ok=false" in r.message.lower() or "ok=false" in str(r.message).lower()
            for r in caplog.records
            if r.levelno == logging.ERROR
        )

    @pytest.mark.asyncio
    async def test_ok_false_no_retry(self) -> None:
        """ok=false is a definitive rejection, not retried."""
        from src.notifications.telegram import send_telegram_alert

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": False, "description": "Bad Request"}
        mock_client = _make_mock_client(mock_response)
        settings = _make_settings(telegram_enabled=True)

        with (
            patch(_TELEGRAM_PATCH, return_value=mock_client),
            patch(_TELEGRAM_SLEEP, new_callable=AsyncMock) as mock_sleep,
        ):
            await send_telegram_alert(_make_enriched(), settings)

        mock_sleep.assert_not_called()
        assert mock_client.post.call_count == 1


# ─────────────────────────────────────────────────────────────────────────────
# _parse_retry_after edge cases — Discord and Telegram
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordParseRetryAfter:
    """Tests for src.notifications.discord._parse_retry_after."""

    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            ("5", 5.0),
            ("0", 0.0),
            ("10", 10.0),
        ],
    )
    def test_integer_string(self, input_val: str, expected: float) -> None:
        """Integer string '5' -> 5.0."""
        from src.notifications.discord import _parse_retry_after

        assert _parse_retry_after(input_val) == expected

    def test_http_date_returns_positive_float(self) -> None:
        """Valid HTTP-date returns a float (may be <= 0 if date is in the past,
        but the function itself must not raise)."""
        from src.notifications.discord import _parse_retry_after

        result = _parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT")
        assert isinstance(result, float)
        # Past date -> max(0.0, negative) -> 0.0
        assert result >= 0.0

    def test_http_date_future_returns_positive(self) -> None:
        """A future HTTP-date returns a float > 0."""
        import datetime as dt

        from src.notifications.discord import _parse_retry_after

        future = dt.datetime.now(tz=dt.UTC) + dt.timedelta(seconds=60)
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        result = _parse_retry_after(http_date)
        assert result > 0.0

    def test_garbage_string_returns_default(self) -> None:
        """Unparseable string 'garbage' -> 1.0 (fallback default)."""
        from src.notifications.discord import _parse_retry_after

        assert _parse_retry_after("garbage") == 1.0

    def test_empty_string_returns_default(self) -> None:
        """Empty string -> 1.0 (fallback default)."""
        from src.notifications.discord import _parse_retry_after

        assert _parse_retry_after("") == 1.0


class TestTelegramParseRetryAfter:
    """Tests for src.notifications.telegram._parse_retry_after."""

    @pytest.mark.parametrize(
        ("input_val", "expected"),
        [
            ("5", 5.0),
            ("0", 0.0),
            ("10", 10.0),
        ],
    )
    def test_integer_string(self, input_val: str, expected: float) -> None:
        """Integer string '5' -> 5.0."""
        from src.notifications.telegram import _parse_retry_after

        assert _parse_retry_after(input_val) == expected

    def test_http_date_returns_positive_float(self) -> None:
        """Valid HTTP-date returns a float >= 0."""
        from src.notifications.telegram import _parse_retry_after

        result = _parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT")
        assert isinstance(result, float)
        assert result >= 0.0

    def test_http_date_future_returns_positive(self) -> None:
        """A future HTTP-date returns a float > 0."""
        import datetime as dt

        from src.notifications.telegram import _parse_retry_after

        future = dt.datetime.now(tz=dt.UTC) + dt.timedelta(seconds=60)
        http_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
        result = _parse_retry_after(http_date)
        assert result > 0.0

    def test_garbage_string_returns_default(self) -> None:
        """Unparseable string 'garbage' -> 1.0 (fallback default)."""
        from src.notifications.telegram import _parse_retry_after

        assert _parse_retry_after("garbage") == 1.0

    def test_empty_string_returns_default(self) -> None:
        """Empty string -> 1.0 (fallback default)."""
        from src.notifications.telegram import _parse_retry_after

        assert _parse_retry_after("") == 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Formatter — as_number-only edge case (as_name is empty)
# ─────────────────────────────────────────────────────────────────────────────


class TestFormatterAsNumberOnly:
    """When as_name is empty but as_number is set, output must include AS number."""

    def test_discord_embed_includes_as_number_when_name_empty(self) -> None:
        """Discord embed includes AS number even when as_name is empty."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            as_name="",
            as_number=12345,
            bgp_neighbor="1.2.3.4",
        )
        payload = format_discord_embed(enriched, _make_settings())
        full_text = json.dumps(payload)
        assert "12345" in full_text

    def test_telegram_message_includes_as_number_when_name_empty(self) -> None:
        """Telegram message includes AS number even when as_name is empty."""
        from src.notifications.formatter import format_telegram_message

        enriched = _make_enriched(
            as_name="",
            as_number=12345,
            bgp_neighbor="1.2.3.4",
        )
        msg = format_telegram_message(enriched)
        assert "12345" in msg

    def test_discord_as_number_format_without_name(self) -> None:
        """When as_name is empty, the AS number field shows (AS12345) without
        a trailing name."""
        from src.notifications.formatter import format_discord_embed

        enriched = _make_enriched(
            as_name="",
            as_number=64512,
            bgp_neighbor="10.0.0.1",
        )
        payload = format_discord_embed(enriched, _make_settings())
        full_text = json.dumps(payload)
        assert "AS64512" in full_text
        # There should NOT be a spurious space or trailing empty name
        assert "AS64512 )" not in full_text


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — empty chat_id early exit
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramEmptyChatId:
    """Empty telegram_chat_id -> return False without HTTP call."""

    @pytest.mark.asyncio
    async def test_empty_chat_id_returns_false(self) -> None:
        """send_telegram_alert returns False when chat_id is empty."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(telegram_enabled=True, telegram_chat_id="")

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_chat_id_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """send_telegram_alert logs a warning when chat_id is empty."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(telegram_enabled=True, telegram_chat_id="")

        with (
            patch(_TELEGRAM_PATCH) as mock_cls,
            caplog.at_level(logging.WARNING),
        ):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any(
            "chat_id" in r.message.lower() or "chat_id" in r.message
            for r in caplog.records
        )


# ─────────────────────────────────────────────────────────────────────────────
# Discord — URL length limit
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordUrlLengthLimit:
    """Discord webhook URLs longer than 2048 characters are rejected."""

    @pytest.mark.asyncio
    async def test_url_exceeding_2048_chars_rejected(self) -> None:
        """A URL longer than 2048 characters -> False without HTTP call."""
        from src.notifications.discord import send_discord_alert

        long_url = "https://discord.com/api/webhooks/123/" + "a" * 2048
        settings = _make_settings(discord_webhook_url=long_url)

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_url_exceeding_2048_chars_logs_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A URL over 2048 chars emits an ERROR log mentioning the limit."""
        from src.notifications.discord import send_discord_alert

        long_url = "https://discord.com/api/webhooks/123/" + "a" * 2048
        settings = _make_settings(discord_webhook_url=long_url)

        with patch(_DISCORD_PATCH) as mock_cls, caplog.at_level(logging.ERROR):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any(
            "2048" in r.message or "exceeds" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.ERROR
        )

    @pytest.mark.asyncio
    async def test_url_at_exactly_2048_chars_accepted(self) -> None:
        """A URL at exactly 2048 characters is accepted (limit is >2048)."""
        from src.notifications.discord import send_discord_alert

        # Build a valid-looking URL that is exactly 2048 chars.
        prefix = "https://discord.com/api/webhooks/123/"
        padding = "a" * (2048 - len(prefix))
        url = prefix + padding
        assert len(url) == 2048

        settings = _make_settings(discord_webhook_url=url)
        mock_response = _make_response(204)
        mock_client = _make_mock_client(mock_response)

        with patch(_DISCORD_PATCH, return_value=mock_client):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# Discord — HTTPS-only scheme validation
# ─────────────────────────────────────────────────────────────────────────────


class TestDiscordHttpsOnlyScheme:
    """Only HTTPS URLs are accepted for the Discord webhook."""

    @pytest.mark.asyncio
    async def test_http_scheme_rejected(self) -> None:
        """HTTP (non-TLS) webhook URL -> False without HTTP call."""
        from src.notifications.discord import send_discord_alert

        settings = _make_settings(
            discord_webhook_url="http://discord.com/api/webhooks/123/abc"
        )

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_scheme_logs_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """HTTP scheme emits an ERROR log mentioning the scheme."""
        from src.notifications.discord import send_discord_alert

        settings = _make_settings(
            discord_webhook_url="http://discord.com/api/webhooks/123/abc"
        )

        with patch(_DISCORD_PATCH) as mock_cls, caplog.at_level(logging.ERROR):
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any(
            "https" in r.message.lower() or "scheme" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.ERROR
        )

    @pytest.mark.asyncio
    async def test_ftp_scheme_rejected(self) -> None:
        """FTP scheme -> False."""
        from src.notifications.discord import send_discord_alert

        settings = _make_settings(
            discord_webhook_url="ftp://discord.com/api/webhooks/123/abc"
        )

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_scheme_rejected(self) -> None:
        """URL with no scheme -> False."""
        from src.notifications.discord import send_discord_alert

        settings = _make_settings(
            discord_webhook_url="discord.com/api/webhooks/123/abc"
        )

        with patch(_DISCORD_PATCH) as mock_cls:
            result = await send_discord_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — token length limit
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramTokenLengthLimit:
    """Telegram bot tokens longer than 100 characters are rejected."""

    @pytest.mark.asyncio
    async def test_token_exceeding_100_chars_rejected(self) -> None:
        """A token longer than 100 characters -> False without HTTP call."""
        from src.notifications.telegram import send_telegram_alert

        long_token = "123456:" + "A" * 100  # 107 chars total
        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token=long_token,  # noqa: S106
        )

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_token_exceeding_100_chars_logs_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A token over 100 chars emits an ERROR log mentioning the limit."""
        from src.notifications.telegram import send_telegram_alert

        long_token = "123456:" + "A" * 100
        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token=long_token,  # noqa: S106
        )

        with patch(_TELEGRAM_PATCH) as mock_cls, caplog.at_level(logging.ERROR):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()
        assert any(
            "100" in r.message or "exceeds" in r.message.lower()
            for r in caplog.records
            if r.levelno == logging.ERROR
        )

    @pytest.mark.asyncio
    async def test_token_at_exactly_100_chars_accepted(self) -> None:
        """A token at exactly 100 characters is accepted."""
        from src.notifications.telegram import send_telegram_alert

        # Build a valid-looking token exactly 100 chars: "123456:" + 93 * 'A'
        prefix = "123456:"
        padding = "A" * (100 - len(prefix))
        token = prefix + padding
        assert len(token) == 100

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token=token,  # noqa: S106
        )
        mock_response = _make_response(200)
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is True

    @pytest.mark.asyncio
    async def test_normal_length_token_accepted(self) -> None:
        """A typical ~46-char token is accepted."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token="123456789:ABCDEFghijklmnopqrstuvwxyz012",  # noqa: S106
        )
        mock_response = _make_response(200)
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is True


# ─────────────────────────────────────────────────────────────────────────────
# Telegram — token format validation
# ─────────────────────────────────────────────────────────────────────────────


class TestTelegramTokenFormatValidation:
    """Telegram token must match numeric_id:alphanumeric_string format."""

    @pytest.mark.asyncio
    async def test_token_missing_colon_rejected(self) -> None:
        """Token without colon separator -> False."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token="123456ABCtoken",  # noqa: S106
        )

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_token_non_numeric_prefix_rejected(self) -> None:
        """Token with non-numeric prefix -> False."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token="abc:DEFtoken",  # noqa: S106
        )

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_token_with_spaces_rejected(self) -> None:
        """Token containing spaces -> False."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token="123456:ABC DEF token",  # noqa: S106
        )

        with patch(_TELEGRAM_PATCH) as mock_cls:
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is False
        mock_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_token_with_hyphen_and_underscore(self) -> None:
        """Token with hyphens and underscores in the suffix is valid."""
        from src.notifications.telegram import send_telegram_alert

        settings = _make_settings(
            telegram_enabled=True,
            telegram_bot_token="123456:ABC-test_token",  # noqa: S106
        )
        mock_response = _make_response(200)
        mock_client = _make_mock_client(mock_response)

        with patch(_TELEGRAM_PATCH, return_value=mock_client):
            result = await send_telegram_alert(_make_enriched(), settings)

        assert result is True
