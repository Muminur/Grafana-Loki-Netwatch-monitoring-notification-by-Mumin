"""Telegram Bot API notification sender for BSCCL NetWatch.

Sends Markdown-formatted messages via the Telegram Bot API.  All HTTP calls
use an explicit 10-second timeout.  Failures are logged and return False
rather than propagating exceptions.

Reliability features
--------------------
* Retries transient failures (timeouts, 5xx) with exponential back-off.
  Maximum 3 attempts; delay sequence: 1 s, 2 s (capped at 10 s).
* Respects HTTP 429 rate-limit responses by honouring the ``Retry-After``
  header.
* Validates the bot-token format before attempting any request; an invalid
  token logs an error and returns ``False`` immediately.
* On final exhaustion of retries, logs a WARNING — alerts are never silently
  dropped.
"""

from __future__ import annotations

import asyncio
import logging
import re
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING

import httpx

from src.notifications.formatter import format_telegram_message

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)

_TELEGRAM_API_BASE = "https://api.telegram.org"

# Telegram bot tokens look like "123456789:ABCDEFghijklmnopqrstuvwxyz-_"
_TELEGRAM_TOKEN_RE = re.compile(r"^\d+:[\w-]+$")

_MAX_ATTEMPTS = 3
_BASE_DELAY = 1.0  # seconds
_MAX_DELAY = 10.0  # seconds


def _is_valid_telegram_token(token: str) -> bool:
    """Return True if *token* matches the Telegram bot-token pattern."""
    return bool(_TELEGRAM_TOKEN_RE.match(token))


def _parse_retry_after(header_value: str) -> float:
    """Parse a ``Retry-After`` header into seconds (float).

    Handles integer-seconds and HTTP-date forms.  Returns 1.0 on failure.
    """
    try:
        return max(0.0, float(header_value))
    except ValueError:
        pass
    try:
        import datetime

        retry_dt = parsedate_to_datetime(header_value)
        now = datetime.datetime.now(tz=datetime.UTC)
        return max(0.0, (retry_dt - now).total_seconds())
    except Exception:  # noqa: BLE001
        return 1.0


async def send_telegram_alert(enriched: EnrichedLog, settings: Settings) -> bool:
    """Send a Telegram message for an enriched alert.

    Parameters
    ----------
    enriched:
        The fully enriched syslog event to notify about.
    settings:
        Application settings containing ``telegram_bot_token``,
        ``telegram_chat_id``, and ``telegram_enabled``.

    Returns
    -------
    bool
        ``True`` if the message was delivered successfully (HTTP 200 + ok),
        ``False`` for any failure — disabled flag, missing/invalid token,
        HTTP error, or network error.  Never raises.
    """
    if not settings.telegram_enabled:
        _log.debug("Telegram notifications disabled — skipping.")
        return False

    if not settings.telegram_bot_token:
        _log.warning("telegram_bot_token is empty — cannot send Telegram alert.")
        return False

    if not settings.telegram_chat_id:
        _log.warning("telegram_chat_id is empty — cannot send Telegram alert.")
        return False

    if not _is_valid_telegram_token(settings.telegram_bot_token):
        _log.error(
            "telegram_bot_token has invalid format — skipping.",
        )
        return False

    text = format_telegram_message(enriched)
    url = f"{_TELEGRAM_API_BASE}/bot{settings.telegram_bot_token}/sendMessage"
    payload = {
        "chat_id": settings.telegram_chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    last_error: str = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, json=payload)
        except httpx.TimeoutException as exc:
            # Log the exception type only — httpx error strings embed the
            # request URL, which contains the bot token.
            last_error = f"timeout: {type(exc).__name__}"
            _log.warning(
                "Telegram request timed out (attempt %d/%d): %s",
                attempt,
                _MAX_ATTEMPTS,
                type(exc).__name__,
            )
        except httpx.RequestError as exc:
            last_error = f"request error: {type(exc).__name__}"
            _log.warning(
                "Telegram HTTP request failed (attempt %d/%d): %s",
                attempt,
                _MAX_ATTEMPTS,
                type(exc).__name__,
            )
        else:
            if response.status_code == 200:
                try:
                    body = response.json()
                    if body.get("ok"):
                        _log.debug(
                            "Telegram alert sent for %s/%s",
                            enriched.device_name,
                            enriched.parsed.mnemonic,
                        )
                        return True
                    _log.error("Telegram API returned ok=false: %s", body)
                    return False
                except Exception as exc:  # noqa: BLE001
                    _log.error("Failed to parse Telegram response JSON: %s", exc)
                    return False

            if response.status_code == 429:
                retry_after = min(
                    _parse_retry_after(response.headers.get("Retry-After", "1")),
                    _MAX_DELAY,
                )
                last_error = "HTTP 429 (rate-limited)"
                _log.warning(
                    "Telegram rate-limited (attempt %d/%d); "
                    "sleeping %.1f s (Retry-After: %s)",
                    attempt,
                    _MAX_ATTEMPTS,
                    retry_after,
                    response.headers.get("Retry-After", "—"),
                )
                if attempt < _MAX_ATTEMPTS:
                    await asyncio.sleep(retry_after)
                continue

            if response.status_code >= 500:
                last_error = f"HTTP {response.status_code}"
                _log.warning(
                    "Telegram API returned HTTP %d (attempt %d/%d): %s",
                    response.status_code,
                    attempt,
                    _MAX_ATTEMPTS,
                    response.text[:200],
                )
            else:
                # 4xx (except 429) — not transient; do not retry.
                _log.error(
                    "Telegram API returned HTTP %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

        # Exponential back-off before the next attempt.
        if attempt < _MAX_ATTEMPTS:
            delay = min(_BASE_DELAY * (2 ** (attempt - 1)), _MAX_DELAY)
            await asyncio.sleep(delay)

    _log.warning(
        "Telegram alert delivery failed after %d attempts for %s/%s: %s",
        _MAX_ATTEMPTS,
        enriched.device_name,
        enriched.parsed.mnemonic,
        last_error,
    )
    return False
