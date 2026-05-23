"""Telegram Bot API notification sender for BSCCL NetWatch.

Sends Markdown-formatted messages via the Telegram Bot API.  All HTTP calls
use an explicit 10-second timeout.  Failures are logged and return False
rather than propagating exceptions.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from src.notifications.formatter import format_telegram_message

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)

_TELEGRAM_API_BASE = "https://api.telegram.org"


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
        ``False`` for any failure — disabled flag, missing token, HTTP error,
        or network error.  Never raises.
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

    text = format_telegram_message(enriched)
    url = f"{_TELEGRAM_API_BASE}/bot{settings.telegram_bot_token}/sendMessage"
    payload = {
        "chat_id": settings.telegram_chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
    except httpx.RequestError as exc:
        _log.error("Telegram HTTP request failed: %s", exc)
        return False

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

    _log.error(
        "Telegram API returned HTTP %d: %s",
        response.status_code,
        response.text[:200],
    )
    return False
