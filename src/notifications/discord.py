"""Discord webhook notification sender for BSCCL NetWatch.

Sends formatted Discord embed messages for alert events.  All HTTP calls
use an explicit 10-second timeout.  Failures are logged and return False
rather than propagating exceptions.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx

from src.notifications.formatter import format_discord_embed

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)


async def send_discord_alert(enriched: EnrichedLog, settings: Settings) -> bool:
    """Send a Discord webhook embed for an enriched alert.

    Parameters
    ----------
    enriched:
        The fully enriched syslog event to notify about.
    settings:
        Application settings containing ``discord_webhook_url`` and
        ``discord_enabled``.

    Returns
    -------
    bool
        ``True`` if the webhook was delivered successfully (HTTP 2xx),
        ``False`` for any failure — disabled flag, missing URL, HTTP error,
        or network error.  Never raises.
    """
    if not settings.discord_enabled:
        _log.debug("Discord notifications disabled — skipping.")
        return False

    if not settings.discord_webhook_url:
        _log.warning("discord_webhook_url is empty — cannot send Discord alert.")
        return False

    payload = format_discord_embed(enriched, settings)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                settings.discord_webhook_url,
                json=payload,
            )
    except httpx.RequestError as exc:
        _log.error("Discord HTTP request failed: %s", exc)
        return False

    if response.status_code in (200, 204):
        _log.debug(
            "Discord alert sent for %s/%s (HTTP %d)",
            enriched.device_name,
            enriched.parsed.mnemonic,
            response.status_code,
        )
        return True

    _log.error(
        "Discord webhook returned HTTP %d: %s",
        response.status_code,
        response.text[:200],
    )
    return False
