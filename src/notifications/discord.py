"""Discord webhook notification sender for BSCCL NetWatch.

Sends formatted Discord embed messages for alert events.  All HTTP calls
use an explicit 10-second timeout.  Failures are logged and return False
rather than propagating exceptions.

Reliability features
--------------------
* Retries transient failures (timeouts, 5xx) with exponential back-off.
  Maximum 3 attempts; delay sequence: 1 s, 2 s (capped at 10 s).
* Respects HTTP 429 rate-limit responses by honouring the ``Retry-After``
  header (integer seconds or HTTP-date string).
* Validates the webhook URL format before attempting any request; an invalid
  URL logs an error and returns ``False`` immediately.
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

from src.notifications.formatter import format_discord_embed

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

_log = logging.getLogger(__name__)

# Discord webhook URLs must match the well-known path structure.
# The snowflake ID segment is typically numeric but we accept alphanumeric
# to stay compatible with test/stub values.
_DISCORD_WEBHOOK_RE = re.compile(
    r"^https://discord(?:app)?\.com/api/webhooks/[\w-]+/[\w-]+$"
)

_MAX_ATTEMPTS = 3
_BASE_DELAY = 1.0  # seconds — first retry delay
_MAX_DELAY = 10.0  # seconds — cap for exponential back-off


def _is_valid_discord_url(url: str) -> bool:
    """Return True if *url* is a well-formed Discord webhook URL."""
    return bool(_DISCORD_WEBHOOK_RE.match(url))


def _parse_retry_after(header_value: str) -> float:
    """Parse a ``Retry-After`` header value into seconds (float).

    Handles both integer-seconds form (``"1"``) and HTTP-date form
    (``"Mon, 01 Jan 2026 00:00:00 GMT"``).  Returns 1.0 on parse failure.
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
        ``False`` for any failure — disabled flag, missing/invalid URL,
        HTTP error, or network error.  Never raises.
    """
    if not settings.discord_enabled:
        _log.debug("Discord notifications disabled — skipping.")
        return False

    if not settings.discord_webhook_url:
        _log.warning("discord_webhook_url is empty — cannot send Discord alert.")
        return False

    if not _is_valid_discord_url(settings.discord_webhook_url):
        _log.error(
            "discord_webhook_url has invalid format: %r — skipping.",
            settings.discord_webhook_url,
        )
        return False

    payload = format_discord_embed(enriched, settings)

    last_error: str = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    settings.discord_webhook_url,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            last_error = f"timeout: {exc}"
            _log.warning(
                "Discord request timed out (attempt %d/%d): %s",
                attempt,
                _MAX_ATTEMPTS,
                exc,
            )
        except httpx.RequestError as exc:
            last_error = f"request error: {exc}"
            _log.warning(
                "Discord HTTP request failed (attempt %d/%d): %s",
                attempt,
                _MAX_ATTEMPTS,
                exc,
            )
        else:
            if response.status_code in (200, 204):
                _log.debug(
                    "Discord alert sent for %s/%s (HTTP %d)",
                    enriched.device_name,
                    enriched.parsed.mnemonic,
                    response.status_code,
                )
                return True

            if response.status_code == 429:
                retry_after = min(
                    _parse_retry_after(response.headers.get("Retry-After", "1")),
                    _MAX_DELAY,
                )
                last_error = "HTTP 429 (rate-limited)"
                _log.warning(
                    "Discord rate-limited (attempt %d/%d); "
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
                    "Discord webhook returned HTTP %d (attempt %d/%d): %s",
                    response.status_code,
                    attempt,
                    _MAX_ATTEMPTS,
                    response.text[:200],
                )
            else:
                # 4xx (except 429) — not transient; do not retry.
                _log.error(
                    "Discord webhook returned HTTP %d: %s",
                    response.status_code,
                    response.text[:200],
                )
                return False

        # Exponential back-off before the next attempt.
        if attempt < _MAX_ATTEMPTS:
            delay = min(_BASE_DELAY * (2 ** (attempt - 1)), _MAX_DELAY)
            await asyncio.sleep(delay)

    _log.warning(
        "Discord alert delivery failed after %d attempts for %s/%s: %s",
        _MAX_ATTEMPTS,
        enriched.device_name,
        enriched.parsed.mnemonic,
        last_error,
    )
    return False
