"""Daily digest generator for BSCCL NetWatch.

Produces a summary message (for Discord and Telegram) covering:
- Total alert counts by severity for the current day
- Top 5 most active devices
- Active incident count
- Network health score

Scheduled to run at 08:00 BDT (02:00 UTC) via the background task scheduler.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

import httpx
from sqlalchemy import func, select

from src.config import get_settings
from src.database.models import AlertLog, BGPPeerHistory, Incident
from src.statistics.engine import get_daily_stats
from src.statistics.health_score import calculate_health_score

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_log = logging.getLogger(__name__)


async def generate_daily_digest(session: AsyncSession) -> str:
    """Generate a daily summary message for Discord/Telegram.

    Includes:
    - Alert counts by severity (CRITICAL / WARNING / INFO / NOISE)
    - Top 5 most active devices
    - Active incident count
    - Network health score

    Parameters
    ----------
    session:
        An active async session (read-only queries).

    Returns
    -------
    str
        A plain-text / Markdown-compatible summary string.
    """
    _bdt = timezone(timedelta(hours=6))
    today = datetime.now(tz=_bdt).date()
    daily = await get_daily_stats(session, today)

    critical: int = daily["critical"]  # type: ignore[assignment]
    warning: int = daily["warning"]  # type: ignore[assignment]
    info: int = daily["info"]  # type: ignore[assignment]
    noise: int = daily["noise"]  # type: ignore[assignment]
    total: int = daily["total"]  # type: ignore[assignment]

    # Active incidents
    active_stmt = select(func.count(Incident.id)).where(Incident.status == "active")
    active_result = await session.execute(active_stmt)
    active_incidents: int = active_result.scalar_one() or 0

    # Flapping peers: count distinct device+neighbor pairs with state='FLAPPING'
    # within the current day (UTC midnight boundary).
    _utc_midnight = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    flap_stmt = (
        select(
            func.count(
                func.distinct(
                    BGPPeerHistory.device_name + ":" + BGPPeerHistory.neighbor
                )
            )
        )
        .where(BGPPeerHistory.state == "FLAPPING")
        .where(BGPPeerHistory.timestamp >= _utc_midnight)
    )
    flap_result = await session.execute(flap_stmt)
    flapping_peers: int = flap_result.scalar_one() or 0

    # Health score
    # bgp_down_count / degraded_backhauls / pni_healthy use PRD defaults until a
    # live data source is wired; critical/warning/flapping reflect today's state.
    score = calculate_health_score(
        critical_count=critical,
        warning_count=warning,
        flapping_peers=flapping_peers,
    )

    # Top 5 most active devices today — use naive BDT bounds to match
    # how SQLite stores timestamps (naive BDT face values, no UTC offset).
    start = datetime(today.year, today.month, today.day, 0, 0, 0)  # noqa: DTZ001
    end = start + timedelta(days=1)
    top_devices_stmt = (
        select(AlertLog.device_name, func.count(AlertLog.id).label("cnt"))
        .where(AlertLog.timestamp >= start, AlertLog.timestamp < end)
        .group_by(AlertLog.device_name)
        .order_by(func.count(AlertLog.id).desc())
        .limit(5)
    )
    top_result = await session.execute(top_devices_stmt)
    top_devices = top_result.all()

    # Build digest message
    lines: list[str] = []
    lines.append("BSCCL NetWatch — Daily Digest")
    lines.append(f"Date: {today.isoformat()}")
    lines.append("")
    lines.append("Alert Summary")
    lines.append(f"  CRITICAL : {critical}")
    lines.append(f"  WARNING  : {warning}")
    lines.append(f"  INFO     : {info}")
    lines.append(f"  NOISE    : {noise}")
    lines.append(f"  TOTAL    : {total}")
    lines.append("")
    lines.append(f"Active Incidents : {active_incidents}")
    lines.append(f"Health Score     : {score:.1f}/100")
    lines.append("")

    if top_devices:
        lines.append("Top Active Devices")
        for device_name, cnt in top_devices:
            lines.append(f"  {device_name}: {cnt} alerts")
    else:
        lines.append("Top Active Devices: none")

    return "\n".join(lines)


async def send_daily_digest(session: AsyncSession) -> bool:
    """Generate and dispatch the daily digest to Discord and Telegram.

    Calls :func:`generate_daily_digest` to build the summary text, then
    posts it to Discord (as a plain-text webhook message) and Telegram (as
    a ``sendMessage`` API call).  Each channel is attempted independently —
    a failure in one does not prevent the other from being sent.

    Parameters
    ----------
    session:
        An active async session used by :func:`generate_daily_digest`.

    Returns
    -------
    bool
        ``True`` if at least one channel was delivered successfully,
        ``False`` if both channels failed or are disabled.
    """
    settings = get_settings()
    text = await generate_daily_digest(session)

    discord_ok = False
    telegram_ok = False

    # ── Discord ────────────────────────────────────────────────────────────
    if settings.discord_enabled and settings.discord_webhook_url:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    settings.discord_webhook_url,
                    json={"content": f"```\n{text}\n```"},
                )
            if resp.status_code in (200, 204):
                discord_ok = True
                _log.info("Daily digest sent to Discord (HTTP %d)", resp.status_code)
            else:
                _log.error(
                    "Discord digest returned HTTP %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
        except httpx.RequestError as exc:
            _log.error("Discord digest request failed: %s", exc)
    else:
        _log.debug("Discord disabled or no webhook URL — skipping digest dispatch.")

    # ── Telegram ───────────────────────────────────────────────────────────
    if (
        settings.telegram_enabled
        and settings.telegram_bot_token
        and settings.telegram_chat_id
    ):
        try:
            url = (
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
            )
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    url,
                    json={
                        "chat_id": settings.telegram_chat_id,
                        "text": f"```\n{text}\n```",
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True,
                    },
                )
            body = resp.json() if resp.status_code == 200 else {}
            if resp.status_code == 200 and body.get("ok"):
                telegram_ok = True
                _log.info("Daily digest sent to Telegram")
            else:
                _log.error(
                    "Telegram digest returned HTTP %d / ok=%s",
                    resp.status_code,
                    body.get("ok"),
                )
        except httpx.RequestError as exc:
            _log.error("Telegram digest request failed: %s", exc)
    else:
        _log.debug("Telegram disabled or missing token/chat_id — skipping digest.")

    return discord_ok or telegram_ok
