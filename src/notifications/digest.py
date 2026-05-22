"""Daily digest generator for BSCCL NetWatch.

Produces a summary message (for Discord and Telegram) covering:
- Total alert counts by severity for the current day
- Top 5 most active devices
- Active incident count
- Network health score

Scheduled to run at 08:00 BDT (02:00 UTC) via the background task scheduler.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select

from src.database.models import AlertLog, Incident
from src.statistics.engine import get_daily_stats
from src.statistics.health_score import calculate_health_score

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


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
    today = datetime.now(tz=UTC).date()
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

    # Flapping peers: approximate from BGP peer history (digest uses 0 for simplicity)
    flapping_peers = 0

    # Health score
    score = calculate_health_score(
        critical_count=critical,
        warning_count=warning,
        active_incidents=active_incidents,
        flapping_peers=flapping_peers,
    )

    # Top 5 most active devices today
    start = datetime(today.year, today.month, today.day, 0, 0, 0, tzinfo=UTC)
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
