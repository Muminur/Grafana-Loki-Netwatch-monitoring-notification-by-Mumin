"""Statistics query engine for BSCCL NetWatch.

Provides async functions to query aggregated alert statistics for daily,
weekly, and per-device views.  All functions read directly from ``AlertLog``
so they work even if the hourly aggregator has not yet run.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import func, select

from src.database.models import AlertLog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


async def get_daily_stats(
    session: AsyncSession, target_date: date
) -> dict[str, object]:
    """Get alert counts grouped by classification for a specific day.

    Parameters
    ----------
    session:
        An active async session.
    target_date:
        The calendar date to query.

    Returns
    -------
    dict
        Keys: ``date`` (ISO string), ``critical``, ``warning``, ``info``,
        ``noise``, ``login``, ``total``.
    """
    start = datetime(
        target_date.year, target_date.month, target_date.day, 0, 0, 0, tzinfo=UTC
    )
    end = start + timedelta(days=1)

    stmt = (
        select(AlertLog.classification, func.count(AlertLog.id).label("cnt"))
        .where(AlertLog.timestamp >= start, AlertLog.timestamp < end)
        .group_by(AlertLog.classification)
    )
    result = await session.execute(stmt)
    rows = result.all()

    counts: dict[str, int] = {
        "CRITICAL": 0,
        "WARNING": 0,
        "INFO": 0,
        "NOISE": 0,
        "USER_LOGIN": 0,
    }
    for classification, cnt in rows:
        if classification in counts:
            counts[classification] = cnt

    total = sum(counts.values())
    return {
        "date": target_date.isoformat(),
        "critical": counts["CRITICAL"],
        "warning": counts["WARNING"],
        "info": counts["INFO"],
        "noise": counts["NOISE"],
        "login": counts["USER_LOGIN"],
        "total": total,
    }


async def get_weekly_stats(
    session: AsyncSession, week_start: date
) -> dict[str, object]:
    """Get daily alert counts for a 7-day period starting from ``week_start``.

    Parameters
    ----------
    session:
        An active async session.
    week_start:
        The first day of the week to query.

    Returns
    -------
    dict
        Keys: ``week_start`` (ISO string), ``days`` (list of 7 daily stat dicts).
    """
    days: list[dict[str, object]] = []
    for offset in range(7):
        day = week_start + timedelta(days=offset)
        daily = await get_daily_stats(session, day)
        days.append(daily)

    return {
        "week_start": week_start.isoformat(),
        "days": days,
    }


async def get_device_stats(
    session: AsyncSession,
    device_name: str,
    days: int = 7,
) -> dict[str, object]:
    """Get alert history for a specific device over the last ``days`` days.

    Parameters
    ----------
    session:
        An active async session.
    device_name:
        Exact device name as stored in ``AlertLog.device_name``.
    days:
        Number of days to look back from now (default 7).

    Returns
    -------
    dict
        Keys: ``device_name``, ``days``, ``total_alerts``, ``by_classification``
        (dict with counts per severity), ``daily`` (list of per-day counts).
    """
    end = datetime.now(UTC)
    start = end - timedelta(days=days)

    stmt = (
        select(AlertLog.classification, func.count(AlertLog.id).label("cnt"))
        .where(
            AlertLog.device_name == device_name,
            AlertLog.timestamp >= start,
            AlertLog.timestamp <= end,
        )
        .group_by(AlertLog.classification)
    )
    result = await session.execute(stmt)
    rows = result.all()

    by_class: dict[str, int] = {
        "CRITICAL": 0,
        "WARNING": 0,
        "INFO": 0,
        "NOISE": 0,
        "USER_LOGIN": 0,
    }
    for classification, cnt in rows:
        if classification in by_class:
            by_class[classification] = cnt

    total = sum(by_class.values())

    return {
        "device_name": device_name,
        "days": days,
        "total_alerts": total,
        "by_classification": by_class,
    }
