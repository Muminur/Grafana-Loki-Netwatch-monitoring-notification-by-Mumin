"""Hourly alert aggregation background task for BSCCL NetWatch.

Reads ``AlertLog`` rows and writes pre-aggregated counts into ``HourlyStats``
so that statistics queries can be served from a small, pre-computed table
rather than scanning the full alert log.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import AlertLog, HourlyStats

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


async def aggregate_hourly(session: AsyncSession) -> None:
    """Aggregate alert counts into hourly per-device buckets.

    For each (device_name, hour) combination found in ``AlertLog``, this
    function upserts a ``HourlyStats`` row containing counts per
    classification.

    The hour bucket is computed by truncating the alert's ``timestamp`` to
    the hour boundary (minutes/seconds set to zero).

    This function is idempotent: re-running it for the same time window will
    overwrite existing rows with the same counts.

    Parameters
    ----------
    session:
        An active async session.  The caller is responsible for committing
        the transaction after this function returns.
    """
    # Fetch all alert rows (timestamp, device_name, classification)
    stmt = select(
        AlertLog.timestamp,
        AlertLog.device_name,
        AlertLog.classification,
    )
    result = await session.execute(stmt)
    rows = result.all()

    # Group counts by (device_name, hour_bucket, classification)
    from collections import defaultdict

    # key: (device_name, hour_bucket) → {classification: count}
    buckets: dict[tuple[str, datetime], dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )

    for ts, device_name, classification in rows:
        # Truncate to hour boundary (timezone-aware)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        hour_bucket = ts.replace(minute=0, second=0, microsecond=0)
        buckets[(device_name, hour_bucket)][classification] += 1

    # Upsert HourlyStats rows
    for (device_name, hour_bucket), counts in buckets.items():
        # Check if row already exists
        existing_stmt = select(HourlyStats).where(
            HourlyStats.device_name == device_name,
            HourlyStats.hour == hour_bucket,
        )
        existing_result = await session.execute(existing_stmt)
        existing = existing_result.scalar_one_or_none()

        critical = counts.get("CRITICAL", 0)
        warning = counts.get("WARNING", 0)
        info = counts.get("INFO", 0)
        noise = counts.get("NOISE", 0)
        login = counts.get("USER_LOGIN", 0)

        if existing is None:
            hourly = HourlyStats(
                hour=hour_bucket,
                device_name=device_name,
                critical_count=critical,
                warning_count=warning,
                info_count=info,
                noise_count=noise,
                login_count=login,
            )
            session.add(hourly)
        else:
            existing.critical_count = critical
            existing.warning_count = warning
            existing.info_count = info
            existing.noise_count = noise
            existing.login_count = login

    await session.flush()
