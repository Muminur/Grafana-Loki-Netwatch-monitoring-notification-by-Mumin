"""Hourly alert aggregation background task for BSCCL NetWatch.

Reads ``AlertLog`` rows and writes pre-aggregated counts into ``HourlyStats``
so that statistics queries can be served from a small, pre-computed table
rather than scanning the full alert log.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import AlertLog, HourlyStats

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


async def aggregate_hourly(
    session: AsyncSession,
    *,
    lookback_days: int = 7,
) -> None:
    """Aggregate alert counts into hourly per-device buckets.

    For each (device_name, hour) combination found in ``AlertLog`` within the
    lookback window, this function upserts a ``HourlyStats`` row containing
    counts per classification.

    The hour bucket is computed by truncating the alert's ``timestamp`` to
    the hour boundary (minutes/seconds set to zero).

    This function is idempotent: re-running it for the same time window will
    overwrite existing rows with the same counts.

    Only alerts within the last ``lookback_days`` days are processed.  This
    bounds the query to a recent window so the function stays fast even on
    deployments with millions of historical rows.

    Parameters
    ----------
    session:
        An active async session.  The caller is responsible for committing
        the transaction after this function returns.
    lookback_days:
        Number of days to look back from now (default 7).  Older rows are
        not re-aggregated; their ``HourlyStats`` rows remain unchanged.
    """
    # Compute a time-bounded cutoff so we only scan recent rows.
    # SQLite stores timestamps as naive face values (UTC+6 BDT), so the
    # cutoff must use a naive datetime to compare correctly.
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(
        days=lookback_days
    )  # noqa: DTZ001

    # Fetch only recent alert rows (timestamp, device_name, classification)
    stmt = select(
        AlertLog.timestamp,
        AlertLog.device_name,
        AlertLog.classification,
    ).where(AlertLog.timestamp >= cutoff)

    result = await session.execute(stmt)
    rows = result.all()

    # Group counts by (device_name, hour_bucket, classification)
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
