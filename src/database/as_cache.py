"""AS number lookup cache backed by SQLite.

External lookups (PeeringDB / bgpview / RIPE STAT) are expensive and
rate-limited.  Results are stored in the ``as_cache`` table and expire
after ``TTL_HOURS`` hours.  Callers should check :func:`get_cached_as`
before performing a live lookup.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import ASCache

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

TTL_HOURS: int = 24  # Cache time-to-live in hours


async def get_cached_as(session: AsyncSession, asn: int) -> ASCache | None:
    """Return a cached AS record if it exists and has not expired.

    The record is considered expired when its ``cached_at`` timestamp is
    older than ``TTL_HOURS`` hours from *now* (UTC).

    Args:
        session: An active async session.
        asn: The Autonomous System Number to look up.

    Returns:
        An ``ASCache`` instance if fresh, ``None`` if missing or expired.
    """
    stmt = select(ASCache).where(ASCache.asn == asn)
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        return None

    expiry_threshold = datetime.now(tz=UTC) - timedelta(hours=TTL_HOURS)

    # Support both timezone-aware and timezone-naive datetimes stored in SQLite
    cached_at = record.cached_at
    if cached_at.tzinfo is None:
        cached_at = cached_at.replace(tzinfo=UTC)

    if cached_at < expiry_threshold:
        return None  # TTL expired

    return record


async def cache_as_lookup(
    session: AsyncSession,
    asn: int,
    name: str,
    as_type: str,
    source: str,
) -> ASCache:
    """Store or update an AS lookup result in the cache.

    If a record for ``asn`` already exists it is updated in-place;
    otherwise a new row is inserted.  The ``cached_at`` timestamp is
    always set to the current UTC time.

    Args:
        session: An active async session.
        asn: Autonomous System Number.
        name: Human-readable AS name (e.g. ``"TCLOUD Computing"``).
        as_type: Category tag (e.g. ``"IX-MLPE"``, ``"ISP-Client"``).
        source: Where the data came from (``"peeringdb"``, ``"bgpview"``,
            ``"ripe"``).

    Returns:
        The persisted (or updated) ``ASCache`` instance.
    """
    stmt = select(ASCache).where(ASCache.asn == asn)
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    now = datetime.now(tz=UTC)

    if existing is not None:
        existing.name = name
        existing.as_type = as_type
        existing.source = source
        existing.cached_at = now
        await session.flush()
        await session.refresh(existing)
        return existing

    record = ASCache(
        asn=asn,
        name=name,
        as_type=as_type,
        source=source,
        cached_at=now,
    )
    session.add(record)
    await session.flush()
    await session.refresh(record)
    return record
