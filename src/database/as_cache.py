"""AS number lookup cache backed by SQLite.

External lookups (PeeringDB / bgpview / RIPE STAT / BigDataCloud) are
expensive and rate-limited.  Results are stored in the ``as_cache`` table
and expire after ``TTL_HOURS`` hours.  Callers should check
:func:`get_cached_as` before performing a live lookup.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import ASCache

_log = logging.getLogger(__name__)

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


async def resolve_as_name(
    session: AsyncSession,
    asn: int,
    api_key: str = "",
) -> str:
    """Resolve an AS number to an organization name.

    Lookup order: static AS database → SQLite cache → BigDataCloud API.
    API results are cached so subsequent lookups never hit the network.

    Returns the org name, or ``""`` if all sources fail.
    """
    if asn <= 0:
        return ""

    from src.data.as_database import lookup_as  # noqa: PLC0415

    static = lookup_as(asn)
    if static is not None:
        return static.name

    cached = await get_cached_as(session, asn)
    if cached is not None:
        return cached.name

    if not api_key:
        return ""

    try:
        import httpx  # noqa: PLC0415

        url = "https://api-bdc.net/data/asn-info"
        params = {
            "asn": f"AS{asn}",
            "localityLanguage": "en",
            "key": api_key,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

        org_name: str = data.get("organisation", "") or data.get("name", "")

        if org_name:
            await cache_as_lookup(session, asn, org_name, "external", "bigdatacloud")
            _log.info("Cached AS%d → %s (BigDataCloud)", asn, org_name)
            return org_name
    except Exception as exc:  # noqa: BLE001
        _log.warning("BigDataCloud ASN lookup failed for AS%d: %s", asn, exc)

    return ""
