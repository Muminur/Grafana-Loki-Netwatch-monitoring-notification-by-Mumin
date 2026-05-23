"""CRUD helpers for the BSCCL NetWatch database.

All functions are async and accept an ``AsyncSession`` so callers control
transaction boundaries.  Each function commits its own work unless the
caller manages the session explicitly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import AlertLog

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


async def insert_alert(session: AsyncSession, alert: AlertLog) -> AlertLog:
    """Persist a single ``AlertLog`` and return the flushed instance.

    The session is flushed and the row is refreshed so ``alert.id`` is
    populated when this function returns.

    Args:
        session: An active async session.
        alert: The ``AlertLog`` instance to insert.

    Returns:
        The same instance with ``id`` populated.
    """
    session.add(alert)
    await session.flush()
    await session.refresh(alert)
    return alert


async def insert_alerts_batch(
    session: AsyncSession, alerts: list[AlertLog]
) -> list[AlertLog]:
    """Persist multiple ``AlertLog`` rows in a single flush.

    Args:
        session: An active async session.
        alerts: Non-empty list of ``AlertLog`` instances.

    Returns:
        The same list with ``id`` populated on every element.
    """
    for alert in alerts:
        session.add(alert)
    await session.flush()
    for alert in alerts:
        await session.refresh(alert)
    return alerts


async def get_alerts_by_severity(
    session: AsyncSession,
    classification: str,
    limit: int = 100,
) -> list[AlertLog]:
    """Return up to ``limit`` alerts matching ``classification``.

    Results are ordered newest-first (descending ``timestamp``).

    Args:
        session: An active async session.
        classification: One of CRITICAL / WARNING / INFO / NOISE / USER_LOGIN.
        limit: Maximum number of rows to return (default 100).

    Returns:
        A list of matching ``AlertLog`` instances.
    """
    stmt = (
        select(AlertLog)
        .where(AlertLog.classification == classification)
        .order_by(AlertLog.timestamp.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_alerts_by_device(
    session: AsyncSession,
    device_name: str,
    limit: int = 100,
) -> list[AlertLog]:
    """Return up to ``limit`` alerts from a specific device.

    Results are ordered newest-first (descending ``timestamp``).

    Args:
        session: An active async session.
        device_name: Exact device name as stored (e.g. ``BSCCL-EQ-RTR-01``).
        limit: Maximum number of rows to return (default 100).

    Returns:
        A list of matching ``AlertLog`` instances.
    """
    stmt = (
        select(AlertLog)
        .where(AlertLog.device_name == device_name)
        .order_by(AlertLog.timestamp.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())
