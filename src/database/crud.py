"""CRUD helpers for the BSCCL NetWatch database.

All functions are async and accept an ``AsyncSession`` so callers control
transaction boundaries.  Each function commits its own work unless the
caller manages the session explicitly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import delete, select

from src.database.models import AlertLog, AppSetting, HourlyStats, MaintenanceWindow

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession


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


# ---------------------------------------------------------------------------
# MaintenanceWindow CRUD
# ---------------------------------------------------------------------------


async def list_maintenance_windows(
    session: AsyncSession,
) -> list[MaintenanceWindow]:
    """Return all maintenance windows ordered by start_time ascending.

    Args:
        session: An active async session.

    Returns:
        A list of all ``MaintenanceWindow`` instances.
    """
    stmt = select(MaintenanceWindow).order_by(MaintenanceWindow.start_time)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def create_maintenance_window(
    session: AsyncSession,
    device_name: str,
    start_time: datetime,
    end_time: datetime,
    reason: str = "",
    created_by: str = "",
) -> MaintenanceWindow:
    """Persist a new maintenance window and return the flushed instance.

    The session is flushed so ``window.id`` is populated when this function
    returns.  The caller is responsible for committing the transaction.

    Args:
        session: An active async session.
        device_name: Name of the device under maintenance.
        start_time: Maintenance window start (UTC-aware or naive UTC).
        end_time: Maintenance window end (UTC-aware or naive UTC).
        reason: Optional human-readable reason string.
        created_by: Optional operator/user identifier.

    Returns:
        The persisted ``MaintenanceWindow`` with ``id`` populated.
    """
    window = MaintenanceWindow(
        device_name=device_name,
        start_time=start_time,
        end_time=end_time,
        reason=reason,
        created_by=created_by,
        created_at=datetime.now(UTC),
    )
    session.add(window)
    await session.flush()
    await session.refresh(window)
    return window


async def delete_maintenance_window(session: AsyncSession, window_id: int) -> bool:
    """Delete a maintenance window by primary key.

    Args:
        session: An active async session.
        window_id: The integer primary key of the window to delete.

    Returns:
        ``True`` if a row was deleted, ``False`` if not found.
    """
    stmt = select(MaintenanceWindow).where(MaintenanceWindow.id == window_id)
    result = await session.execute(stmt)
    window = result.scalar_one_or_none()
    if window is None:
        return False
    await session.delete(window)
    return True


# ---------------------------------------------------------------------------
# AppSetting CRUD
# ---------------------------------------------------------------------------


async def get_app_setting(session: AsyncSession, key: str) -> str | None:
    """Return the value for *key*, or ``None`` if the key does not exist.

    Args:
        session: An active async session.
        key: The setting key to look up.

    Returns:
        The stored value string, or ``None`` if not found.
    """
    stmt = select(AppSetting).where(AppSetting.key == key)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    return row.value if row is not None else None


async def set_app_setting(session: AsyncSession, key: str, value: str) -> AppSetting:
    """Upsert an application setting (insert or update).

    Creates the row if it does not exist; updates ``value`` and
    ``updated_at`` if it does.  The caller is responsible for committing.

    Args:
        session: An active async session.
        key: The setting key.
        value: The string value to store.

    Returns:
        The ``AppSetting`` instance.
    """
    stmt = select(AppSetting).where(AppSetting.key == key)
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is None:
        row = AppSetting(key=key, value=value, updated_at=datetime.now(UTC))
        session.add(row)
    else:
        row.value = value
        row.updated_at = datetime.now(UTC)
    await session.flush()
    return row


# ---------------------------------------------------------------------------
# Retention cleanup
# ---------------------------------------------------------------------------


async def prune_old_alerts(session: AsyncSession, retention_days: int) -> int:
    """Delete ``AlertLog`` rows older than *retention_days*.

    SQLite stores AlertLog timestamps as naive BDT (UTC+6) face values, so
    the cutoff is computed as a naive datetime to match.  Uses
    ``synchronize_session=False`` so the ORM does not attempt in-Python
    evaluation of remaining session objects after the bulk delete.

    Args:
        session: An active async session.  The caller is responsible for
            committing the transaction.
        retention_days: Age threshold in days.  Rows with a ``timestamp``
            older than the cutoff are deleted.

    Returns:
        The number of rows deleted.
    """
    # Strip tzinfo so the cutoff is naive, matching stored BDT timestamps.
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=retention_days)
    stmt = (
        delete(AlertLog)
        .where(AlertLog.timestamp < cutoff)
        .execution_options(synchronize_session=False)
    )
    result = await session.execute(stmt)
    return result.rowcount  # type: ignore[return-value]


async def prune_old_stats(session: AsyncSession, max_age_days: int = 365) -> int:
    """Delete ``HourlyStats`` rows older than *max_age_days*.

    Uses a naive datetime cutoff to match the naive BDT values stored in
    SQLite, consistent with :func:`prune_old_alerts`.

    Args:
        session: An active async session.  The caller is responsible for
            committing the transaction.
        max_age_days: Age threshold in days.  Defaults to 365.

    Returns:
        The number of rows deleted.
    """
    # Strip tzinfo so the cutoff is naive, matching stored BDT timestamps.
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=max_age_days)
    stmt = (
        delete(HourlyStats)
        .where(HourlyStats.hour < cutoff)
        .execution_options(synchronize_session=False)
    )
    result = await session.execute(stmt)
    return result.rowcount  # type: ignore[return-value]


async def vacuum_db(engine: AsyncEngine) -> None:
    """Run SQLite ``VACUUM`` to reclaim disk space after bulk deletes.

    ``VACUUM`` cannot run inside a transaction, so this function uses a raw
    DBAPI connection with ``isolation_level`` set to autocommit.

    Args:
        engine: The SQLAlchemy async engine whose underlying database will
            be vacuumed.
    """
    from sqlalchemy import text  # noqa: PLC0415

    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        await conn.execute(text("VACUUM"))
