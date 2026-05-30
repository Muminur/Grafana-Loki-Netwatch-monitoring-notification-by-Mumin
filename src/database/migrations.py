"""Database migrations: create tables and configure SQLite engine.

Called once at application startup via ``create_tables(engine)``.
WAL mode is enabled for better concurrent read performance.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from src.database.models import Base


async def get_engine(database_url: str) -> AsyncEngine:
    """Create and return an async SQLAlchemy engine.

    WAL journal mode is applied via ``connect_args`` so every new
    connection automatically switches to WAL before any queries run.

    ``pool_pre_ping=True`` causes SQLAlchemy to test each connection
    before handing it to the application, transparently recycling stale
    handles.  The aiosqlite engine uses a ``StaticPool`` for in-memory
    URLs and an ``AsyncAdaptedQueuePool`` for file-backed URLs; pre-ping
    adds negligible overhead while guarding against rare file-handle
    recycling issues on long-running deployments.

    Args:
        database_url: SQLAlchemy-style async DB URL, e.g.
            ``sqlite+aiosqlite:///bsccl_netwatch.db`` or
            ``sqlite+aiosqlite:///:memory:`` for tests.

    Returns:
        A ready-to-use ``AsyncEngine``.
    """
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        connect_args={"check_same_thread": False},
    )
    # Enable WAL mode for SQLite on the first connection
    from sqlalchemy import event

    @event.listens_for(engine.sync_engine, "connect")
    def _set_wal(dbapi_conn: Any, _connection_record: Any) -> None:
        dbapi_conn.execute("PRAGMA journal_mode=WAL")

    return engine


async def create_tables(engine: AsyncEngine) -> None:
    """Create all ORM-declared tables if they do not already exist.

    Idempotent: safe to call on every startup.

    Args:
        engine: The async engine returned by :func:`get_engine`.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await _migrate_alert_log_resolution_columns(engine)
    await _migrate_alert_log_acknowledged_at(engine)
    await _migrate_alert_log_indexes(engine)
    await _migrate_maintenance_window_created_at(engine)
    await _migrate_alert_log_notification_columns(engine)


async def _migrate_alert_log_resolution_columns(engine: AsyncEngine) -> None:
    """Add resolved_at and resolution_reason columns if missing (v9 schema)."""
    from sqlalchemy import text  # noqa: PLC0415

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns = {row[1] for row in result.fetchall()}

        if "resolved_at" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log ADD COLUMN resolved_at DATETIME DEFAULT NULL"
                )
            )
        if "resolution_reason" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log "
                    "ADD COLUMN resolution_reason VARCHAR(64) DEFAULT ''"
                )
            )


async def _migrate_alert_log_indexes(engine: AsyncEngine) -> None:
    """Ensure performance indexes exist on alert_log (v10 schema).

    Uses ``CREATE INDEX IF NOT EXISTS`` so this is safe to call on both
    fresh databases (where ``create_all`` already created the indexes via
    ORM metadata) and existing deployments that were created before the
    indexes were added to the model.

    Indexes created here must match the names declared in
    ``AlertLog.__table_args__`` so that SQLAlchemy and the migration stay
    in sync.
    """
    from sqlalchemy import text  # noqa: PLC0415

    ddl_statements = [
        # incident_id — incident detail lookups (WHERE incident_id = ?)
        text(
            "CREATE INDEX IF NOT EXISTS ix_alertlog_incident_id "
            "ON alert_log (incident_id)"
        ),
        # (device_name, mnemonic, resolved_at) — BGP-UP silent-fault
        # resolution query:
        #   WHERE device_name = ? AND mnemonic IN (...)
        #   AND resolved_at IS NULL AND timestamp >= ?
        text(
            "CREATE INDEX IF NOT EXISTS ix_alertlog_device_mnemonic_resolved "
            "ON alert_log (device_name, mnemonic, resolved_at)"
        ),
        # timestamp — stats range scans (WHERE timestamp >= start) for the
        # hourly-bucket and per-device aggregation in /api/stats/daily|weekly
        text(
            "CREATE INDEX IF NOT EXISTS ix_alertlog_timestamp "
            "ON alert_log (timestamp)"
        ),
    ]

    async with engine.begin() as conn:
        for stmt in ddl_statements:
            await conn.execute(stmt)


async def _migrate_alert_log_acknowledged_at(engine: AsyncEngine) -> None:
    """Add acknowledged_at column to alert_log if missing (v12 schema).

    Mirrors the pattern used by ``_migrate_alert_log_resolution_columns``.
    Idempotent: guarded by a ``PRAGMA table_info`` existence check.
    Safe to call on fresh databases (``create_all`` already creates the column
    via ORM metadata).
    """
    from sqlalchemy import text  # noqa: PLC0415

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns = {row[1] for row in result.fetchall()}

        if "acknowledged_at" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log "
                    "ADD COLUMN acknowledged_at DATETIME DEFAULT NULL"
                )
            )


async def _migrate_maintenance_window_created_at(engine: AsyncEngine) -> None:
    """Add created_at column to maintenance_window if missing (v11 schema).

    Existing rows get the current UTC timestamp as their created_at value.
    Safe to call on fresh databases (the ORM already creates the column via
    ``Base.metadata.create_all``).
    """
    from sqlalchemy import text  # noqa: PLC0415

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(maintenance_window)"))
        columns = {row[1] for row in result.fetchall()}

        if "created_at" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE maintenance_window "
                    "ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
                )
            )


async def _migrate_alert_log_notification_columns(engine: AsyncEngine) -> None:
    """Add per-channel notification tracking columns if missing (v13 schema).

    Adds ``discord_sent``, ``telegram_sent``, ``discord_error``, and
    ``telegram_error`` to ``alert_log`` so delivery status can be tracked
    per notification channel.  Existing rows default to ``0`` (False) for
    booleans and ``''`` for error strings.

    Idempotent: guarded by ``PRAGMA table_info`` existence check.
    Safe to call on fresh databases (``create_all`` already creates the
    columns via ORM metadata).
    """
    from sqlalchemy import text  # noqa: PLC0415

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns = {row[1] for row in result.fetchall()}

        if "discord_sent" not in columns:
            await conn.execute(
                text("ALTER TABLE alert_log ADD COLUMN discord_sent BOOLEAN DEFAULT 0")
            )
        if "telegram_sent" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log "
                    "ADD COLUMN telegram_sent BOOLEAN DEFAULT 0"
                )
            )
        if "discord_error" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log "
                    "ADD COLUMN discord_error VARCHAR(256) DEFAULT ''"
                )
            )
        if "telegram_error" not in columns:
            await conn.execute(
                text(
                    "ALTER TABLE alert_log "
                    "ADD COLUMN telegram_error VARCHAR(256) DEFAULT ''"
                )
            )
