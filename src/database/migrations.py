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
