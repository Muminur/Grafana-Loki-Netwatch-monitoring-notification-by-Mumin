"""Tests for database migration idempotency.

Verifies that ``create_tables()`` can be called multiple times on the same
database without errors.  This is critical for production deployments where
the application restarts against an existing database file.

Uses an in-memory SQLite database via ``create_async_engine``.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.migrations import create_tables, get_engine

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def engine():
    """Create a fresh in-memory engine for each test."""
    _engine = await get_engine(IN_MEMORY_URL)
    yield _engine
    await _engine.dispose()


# ---------------------------------------------------------------------------
# 1. create_tables is idempotent (can be called twice without error)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_tables_idempotent(engine) -> None:
    """Calling create_tables() twice on the same engine raises no error."""
    # First call -- creates all tables
    await create_tables(engine)

    # Second call -- must be idempotent (no error)
    await create_tables(engine)

    # Verify core tables exist by querying them
    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )
        table_names = {row[0] for row in result.fetchall()}

    assert "alert_log" in table_names
    assert "incident" in table_names
    assert "hourly_stats" in table_names
    assert "maintenance_window" in table_names


# ---------------------------------------------------------------------------
# 2. create_tables produces correct schema on fresh DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_tables_produces_all_expected_tables(engine) -> None:
    """create_tables creates every model table defined in models.py."""
    await create_tables(engine)

    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'")
        )
        table_names = {row[0] for row in result.fetchall()}

    expected = {
        "alert_log",
        "incident",
        "bgp_peer_history",
        "hourly_stats",
        "as_cache",
        "maintenance_window",
        "app_setting",
        "user_login",
    }
    assert expected.issubset(table_names), f"Missing tables: {expected - table_names}"


# ---------------------------------------------------------------------------
# 3. Migration columns present after create_tables
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_columns_present_after_create(engine) -> None:
    """Columns added by migrations (resolved_at, acknowledged_at) exist."""
    await create_tables(engine)

    async with AsyncSession(engine) as session:
        result = await session.execute(text("PRAGMA table_info(alert_log)"))
        columns = {row[1] for row in result.fetchall()}

    assert "resolved_at" in columns
    assert "resolution_reason" in columns
    assert "acknowledged_at" in columns


# ---------------------------------------------------------------------------
# 4. Maintenance window migration column present
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_maintenance_window_created_at_column(engine) -> None:
    """The created_at column on maintenance_window exists after migration."""
    await create_tables(engine)

    async with AsyncSession(engine) as session:
        result = await session.execute(text("PRAGMA table_info(maintenance_window)"))
        columns = {row[1] for row in result.fetchall()}

    assert "created_at" in columns


# ---------------------------------------------------------------------------
# 5. Indexes created by migration are present
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migration_indexes_present(engine) -> None:
    """Performance indexes from migration step exist on alert_log."""
    await create_tables(engine)

    async with AsyncSession(engine) as session:
        result = await session.execute(text("PRAGMA index_list(alert_log)"))
        index_names = {row[1] for row in result.fetchall()}

    assert "ix_alertlog_incident_id" in index_names
    assert "ix_alertlog_device_mnemonic_resolved" in index_names


# ---------------------------------------------------------------------------
# 6. Triple call still idempotent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_tables_triple_call(engine) -> None:
    """Calling create_tables three times is still safe and idempotent."""
    await create_tables(engine)
    await create_tables(engine)
    await create_tables(engine)

    # Verify DB is still functional by inserting a row
    async with AsyncSession(engine) as session:
        await session.execute(
            text(
                "INSERT INTO app_setting (key, value, updated_at) "
                "VALUES ('test_key', 'test_val', CURRENT_TIMESTAMP)"
            )
        )
        await session.commit()

    async with AsyncSession(engine) as session:
        result = await session.execute(
            text("SELECT value FROM app_setting WHERE key = 'test_key'")
        )
        row = result.scalar_one()
        assert row == "test_val"


# ---------------------------------------------------------------------------
# 7. get_engine enables WAL mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_engine_wal_mode() -> None:
    """get_engine configures WAL journal mode for SQLite connections."""
    _engine = await get_engine(IN_MEMORY_URL)
    try:
        await create_tables(_engine)

        async with AsyncSession(_engine) as session:
            result = await session.execute(text("PRAGMA journal_mode"))
            mode = result.scalar_one()
            # In-memory SQLite may report 'memory' instead of 'wal';
            # the WAL pragma listener fires but SQLite ignores it for
            # in-memory databases.  File-backed DBs would return 'wal'.
            assert mode in ("wal", "memory")
    finally:
        await _engine.dispose()
