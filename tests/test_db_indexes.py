"""Tests for DB index creation and idempotent migration.

Verifies that:
- New indexes are present after create_tables() on a fresh DB.
- Running create_tables() twice (idempotent migration) does not raise.
- pool_pre_ping is configured on the engine (no connection errors on reuse).
"""

from __future__ import annotations

import pytest

from src.database.migrations import create_tables, get_engine

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _index_names(engine: object) -> set[str]:
    """Return the set of index names present in sqlite_master."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine

    assert isinstance(engine, AsyncEngine)
    async with engine.connect() as conn:
        result = await conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='index'")
        )
        return {row[0] for row in result.fetchall()}


# ---------------------------------------------------------------------------
# 1. New indexes present after create_tables
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_incident_id_index_created() -> None:
    """ix_alertlog_incident_id must exist after create_tables on a fresh DB."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)

    names = await _index_names(engine)
    await engine.dispose()

    assert (
        "ix_alertlog_incident_id" in names
    ), f"Expected ix_alertlog_incident_id in indexes, got: {sorted(names)}"


@pytest.mark.asyncio
async def test_device_mnemonic_resolved_index_created() -> None:
    """ix_alertlog_device_mnemonic_resolved must exist after create_tables."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)

    names = await _index_names(engine)
    await engine.dispose()

    assert "ix_alertlog_device_mnemonic_resolved" in names, (
        f"Expected ix_alertlog_device_mnemonic_resolved in indexes, "
        f"got: {sorted(names)}"
    )


@pytest.mark.asyncio
async def test_existing_indexes_preserved() -> None:
    """Pre-existing indexes must still be present alongside the new ones."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)

    names = await _index_names(engine)
    await engine.dispose()

    expected_existing = {
        "ix_alertlog_classification_ts",
        "ix_alertlog_device_ts",
        "ix_alertlog_mnemonic",
    }
    missing = expected_existing - names
    assert not missing, f"Pre-existing indexes missing after migration: {missing}"


# ---------------------------------------------------------------------------
# 2. Idempotent migration — running create_tables twice must not raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_tables_idempotent_fresh_db() -> None:
    """Calling create_tables twice on a fresh in-memory DB must not raise."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)
    # Second call — CREATE INDEX IF NOT EXISTS should be a no-op
    await create_tables(engine)
    await engine.dispose()


@pytest.mark.asyncio
async def test_idempotent_migration_indexes_unchanged(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Indexes are unchanged (no duplicates, no errors) after two startups.

    Uses a file-backed DB so the second create_tables call exercises the
    real idempotent path (the tables and indexes already exist on disk).
    """
    db_path = tmp_path / "idempotent_test.db"
    file_url = f"sqlite+aiosqlite:///{db_path}"

    # First startup
    engine = await get_engine(file_url)
    await create_tables(engine)
    names_first = await _index_names(engine)
    await engine.dispose()

    # Second startup (simulates application restart)
    engine2 = await get_engine(file_url)
    await create_tables(engine2)
    names_second = await _index_names(engine2)
    await engine2.dispose()

    assert names_first == names_second, (
        f"Index set changed between two startups.\n"
        f"First:  {sorted(names_first)}\n"
        f"Second: {sorted(names_second)}"
    )
    assert "ix_alertlog_incident_id" in names_second
    assert "ix_alertlog_device_mnemonic_resolved" in names_second


# ---------------------------------------------------------------------------
# 3. pool_pre_ping — engine reuse does not error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pool_pre_ping_no_error() -> None:
    """Engine with pool_pre_ping=True must handle repeated connection reuse."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession

    # Execute two queries in separate sessions to exercise pre-ping path
    async with AsyncSession(engine) as s1:
        await s1.execute(text("SELECT 1"))

    async with AsyncSession(engine) as s2:
        result = await s2.execute(text("SELECT COUNT(*) FROM alert_log"))
        count = result.scalar()

    await engine.dispose()
    assert count == 0
