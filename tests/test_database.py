"""Tests for database models, CRUD operations, and AS cache.

TDD approach: these tests are written FIRST (RED), then implementation makes them GREEN.
All tests use in-memory SQLite to avoid side effects.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.as_cache import cache_as_lookup, get_cached_as
from src.database.crud import (
    get_alerts_by_device,
    get_alerts_by_severity,
    insert_alert,
    insert_alerts_batch,
)
from src.database.migrations import create_tables, get_engine

# These imports will fail until implementation is done (RED phase)
from src.database.models import (
    AlertLog,
    ASCache,
    Incident,
    UserLogin,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def engine():
    """Create a fresh async engine with in-memory SQLite for each test."""
    _engine = await get_engine(IN_MEMORY_URL)
    await create_tables(_engine)
    yield _engine
    await _engine.dispose()


@pytest_asyncio.fixture
async def session(engine):
    """Provide a single async session bound to the in-memory engine."""
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as _session:
        yield _session


def _make_alert(**kwargs) -> AlertLog:
    """Build a minimal AlertLog with sensible defaults."""
    defaults = {
        "timestamp": datetime(2026, 5, 22, 15, 0, 0, tzinfo=UTC),
        "source_ip": "192.168.203.1",
        "device_name": "BSCCL-EQ-RTR-01",
        "hostname": "BSCCL-EQ-RTR-01",
        "facility": "BGP",
        "severity_level": 5,
        "mnemonic": "ADJCHANGE",
        "message": "neighbor 2001:de8:4::39:9077:1 Down",
        "raw": "raw syslog line here",
        "classification": "CRITICAL",
    }
    defaults.update(kwargs)
    return AlertLog(**defaults)


# ---------------------------------------------------------------------------
# 1. test_create_tables
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_tables():
    """Migrations must create all tables without error on fresh DB."""
    _engine = await get_engine(IN_MEMORY_URL)
    # Should not raise
    await create_tables(_engine)

    # Confirm all expected tables exist
    from sqlalchemy import inspect

    async with _engine.connect() as conn:
        table_names = await conn.run_sync(
            lambda sync_conn: inspect(sync_conn).get_table_names()
        )

    expected = {
        "alert_log",
        "incident",
        "bgp_peer_history",
        "hourly_stats",
        "as_cache",
        "maintenance_window",
        "user_login",
    }
    assert expected.issubset(
        set(table_names)
    ), f"Missing tables: {expected - set(table_names)}"
    await _engine.dispose()


# ---------------------------------------------------------------------------
# 2. test_insert_alert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_alert(session: AsyncSession):
    """Insert a single AlertLog and read it back by id."""
    alert = _make_alert(classification="CRITICAL", mnemonic="ADJCHANGE")
    saved = await insert_alert(session, alert)

    assert saved.id is not None, "id should be auto-assigned after insert"
    assert saved.classification == "CRITICAL"
    assert saved.mnemonic == "ADJCHANGE"
    assert saved.device_name == "BSCCL-EQ-RTR-01"


# ---------------------------------------------------------------------------
# 3. test_insert_alerts_batch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_alerts_batch(session: AsyncSession):
    """Batch insert 10 AlertLogs and verify count."""
    alerts = [
        _make_alert(
            classification="WARNING",
            mnemonic=f"TEST{i:02d}",
            source_ip=f"192.168.200.{i}",
        )
        for i in range(10)
    ]
    saved = await insert_alerts_batch(session, alerts)
    assert len(saved) == 10
    for s in saved:
        assert s.id is not None


# ---------------------------------------------------------------------------
# 4. test_query_by_severity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_by_severity(session: AsyncSession):
    """Insert mixed-severity alerts and query for CRITICAL only."""
    mixed = [
        _make_alert(classification="CRITICAL", mnemonic="ADJCHANGE"),
        _make_alert(classification="WARNING", mnemonic="ADJCHANGE_UP"),
        _make_alert(classification="INFO", mnemonic="SSH_LOGIN"),
        _make_alert(classification="CRITICAL", mnemonic="MAXPFX"),
    ]
    await insert_alerts_batch(session, mixed)

    results = await get_alerts_by_severity(session, "CRITICAL")
    assert len(results) == 2
    for r in results:
        assert r.classification == "CRITICAL"


# ---------------------------------------------------------------------------
# 5. test_query_by_device
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_query_by_device(session: AsyncSession):
    """Insert alerts for multiple devices and query by device name."""
    alerts = [
        _make_alert(device_name="BSCCL-EQ-RTR-01", mnemonic="ADJCHANGE"),
        _make_alert(device_name="KKT-Core-02", mnemonic="MAXPFX"),
        _make_alert(device_name="BSCCL-EQ-RTR-01", mnemonic="NSR_DISABLED"),
        _make_alert(device_name="COX-Core-01", mnemonic="SFPALARM"),
    ]
    await insert_alerts_batch(session, alerts)

    eq_results = await get_alerts_by_device(session, "BSCCL-EQ-RTR-01")
    assert len(eq_results) == 2
    for r in eq_results:
        assert r.device_name == "BSCCL-EQ-RTR-01"

    cox_results = await get_alerts_by_device(session, "COX-Core-01")
    assert len(cox_results) == 1


# ---------------------------------------------------------------------------
# 6. test_incident_creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_incident_creation(session: AsyncSession):
    """Create and retrieve an Incident with INC-YYYYMMDD-NNN ID format."""
    incident = Incident(
        id="INC-20260522-001",
        title="EQ-RTR-01 BGP mass session drop",
        root_cause="Backhaul link failure",
        affected_devices='["BSCCL-EQ-RTR-01"]',
        affected_clients='["TCLOUD", "SG.GS"]',
        alert_count=15,
        symptom_count=14,
        status="active",
        created_at=datetime(2026, 5, 22, 19, 11, 4, tzinfo=UTC),
    )
    session.add(incident)
    await session.commit()
    await session.refresh(incident)

    assert incident.id == "INC-20260522-001"
    assert incident.status == "active"
    assert incident.alert_count == 15
    assert incident.symptom_count == 14


# ---------------------------------------------------------------------------
# 7. test_as_cache_insert_and_retrieve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_as_cache_insert_and_retrieve(session: AsyncSession):
    """Cache an AS lookup result and retrieve it (within 24h TTL)."""
    cached = await cache_as_lookup(
        session,
        asn=399077,
        name="TCLOUD Computing",
        as_type="IX-MLPE",
        source="peeringdb",
    )
    assert cached.asn == 399077
    assert cached.name == "TCLOUD Computing"

    retrieved = await get_cached_as(session, asn=399077)
    assert retrieved is not None
    assert retrieved.asn == 399077
    assert retrieved.name == "TCLOUD Computing"
    assert retrieved.as_type == "IX-MLPE"
    assert retrieved.source == "peeringdb"


# ---------------------------------------------------------------------------
# 8. test_as_cache_ttl_expired
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_as_cache_ttl_expired(session: AsyncSession):
    """AS entry cached >24h ago must not be returned (TTL expired)."""
    # Insert with an old timestamp (25 hours ago)
    old_time = datetime.now(tz=UTC) - timedelta(hours=25)
    stale = ASCache(
        asn=24482,
        name="SG.GS",
        as_type="IX-MLPE",
        source="peeringdb",
        cached_at=old_time,
    )
    session.add(stale)
    await session.commit()

    result = await get_cached_as(session, asn=24482)
    assert result is None, "Expired TTL entry must return None"


# ---------------------------------------------------------------------------
# 9. test_user_login_insert
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_login_insert(session: AsyncSession):
    """Insert a UserLogin record and verify all fields persist."""
    login = UserLogin(
        timestamp=datetime(2026, 5, 22, 21, 0, 31, tzinfo=UTC),
        device_name="BSCPLC-DHK-RTR-03",
        username="rancid",
        source_ip="192.168.200.56",
        vty="vty0",
        action="login",
        cipher="chacha20-poly1305@openssh.com",
    )
    session.add(login)
    await session.commit()
    await session.refresh(login)

    assert login.id is not None
    assert login.username == "rancid"
    assert login.action == "login"
    assert login.cipher == "chacha20-poly1305@openssh.com"
    assert login.vty == "vty0"


# ---------------------------------------------------------------------------
# 10. test_wal_mode_enabled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wal_mode_enabled(tmp_path):
    """WAL journal mode must be set on a file-backed SQLite database.

    In-memory SQLite always uses 'memory' journal mode; WAL requires a
    real file.  This test creates a temporary file DB and verifies that
    ``get_engine`` applies ``PRAGMA journal_mode=WAL`` via the connect event.
    """
    from sqlalchemy import text

    db_path = tmp_path / "test_wal.db"
    file_url = f"sqlite+aiosqlite:///{db_path}"

    _engine = await get_engine(file_url)
    await create_tables(_engine)

    async with _engine.connect() as conn:
        result = await conn.execute(text("PRAGMA journal_mode"))
        mode = result.scalar()

    await _engine.dispose()
    assert mode == "wal", f"Expected WAL mode on file DB, got: {mode}"
