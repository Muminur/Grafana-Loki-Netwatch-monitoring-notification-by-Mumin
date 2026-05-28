"""Tests for Incident CRUD operations.

TDD approach: these tests are written FIRST (RED), then implementation makes them GREEN.
All tests use in-memory SQLite to avoid side effects.
Follows patterns established in tests/test_database.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.crud import (
    create_incident,
    get_alerts_by_incident,
    get_incident,
    get_incidents_by_status,
    insert_alert,
    update_incident,
)
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog

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
# 1. test_create_incident
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_incident(session: AsyncSession):
    """create_incident inserts a row and returns it with all fields populated."""
    inc = await create_incident(
        session,
        id="INC-20260522-001",
        title="EQ-RTR-01 BGP mass session drop",
        root_cause="Backhaul link failure on HundredGigE0/1/0/0",
        affected_devices='["BSCCL-EQ-RTR-01"]',
        affected_clients='["TCLOUD", "SG.GS"]',
        alert_count=15,
        status="active",
        created_at=datetime(2026, 5, 22, 19, 11, 4, tzinfo=UTC),
    )
    await session.commit()

    assert inc.id == "INC-20260522-001"
    assert inc.title == "EQ-RTR-01 BGP mass session drop"
    assert inc.root_cause == "Backhaul link failure on HundredGigE0/1/0/0"
    assert inc.affected_devices == '["BSCCL-EQ-RTR-01"]'
    assert inc.affected_clients == '["TCLOUD", "SG.GS"]'
    assert inc.alert_count == 15
    assert inc.status == "active"
    # SQLite stores datetimes as naive (strips tzinfo); compare face value
    expected_ts = datetime(2026, 5, 22, 19, 11, 4, tzinfo=UTC).replace(tzinfo=None)
    assert inc.created_at.replace(tzinfo=None) == expected_ts


# ---------------------------------------------------------------------------
# 2. test_get_incident
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incident(session: AsyncSession):
    """get_incident returns the incident by primary key."""
    await create_incident(
        session,
        id="INC-20260522-002",
        title="COX-Core-01 SFP alarm",
        root_cause="SFP module degradation",
        affected_devices='["COX-Core-01"]',
        affected_clients='["Client-A"]',
        alert_count=3,
        status="active",
        created_at=datetime(2026, 5, 22, 20, 0, 0, tzinfo=UTC),
    )
    await session.commit()

    fetched = await get_incident(session, "INC-20260522-002")
    assert fetched is not None
    assert fetched.id == "INC-20260522-002"
    assert fetched.title == "COX-Core-01 SFP alarm"
    assert fetched.alert_count == 3


# ---------------------------------------------------------------------------
# 3. test_get_incident_not_found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incident_not_found(session: AsyncSession):
    """get_incident returns None for a non-existent ID."""
    result = await get_incident(session, "INC-99990101-999")
    assert result is None


# ---------------------------------------------------------------------------
# 4. test_update_incident
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_incident(session: AsyncSession):
    """update_incident applies partial kwargs and returns the updated row."""
    await create_incident(
        session,
        id="INC-20260522-003",
        title="KKT-Core-1 link flap",
        root_cause="",
        affected_devices='["KKT-Core-1"]',
        affected_clients="[]",
        alert_count=1,
        status="active",
        created_at=datetime(2026, 5, 22, 18, 0, 0, tzinfo=UTC),
    )
    await session.commit()

    updated = await update_incident(
        session,
        "INC-20260522-003",
        alert_count=5,
        status="resolved",
        resolved_at=datetime(2026, 5, 22, 19, 0, 0, tzinfo=UTC),
    )
    await session.commit()

    assert updated is not None
    assert updated.alert_count == 5
    assert updated.status == "resolved"
    # SQLite stores datetimes as naive (strips tzinfo); compare face value
    assert updated.resolved_at is not None
    expected_resolved = datetime(2026, 5, 22, 19, 0, 0, tzinfo=UTC).replace(tzinfo=None)
    assert updated.resolved_at.replace(tzinfo=None) == expected_resolved

    # Verify via re-fetch
    refetched = await get_incident(session, "INC-20260522-003")
    assert refetched is not None
    assert refetched.alert_count == 5
    assert refetched.status == "resolved"


# ---------------------------------------------------------------------------
# 5. test_update_incident_not_found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_incident_not_found(session: AsyncSession):
    """update_incident returns None for a non-existent ID."""
    result = await update_incident(session, "INC-99990101-999", alert_count=10)
    assert result is None


# ---------------------------------------------------------------------------
# 6. test_get_incidents_by_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incidents_by_status(session: AsyncSession):
    """get_incidents_by_status filters by status and orders newest-first."""
    await create_incident(
        session,
        id="INC-20260522-010",
        title="Incident A",
        root_cause="",
        affected_devices="[]",
        affected_clients="[]",
        alert_count=1,
        status="active",
        created_at=datetime(2026, 5, 22, 10, 0, 0, tzinfo=UTC),
    )
    await create_incident(
        session,
        id="INC-20260522-011",
        title="Incident B",
        root_cause="",
        affected_devices="[]",
        affected_clients="[]",
        alert_count=2,
        status="resolved",
        created_at=datetime(2026, 5, 22, 11, 0, 0, tzinfo=UTC),
    )
    await create_incident(
        session,
        id="INC-20260522-012",
        title="Incident C",
        root_cause="",
        affected_devices="[]",
        affected_clients="[]",
        alert_count=3,
        status="active",
        created_at=datetime(2026, 5, 22, 12, 0, 0, tzinfo=UTC),
    )
    await session.commit()

    active = await get_incidents_by_status(session, "active")
    assert len(active) == 2
    # Newest first
    assert active[0].id == "INC-20260522-012"
    assert active[1].id == "INC-20260522-010"

    resolved = await get_incidents_by_status(session, "resolved")
    assert len(resolved) == 1
    assert resolved[0].id == "INC-20260522-011"


# ---------------------------------------------------------------------------
# 7. test_get_incidents_by_status_limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incidents_by_status_limit(session: AsyncSession):
    """get_incidents_by_status respects the limit parameter."""
    for i in range(5):
        await create_incident(
            session,
            id=f"INC-20260522-{20 + i:03d}",
            title=f"Incident {i}",
            root_cause="",
            affected_devices="[]",
            affected_clients="[]",
            alert_count=i,
            status="active",
            created_at=datetime(2026, 5, 22, 10 + i, 0, 0, tzinfo=UTC),
        )
    await session.commit()

    limited = await get_incidents_by_status(session, "active", limit=3)
    assert len(limited) == 3


# ---------------------------------------------------------------------------
# 8. test_get_alerts_by_incident
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_by_incident(session: AsyncSession):
    """get_alerts_by_incident returns AlertLog rows matching incident_id."""
    inc_id = "INC-20260522-030"
    # Create alerts linked to this incident
    alert1 = _make_alert(incident_id=inc_id, mnemonic="ADJCHANGE")
    alert2 = _make_alert(incident_id=inc_id, mnemonic="MAXPFX")
    # Create an alert for a different incident
    alert3 = _make_alert(incident_id="INC-20260522-099", mnemonic="SFPALARM")
    # Create an alert with no incident
    alert4 = _make_alert(incident_id=None, mnemonic="SSH_LOGIN")

    for a in [alert1, alert2, alert3, alert4]:
        await insert_alert(session, a)
    await session.commit()

    results = await get_alerts_by_incident(session, inc_id)
    assert len(results) == 2
    mnemonics = {r.mnemonic for r in results}
    assert mnemonics == {"ADJCHANGE", "MAXPFX"}


# ---------------------------------------------------------------------------
# 9. test_get_alerts_by_incident_limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_by_incident_limit(session: AsyncSession):
    """get_alerts_by_incident respects the limit parameter."""
    inc_id = "INC-20260522-040"
    for i in range(10):
        alert = _make_alert(
            incident_id=inc_id,
            mnemonic=f"EVT{i:02d}",
            timestamp=datetime(2026, 5, 22, 15, i, 0, tzinfo=UTC),
        )
        await insert_alert(session, alert)
    await session.commit()

    results = await get_alerts_by_incident(session, inc_id, limit=5)
    assert len(results) == 5


# ---------------------------------------------------------------------------
# 10. test_get_alerts_by_incident_empty
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_by_incident_empty(session: AsyncSession):
    """get_alerts_by_incident returns empty list when no alerts match."""
    results = await get_alerts_by_incident(session, "INC-99990101-999")
    assert results == []


# ---------------------------------------------------------------------------
# 11. test_update_incident_increment_symptom_count
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_incident_increment_symptom_count(session: AsyncSession):
    """update_incident can increment symptom_count for symptom events."""
    await create_incident(
        session,
        id="INC-20260522-050",
        title="Mass BGP drop",
        root_cause="Bundle-Ether10 down",
        affected_devices='["BSCCL-EQ-RTR-01"]',
        affected_clients="[]",
        alert_count=1,
        status="active",
        created_at=datetime(2026, 5, 22, 15, 0, 0, tzinfo=UTC),
    )
    await session.commit()

    # Simulate incrementing counts as symptom events arrive
    inc = await get_incident(session, "INC-20260522-050")
    assert inc is not None
    new_count = inc.alert_count + 1
    new_symptom = inc.symptom_count + 1
    updated = await update_incident(
        session,
        "INC-20260522-050",
        alert_count=new_count,
        symptom_count=new_symptom,
    )
    await session.commit()

    assert updated is not None
    assert updated.alert_count == 2
    assert updated.symptom_count == 1
