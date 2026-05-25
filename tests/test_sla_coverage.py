"""SLA edge-case tests for BSCCL NetWatch.

Covers:
  1. Zero incidents for a client -> 100% uptime.
  2. Empty-string ``affected_clients`` JSON -> not matched.
  3. Malformed (non-JSON) ``affected_clients`` -> not matched (no crash).
  4. Client not in the affected_clients list -> excluded from SLA.

All tests use an in-memory SQLite database via pytest-asyncio fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.migrations import create_tables, get_engine
from src.database.models import Incident
from src.statistics.sla import _client_in_incident, calculate_client_sla

# ---------------------------------------------------------------------------
# Shared fixtures
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


# ---------------------------------------------------------------------------
# 1. Zero incidents for a client -> 100% uptime
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_zero_incidents_returns_perfect_uptime(
    session: AsyncSession,
) -> None:
    """A client with zero incidents has 100% uptime, 0 MTBF, 0 MTTR."""
    sla = await calculate_client_sla(session, "NoIncidentClient", days=30)

    assert sla.client_name == "NoIncidentClient"
    assert sla.uptime_percent == 100.0
    assert sla.mtbf_hours == 0.0
    assert sla.mttr_minutes == 0.0
    assert sla.incidents_count == 0


# ---------------------------------------------------------------------------
# 2. affected_clients is an empty string ""
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_empty_string_affected_clients(session: AsyncSession) -> None:
    """An incident with affected_clients='' does not match any client."""
    now = datetime.now(UTC)
    incident = Incident(
        id="INC-20260525-001",
        title="Test outage with empty clients",
        root_cause="Cable cut",
        affected_clients="",  # empty string
        affected_devices="[]",
        alert_count=1,
        symptom_count=0,
        status="resolved",
        created_at=now - timedelta(hours=6),
        resolved_at=now - timedelta(hours=5),
    )
    session.add(incident)
    await session.flush()

    sla = await calculate_client_sla(session, "SomeClient", days=1)

    # No incidents should match
    assert sla.uptime_percent == 100.0
    assert sla.incidents_count == 0


# ---------------------------------------------------------------------------
# 3. affected_clients is malformed JSON (not parseable)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_malformed_json_affected_clients(session: AsyncSession) -> None:
    """An incident with unparseable affected_clients JSON does not crash SLA."""
    now = datetime.now(UTC)
    incident = Incident(
        id="INC-20260525-002",
        title="Test outage with bad JSON",
        root_cause="Unknown",
        affected_clients="not-json",  # malformed
        affected_devices="[]",
        alert_count=1,
        symptom_count=0,
        status="resolved",
        created_at=now - timedelta(hours=4),
        resolved_at=now - timedelta(hours=3),
    )
    session.add(incident)
    await session.flush()

    sla = await calculate_client_sla(session, "AnyClient", days=1)

    # Malformed JSON is silently skipped -- client not matched
    assert sla.uptime_percent == 100.0
    assert sla.incidents_count == 0


# ---------------------------------------------------------------------------
# 4. affected_clients is a valid JSON empty list "[]"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_empty_list_affected_clients(session: AsyncSession) -> None:
    """An incident with affected_clients='[]' matches no clients."""
    now = datetime.now(UTC)
    incident = Incident(
        id="INC-20260525-003",
        title="Test outage with empty list",
        root_cause="Power failure",
        affected_clients="[]",  # valid JSON, empty list
        affected_devices="[]",
        alert_count=1,
        symptom_count=0,
        status="resolved",
        created_at=now - timedelta(hours=2),
        resolved_at=now - timedelta(hours=1),
    )
    session.add(incident)
    await session.flush()

    sla = await calculate_client_sla(session, "GhostClient", days=1)

    assert sla.uptime_percent == 100.0
    assert sla.incidents_count == 0


# ---------------------------------------------------------------------------
# 5. _client_in_incident helper: direct unit tests
# ---------------------------------------------------------------------------


def test_client_in_incident_valid_json() -> None:
    """_client_in_incident returns True when client is in the JSON list."""
    assert _client_in_incident("BSCCL", '["BSCCL", "Other"]') is True


def test_client_in_incident_not_present() -> None:
    """_client_in_incident returns False when client is not in the list."""
    assert _client_in_incident("Missing", '["BSCCL", "Other"]') is False


def test_client_in_incident_empty_string() -> None:
    """_client_in_incident returns False for empty string input."""
    assert _client_in_incident("AnyClient", "") is False


def test_client_in_incident_malformed_json() -> None:
    """_client_in_incident returns False for non-JSON input (no crash)."""
    assert _client_in_incident("Client", "not-json") is False


def test_client_in_incident_none_input() -> None:
    """_client_in_incident returns False for None input."""
    assert _client_in_incident("Client", None) is False  # type: ignore[arg-type]


def test_client_in_incident_json_object_not_list() -> None:
    """_client_in_incident returns False for a JSON object (not a list)."""
    # json.loads('{"a":1}') yields a dict; "Client" in dict checks keys
    assert _client_in_incident("Client", '{"a": 1}') is False


# ---------------------------------------------------------------------------
# 6. Multiple incidents for one client -> correct MTBF
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_multiple_incidents_mtbf(session: AsyncSession) -> None:
    """Two incidents over 30 days -> MTBF = 30*24/2 = 360 hours."""
    now = datetime.now(UTC)
    for i in range(2):
        incident = Incident(
            id=f"INC-20260525-10{i}",
            title=f"Outage {i}",
            root_cause="Test",
            affected_clients='["MTBFClient"]',
            affected_devices="[]",
            alert_count=1,
            symptom_count=0,
            status="resolved",
            created_at=now - timedelta(days=10 * (i + 1)),
            resolved_at=now - timedelta(days=10 * (i + 1)) + timedelta(minutes=30),
        )
        session.add(incident)
    await session.flush()

    sla = await calculate_client_sla(session, "MTBFClient", days=30)

    assert sla.incidents_count == 2
    assert sla.mtbf_hours == 360.0  # 30 * 24 / 2
    assert sla.mttr_minutes == 30.0  # each incident lasted 30 min
