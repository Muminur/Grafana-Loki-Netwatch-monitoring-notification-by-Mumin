"""Tests for DB persistence of maintenance windows, the hardware-noise toggle,
and correlator sequence seeding.

All tests use an in-memory SQLite engine (``sqlite+aiosqlite:///:memory:``) and
fully snapshot/restore every module-global they mutate so the test suite
remains isolated.

Coverage targets:
- Maintenance window create → persisted in DB AND in cache
- Maintenance window delete → removed from both DB and cache
- Hardware-noise toggle persists to DB
- Startup load (load_persisted_state) restores windows + toggle from DB
- Correlator seed_sequence raises the starting counter above the DB max
"""

# ruff: noqa: SLF001, ARG001, DTZ001
from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import src.api.routes as routes_mod
from src.core.correlator import CorrelationEngine
from src.database.models import AppSetting, Base

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def clean_stores() -> Iterator[None]:
    """Snapshot and restore all module-globals mutated by these tests."""
    orig_maint = list(routes_mod._maintenance_store)
    orig_counter = routes_mod._maintenance_id_counter
    orig_noise = routes_mod._hardware_defects_as_noise
    orig_engine = routes_mod._db_engine

    routes_mod._maintenance_store.clear()
    try:
        yield
    finally:
        routes_mod._maintenance_store.clear()
        routes_mod._maintenance_store.extend(orig_maint)
        routes_mod._maintenance_id_counter = orig_counter
        routes_mod._hardware_defects_as_noise = orig_noise
        routes_mod._db_engine = orig_engine


@pytest.fixture
async def async_db() -> AsyncIterator[Any]:
    """In-memory SQLite async engine with the full schema created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def http_client() -> AsyncClient:
    """httpx AsyncClient bound to the FastAPI app (no real server)."""
    from src.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# CRUD unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_maintenance_window_crud(async_db: Any) -> None:
    """create_maintenance_window persists a row and returns id-populated instance."""
    from src.database.crud import create_maintenance_window

    async with AsyncSession(async_db) as session:
        start = datetime(2030, 1, 1, 0, 0, 0)
        end = datetime(2030, 1, 1, 4, 0, 0)
        row = await create_maintenance_window(
            session,
            device_name="EQ-RTR-01",
            start_time=start,
            end_time=end,
            reason="Planned upgrade",
            created_by="noc-ops",
        )
        # Capture scalar values BEFORE commit() to avoid expired-attribute
        # access errors: commit() expires all loaded objects in the session.
        row_id = row.id
        row_device = row.device_name
        row_reason = row.reason
        row_created_by = row.created_by
        await session.commit()

    assert row_id is not None
    assert row_id > 0
    assert row_device == "EQ-RTR-01"
    assert row_reason == "Planned upgrade"
    assert row_created_by == "noc-ops"


@pytest.mark.asyncio
async def test_list_maintenance_windows_crud(async_db: Any) -> None:
    """crud.list_maintenance_windows returns all rows in start_time order."""
    from src.database.crud import create_maintenance_window, list_maintenance_windows

    async with AsyncSession(async_db) as session:
        await create_maintenance_window(
            session,
            "EQ-RTR-01",
            datetime(2030, 2, 1, 0, 0, 0),
            datetime(2030, 2, 1, 4, 0, 0),
        )
        await create_maintenance_window(
            session,
            "KKT-Core-01",
            datetime(2030, 1, 1, 0, 0, 0),
            datetime(2030, 1, 1, 2, 0, 0),
        )
        await session.commit()

    async with AsyncSession(async_db) as session:
        rows = await list_maintenance_windows(session)

    assert len(rows) == 2
    # Ordered by start_time ascending
    assert rows[0].device_name == "KKT-Core-01"
    assert rows[1].device_name == "EQ-RTR-01"


@pytest.mark.asyncio
async def test_delete_maintenance_window_crud(async_db: Any) -> None:
    """crud.delete_maintenance_window returns True and removes the row."""
    from src.database.crud import (
        create_maintenance_window,
        delete_maintenance_window,
        list_maintenance_windows,
    )

    async with AsyncSession(async_db) as session:
        row = await create_maintenance_window(
            session,
            "EQ-RTR-01",
            datetime(2030, 1, 1, 0, 0, 0),
            datetime(2030, 1, 1, 4, 0, 0),
        )
        # Capture id BEFORE commit() to avoid expired-attribute errors
        window_id = row.id
        await session.commit()

    async with AsyncSession(async_db) as session:
        deleted = await delete_maintenance_window(session, window_id)
        await session.commit()

    assert deleted is True

    async with AsyncSession(async_db) as session:
        rows = await list_maintenance_windows(session)
    assert len(rows) == 0


@pytest.mark.asyncio
async def test_delete_maintenance_window_not_found_returns_false(
    async_db: Any,
) -> None:
    """crud.delete_maintenance_window returns False for a nonexistent id."""
    from src.database.crud import delete_maintenance_window

    async with AsyncSession(async_db) as session:
        result = await delete_maintenance_window(session, 99999)
        await session.commit()

    assert result is False


@pytest.mark.asyncio
async def test_get_set_app_setting_crud(async_db: Any) -> None:
    """crud.get_app_setting / set_app_setting upsert and retrieve settings."""
    from src.database.crud import get_app_setting, set_app_setting

    async with AsyncSession(async_db) as session:
        # Not yet set — should return None
        val = await get_app_setting(session, "hardware_defects_as_noise")
        assert val is None

        # Insert
        await set_app_setting(session, "hardware_defects_as_noise", "true")
        await session.commit()

    async with AsyncSession(async_db) as session:
        val = await get_app_setting(session, "hardware_defects_as_noise")
    assert val == "true"


@pytest.mark.asyncio
async def test_set_app_setting_upsert(async_db: Any) -> None:
    """Calling set_app_setting twice updates rather than duplicating."""
    from src.database.crud import get_app_setting, set_app_setting

    async with AsyncSession(async_db) as session:
        await set_app_setting(session, "hardware_defects_as_noise", "true")
        await session.commit()

    async with AsyncSession(async_db) as session:
        await set_app_setting(session, "hardware_defects_as_noise", "false")
        await session.commit()

    async with AsyncSession(async_db) as session:
        val = await get_app_setting(session, "hardware_defects_as_noise")
        # Only one row, value updated
        from sqlalchemy import func, select

        count = (
            await session.execute(
                select(func.count(AppSetting.key)).where(
                    AppSetting.key == "hardware_defects_as_noise"
                )
            )
        ).scalar()

    assert val == "false"
    assert count == 1


# ---------------------------------------------------------------------------
# API endpoint write-through tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_maintenance_window_persisted_in_db_and_cache(
    http_client: AsyncClient,
    clean_stores: None,
    async_db: Any,
) -> None:
    """POST /api/maintenance → row in DB AND entry in _maintenance_store cache."""
    from src.database.crud import list_maintenance_windows

    routes_mod._db_engine = async_db

    async with http_client as client:
        resp = await client.post(
            "/api/maintenance",
            json={
                "device_name": "EQ-RTR-01",
                "start_time": "2030-06-01T00:00:00+00:00",
                "end_time": "2030-06-01T02:00:00+00:00",
                "reason": "Test upgrade",
                "created_by": "ops-test",
            },
        )

    assert resp.status_code == 201
    body = resp.json()
    assert body["device_name"] == "EQ-RTR-01"
    assert body["reason"] == "Test upgrade"
    assert isinstance(body["id"], int)
    created_id = body["id"]

    # In-memory cache must contain the new window
    in_cache = any(w["id"] == created_id for w in routes_mod._maintenance_store)
    assert in_cache, "Window not found in _maintenance_store"

    # DB must also have the row; capture ids inside the session to avoid
    # DetachedInstanceError when the session expires objects on close.
    async with AsyncSession(async_db) as session:
        rows = await list_maintenance_windows(session)
        db_ids = [r.id for r in rows]
    assert created_id in db_ids, "Window not found in DB"


@pytest.mark.asyncio
async def test_delete_maintenance_window_removed_from_db_and_cache(
    http_client: AsyncClient,
    clean_stores: None,
    async_db: Any,
) -> None:
    """DELETE /api/maintenance/{id} removes window from both DB and cache."""
    from src.database.crud import list_maintenance_windows

    routes_mod._db_engine = async_db

    # Create via API so DB + cache are both populated
    async with http_client as client:
        create_resp = await client.post(
            "/api/maintenance",
            json={
                "device_name": "KKT-Core-01",
                "start_time": "2030-07-01T00:00:00+00:00",
                "end_time": "2030-07-01T04:00:00+00:00",
                "reason": "Delete test",
                "created_by": "ops",
            },
        )
        assert create_resp.status_code == 201
        window_id = create_resp.json()["id"]

        del_resp = await client.delete(f"/api/maintenance/{window_id}")

    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "deleted"

    # Must be gone from cache
    assert not any(
        w["id"] == window_id for w in routes_mod._maintenance_store
    ), "Window still in _maintenance_store after delete"

    # Must be gone from DB; capture ids inside the session to avoid
    # DetachedInstanceError when the session expires objects on close.
    async with AsyncSession(async_db) as session:
        rows = await list_maintenance_windows(session)
        remaining_ids = [r.id for r in rows]
    assert window_id not in remaining_ids, "Window still in DB after delete"


@pytest.mark.asyncio
async def test_hardware_noise_toggle_persisted_to_db(
    clean_stores: None,
    async_db: Any,
) -> None:
    """POST /api/settings/hardware-noise persists the value to the app_setting table."""
    from src.database.crud import get_app_setting
    from src.main import app

    routes_mod._db_engine = async_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/api/settings/hardware-noise", params={"enabled": False}
        )

    assert resp.status_code == 200
    assert resp.json()["hardware_defects_as_noise"] is False
    assert routes_mod._hardware_defects_as_noise is False

    # DB must reflect the new value
    async with AsyncSession(async_db) as session:
        val = await get_app_setting(session, "hardware_defects_as_noise")
    assert val == "false"

    # Toggle back to True
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client2:
        resp2 = await client2.post(
            "/api/settings/hardware-noise", params={"enabled": True}
        )

    assert resp2.json()["hardware_defects_as_noise"] is True
    async with AsyncSession(async_db) as session:
        val2 = await get_app_setting(session, "hardware_defects_as_noise")
    assert val2 == "true"


# ---------------------------------------------------------------------------
# Startup load (load_persisted_state)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_load_persisted_state_restores_windows_and_toggle(
    clean_stores: None,
    async_db: Any,
) -> None:
    """load_persisted_state seeds _maintenance_store and _hardware_defects_as_noise."""
    from src.database.crud import (
        create_maintenance_window,
        set_app_setting,
    )

    # Seed DB with two windows and the toggle set to False
    async with AsyncSession(async_db) as session:
        await create_maintenance_window(
            session,
            "EQ-RTR-01",
            datetime(2030, 1, 1, 0, 0, 0),
            datetime(2030, 1, 1, 4, 0, 0),
            reason="Seeded 1",
        )
        await create_maintenance_window(
            session,
            "KKT-Core-01",
            datetime(2030, 2, 1, 0, 0, 0),
            datetime(2030, 2, 1, 2, 0, 0),
            reason="Seeded 2",
        )
        await set_app_setting(session, "hardware_defects_as_noise", "false")
        await session.commit()

    # Ensure in-memory cache starts empty and toggle is default (True)
    routes_mod._maintenance_store.clear()
    routes_mod._hardware_defects_as_noise = True  # default

    # Call the load function
    from src.api.routes import load_persisted_state

    await load_persisted_state(async_db)

    # Cache should now have 2 windows
    assert len(routes_mod._maintenance_store) == 2
    devices = {w["device_name"] for w in routes_mod._maintenance_store}
    assert devices == {"EQ-RTR-01", "KKT-Core-01"}

    # Toggle should be False (as stored)
    assert routes_mod._hardware_defects_as_noise is False


@pytest.mark.asyncio
async def test_load_persisted_state_default_toggle_when_not_set(
    clean_stores: None,
    async_db: Any,
) -> None:
    """load_persisted_state leaves noise toggle unchanged when key absent."""
    routes_mod._hardware_defects_as_noise = True  # default
    routes_mod._maintenance_store.clear()

    from src.api.routes import load_persisted_state

    await load_persisted_state(async_db)

    # Toggle unchanged (no DB row to override it)
    assert routes_mod._hardware_defects_as_noise is True
    assert len(routes_mod._maintenance_store) == 0


@pytest.mark.asyncio
async def test_load_persisted_state_tolerates_db_failure(
    clean_stores: None,
) -> None:
    """load_persisted_state logs and swallows DB failures gracefully."""
    from sqlalchemy.ext.asyncio import create_async_engine

    # Create a valid engine but immediately dispose it so any operation fails
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await engine.dispose()

    # Should not raise
    from src.api.routes import load_persisted_state

    await load_persisted_state(engine)


# ---------------------------------------------------------------------------
# Correlator sequence seeding
# ---------------------------------------------------------------------------


def test_correlator_seed_sequence_basic() -> None:
    """seed_sequence advances _incident_seq so the next ID exceeds the DB max."""
    engine = CorrelationEngine()
    engine.seed_sequence(5)
    # The next generated ID should be 006 (one above 005)
    inc_id = engine._generate_incident_id()
    # NNN part must be 6
    nnn = int(inc_id.split("-")[2])
    assert nnn == 6, f"Expected NNN=006 but got {inc_id}"


def test_correlator_seed_sequence_zero_is_noop() -> None:
    """seed_sequence(0) is a no-op; the first ID is 001."""
    engine = CorrelationEngine()
    engine.seed_sequence(0)
    inc_id = engine._generate_incident_id()
    nnn = int(inc_id.split("-")[2])
    assert nnn == 1


def test_correlator_seed_sequence_negative_is_noop() -> None:
    """seed_sequence with a negative value is a no-op."""
    engine = CorrelationEngine()
    engine.seed_sequence(-10)
    inc_id = engine._generate_incident_id()
    nnn = int(inc_id.split("-")[2])
    assert nnn == 1


def test_correlator_seed_sequence_never_decreases() -> None:
    """Calling seed_sequence with a smaller value than the current counter is safe."""
    engine = CorrelationEngine()
    # Generate 3 IDs to advance the counter to seq=3
    for _ in range(3):
        engine._generate_incident_id()
    # Attempt to seed below the current counter — should be a no-op
    engine.seed_sequence(1)
    next_id = engine._generate_incident_id()
    nnn = int(next_id.split("-")[2])
    assert nnn == 4, f"Expected NNN=004 but got {next_id}"


def test_correlator_seed_sequence_large_value() -> None:
    """Seeding with a large value produces the next ID one above it."""
    engine = CorrelationEngine()
    engine.seed_sequence(999)
    inc_id = engine._generate_incident_id()
    nnn = int(inc_id.split("-")[2])
    assert nnn == 1000


def test_correlator_seed_sequence_carries_correct_date() -> None:
    """The date component of the generated ID matches today's UTC date."""
    today = datetime.now(UTC).strftime("%Y%m%d")
    engine = CorrelationEngine()
    engine.seed_sequence(2)
    inc_id = engine._generate_incident_id()
    assert inc_id.startswith(f"INC-{today}-"), f"Wrong date in {inc_id}"


# ---------------------------------------------------------------------------
# E2E: maintenance and settings endpoints with startup-like DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_maintenance_lifecycle_with_db(
    clean_stores: None,
    async_db: Any,
) -> None:
    """Full maintenance lifecycle: create → list → delete → list confirms removal.

    This is the E2E driver for the maintenance persistence unit.  No real
    port binding — all via FastAPI TestClient.
    """
    from src.main import app

    routes_mod._db_engine = async_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Create
        create_resp = await client.post(
            "/api/maintenance",
            json={
                "device_name": "EQ-RTR-01",
                "start_time": "2030-08-01T00:00:00+00:00",
                "end_time": "2030-08-01T06:00:00+00:00",
                "reason": "E2E test",
                "created_by": "e2e",
            },
        )
        assert create_resp.status_code == 201
        created = create_resp.json()
        wid = created["id"]

        # List — must contain the new window
        list_resp = await client.get("/api/maintenance")
        assert list_resp.status_code == 200
        ids = [w["id"] for w in list_resp.json()]
        assert wid in ids

        # Delete
        del_resp = await client.delete(f"/api/maintenance/{wid}")
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "deleted"

        # List again — must not contain the deleted window
        list_resp2 = await client.get("/api/maintenance")
        ids2 = [w["id"] for w in list_resp2.json()]
        assert wid not in ids2


@pytest.mark.asyncio
async def test_e2e_startup_load_restores_windows(
    clean_stores: None,
    async_db: Any,
) -> None:
    """Simulated startup: seed DB, call load_persisted_state, verify caches."""
    from src.database.crud import create_maintenance_window, set_app_setting

    # Seed DB directly (simulating previously persisted state)
    async with AsyncSession(async_db) as session:
        await create_maintenance_window(
            session,
            "COX-Core-01",
            datetime(2030, 9, 1, 0, 0, 0),
            datetime(2030, 9, 1, 4, 0, 0),
            reason="E2E startup test",
        )
        await set_app_setting(session, "hardware_defects_as_noise", "false")
        await session.commit()

    # Simulate fresh startup: clear caches
    routes_mod._maintenance_store.clear()
    routes_mod._hardware_defects_as_noise = True

    from src.api.routes import load_persisted_state

    await load_persisted_state(async_db)

    # Verify restoration
    assert any(w["device_name"] == "COX-Core-01" for w in routes_mod._maintenance_store)
    assert routes_mod._hardware_defects_as_noise is False


@pytest.mark.asyncio
async def test_e2e_correlator_seeded_above_db_max(
    clean_stores: None,
    async_db: Any,
) -> None:
    """Correlator seeded so next ID exceeds the max already in DB for today."""
    from datetime import UTC

    from sqlalchemy import Integer, func, select
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.database.models import AlertLog

    today_str = datetime.now(UTC).strftime("%Y%m%d")
    inc_prefix = f"INC-{today_str}-%"

    # Seed three fake incident IDs in the DB for today
    async with AsyncSession(async_db) as session:
        for seq in (1, 2, 3):
            session.add(
                AlertLog(
                    timestamp=datetime.now(UTC),
                    source_ip="192.168.203.1",
                    device_name="EQ-RTR-01",
                    hostname="h",
                    facility="ROUTING",
                    severity_level=5,
                    mnemonic="ADJCHANGE",
                    message="test",
                    raw="r",
                    classification="CRITICAL",
                    incident_id=f"INC-{today_str}-{seq:03d}",
                )
            )
        await session.commit()

    # Query the max sequence as the lifespan does.
    # INC-YYYYMMDD-NNN: SUBSTR(incident_id, 14) extracts the NNN digits.
    async with AsyncSession(async_db) as session:
        seq_result = await session.execute(
            select(
                func.max(
                    func.cast(
                        func.substr(AlertLog.incident_id, 14),
                        Integer,
                    )
                )
            ).where(AlertLog.incident_id.like(inc_prefix))
        )
        max_seq = seq_result.scalar() or 0

    assert max_seq == 3

    # Seed a fresh correlator and verify the next ID is 004
    engine = CorrelationEngine()
    engine.seed_sequence(max_seq)
    next_id = engine._generate_incident_id()
    assert next_id == f"INC-{today_str}-004", f"Unexpected ID: {next_id}"


async def test_delete_db_failure_warns_and_still_returns_deleted(
    clean_stores: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failing DB delete must log a warning yet still report success.

    The in-memory cache is already updated, so the endpoint returns 200; the
    warning surfaces the DB/cache divergence (the row would otherwise silently
    reappear on the next startup reload).
    """
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    routes_mod.set_db_engine(engine)
    # Seed the in-memory cache so the window is "found" and 200 is returned.
    routes_mod._maintenance_store.append({"id": 4242, "device_name": "X"})

    async def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated DB delete failure")

    monkeypatch.setattr("src.database.crud.delete_maintenance_window", _boom)

    with caplog.at_level("WARNING"):
        result = await routes_mod.delete_maintenance_window(4242)

    await engine.dispose()
    assert result == {"status": "deleted", "id": 4242}
    assert any(
        "may reappear after a restart" in rec.getMessage() for rec in caplog.records
    )
