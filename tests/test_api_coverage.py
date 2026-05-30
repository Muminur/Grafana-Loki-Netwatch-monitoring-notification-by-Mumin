"""Additional coverage tests for src/api/routes.py.

Targets the error/edge branches and helper functions that the primary
``tests/test_api.py`` suite leaves uncovered: helper extractors,
``build_incident_title`` branches, DB-backed alert/incident endpoints,
the BGP-UP DB-persistence task path, and various found/not-found and
filter permutations.

All external I/O is mocked or backed by an in-memory SQLite engine; the
real ``bsccl_netwatch.db`` is never touched. Any mutation of the module's
in-memory stores or the registered DB engine is restored in a finally
block or fixture teardown so other tests are unaffected.
"""

# This test module deliberately reaches into src.api.routes private internals
# (helpers, in-memory stores, module flags) to drive uncovered branches, uses
# fixtures for their side effects, and constructs naive datetimes to match how
# SQLite persists timestamps. Suppress the corresponding lint rules file-wide.
# ruff: noqa: SLF001, ARG001, DTZ001
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import src.api.routes as routes_mod
from src.database.models import AlertLog, Base

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def client() -> AsyncClient:
    """An httpx AsyncClient bound to the FastAPI app (no real server)."""
    from src.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def clean_stores() -> Iterator[None]:
    """Snapshot and restore all in-memory stores + module flags.

    Ensures any test that mutates ``_alerts_store`` / ``_incidents_store`` /
    ``_maintenance_store`` / counters / the noise toggle / the DB engine
    leaves global state exactly as it found it.
    """
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    orig_incidents = list(routes_mod._incidents_store)  # noqa: SLF001
    orig_maint = list(routes_mod._maintenance_store)  # noqa: SLF001
    orig_counter = routes_mod._maintenance_id_counter  # noqa: SLF001
    orig_noise = routes_mod._hardware_defects_as_noise  # noqa: SLF001
    orig_engine = routes_mod._db_engine  # noqa: SLF001

    routes_mod._alerts_store.clear()  # noqa: SLF001
    routes_mod._incidents_store.clear()  # noqa: SLF001
    routes_mod._maintenance_store.clear()  # noqa: SLF001
    try:
        yield
    finally:
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_incidents)  # noqa: SLF001
        routes_mod._maintenance_store.clear()  # noqa: SLF001
        routes_mod._maintenance_store.extend(orig_maint)  # noqa: SLF001
        routes_mod._maintenance_id_counter = orig_counter  # noqa: SLF001
        routes_mod._hardware_defects_as_noise = orig_noise  # noqa: SLF001
        routes_mod._db_engine = orig_engine  # noqa: SLF001


@pytest.fixture
async def async_db() -> AsyncIterator[Any]:
    """In-memory SQLite async engine with the schema created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


def _make_enriched(
    *,
    device_name: str,
    source_ip: str,
    mnemonic: str,
    message: str,
    interface_name: str = "",
    bgp_neighbor: str = "",
    as_number: int | None = 0,
    as_name: str = "",
    classification: str = "CRITICAL",
    rule_id: str = "",
    client_name: str = "",
) -> MagicMock:
    enriched = MagicMock()
    enriched.device_name = device_name
    enriched.interface_name = interface_name
    enriched.interface_description = ""
    enriched.bgp_neighbor = bgp_neighbor
    enriched.as_number = as_number
    enriched.as_name = as_name
    enriched.classification = classification
    enriched.event_type = ""
    enriched.client_name = client_name
    enriched.vrf = ""
    enriched.rule_id = rule_id
    enriched.parsed = MagicMock()
    enriched.parsed.source_ip = source_ip
    enriched.parsed.mnemonic = mnemonic
    enriched.parsed.message = message
    enriched.parsed.hostname = device_name
    enriched.parsed.facility = "PLATFORM"
    enriched.parsed.timestamp = MagicMock()
    enriched.parsed.timestamp.isoformat.return_value = "2026-05-23T16:22:56"
    return enriched


def _make_correlated(
    *,
    incident_id: str = "",
    is_symptom: bool = False,
    is_flapping: bool = False,
) -> MagicMock:
    correlated = MagicMock()
    correlated.incident_id = incident_id
    correlated.is_symptom = is_symptom
    correlated.is_flapping = is_flapping
    correlated.suppress_notification = False
    return correlated


# ---------------------------------------------------------------------------
# Helper-function unit tests (lines 78, 111-132, 152-191)
# ---------------------------------------------------------------------------


def test_is_recovery_event_active_always() -> None:
    """ACTIVE mnemonic without 'no longer' is a recovery event (line 78)."""
    assert routes_mod._is_recovery_event("ACTIVE", "is Active part of Bundle") is True


def test_is_recovery_event_active_down_is_not_recovery() -> None:
    """ACTIVE with 'no longer' (bundle down) is NOT a recovery event."""
    assert (
        routes_mod._is_recovery_event("ACTIVE", "no longer Active as part of") is False
    )


def test_is_recovery_event_updown_up() -> None:
    """UPDOWN with 'Up' in message is a recovery (line 79-81)."""
    assert routes_mod._is_recovery_event("UPDOWN", "changed state to Up") is True


def test_is_recovery_event_rule_id_shortcut() -> None:
    """A recovery rule_id returns True regardless of mnemonic (line 75-76)."""
    assert routes_mod._is_recovery_event("ANY", "anything", rule_id="BGP_UP") is True


def test_is_recovery_event_non_recovery() -> None:
    """A plain Down event is not a recovery event."""
    assert routes_mod._is_recovery_event("UPDOWN", "changed state to Down") is False


def test_extract_bundle_from_msg() -> None:
    """Bundle is extracted and shortened (lines 111-112)."""
    assert (
        routes_mod._extract_bundle_from_msg("part of Bundle-Ether201 (Link)") == "BE201"
    )
    assert routes_mod._extract_bundle_from_msg("no bundle here") == ""


def test_extract_bgp_state_all_branches() -> None:
    """Flap / DOWN / UP / empty branches (lines 116-122)."""
    assert routes_mod._extract_bgp_state("Interface flap detected") == "Flap"
    assert routes_mod._extract_bgp_state("neighbor X Down - reason") == "DOWN"
    assert routes_mod._extract_bgp_state("neighbor X Up (VRF)") == "UP"
    assert routes_mod._extract_bgp_state("steady state") == ""


def test_extract_fault_type_all_branches() -> None:
    """Local+Remote / Local / Remote / generic fault (lines 126-132)."""
    assert (
        routes_mod._extract_fault_type("Detected Local Fault and Remote Fault")
        == "Local+Remote Fault"
    )
    assert routes_mod._extract_fault_type("Detected Local Fault") == "Local Fault"
    assert routes_mod._extract_fault_type("Detected Remote Fault") == "Remote Fault"
    assert routes_mod._extract_fault_type("Detected something else") == "Fault"


def test_build_incident_title_active_bundle_up() -> None:
    """ACTIVE → 'Bundle ACTIVE' with iface + bundle (lines 152-160)."""
    title = routes_mod.build_incident_title(
        mnemonic="ACTIVE",
        device_name="KKT-Core-2",
        message="TenGigE0/0/1/7 is Active as part of Bundle-Ether201",
        interface_name="TenGigE0/0/1/7",
    )
    assert title == "Bundle ACTIVE — KKT-Core-2, TGE0/0/1/7, BE201"


def test_build_incident_title_active_bundle_down() -> None:
    """ACTIVE with 'no longer' → 'Bundle DOWN' label."""
    title = routes_mod.build_incident_title(
        mnemonic="ACTIVE",
        device_name="KKT-Core-2",
        message="TenGigE0/0/1/7 is no longer Active as part of Bundle-Ether201",
        interface_name="TenGigE0/0/1/7",
    )
    assert title.startswith("Bundle DOWN — KKT-Core-2")
    assert "BE201" in title


def test_build_incident_title_adjchange_with_state_and_as() -> None:
    """ADJCHANGE → device + state + AS name (lines 162-169)."""
    title = routes_mod.build_incident_title(
        mnemonic="ADJCHANGE",
        device_name="KKT-Core-3",
        message="neighbor X Down - reason",
        as_name="Orange",
    )
    assert title == "ADJCHANGE — KKT-Core-3 DOWN - Orange"


def test_build_incident_title_adjchange_no_state_no_as() -> None:
    """ADJCHANGE with neither extractable state nor AS name."""
    title = routes_mod.build_incident_title(
        mnemonic="ADJCHANGE",
        device_name="KKT-Core-3",
        message="steady neighbor message",
    )
    assert title == "ADJCHANGE — KKT-Core-3"


def test_build_incident_title_rx_fault() -> None:
    """RX_FAULT → RXFault-<device> - <iface> - <fault> (lines 171-177)."""
    title = routes_mod.build_incident_title(
        mnemonic="RX_FAULT",
        device_name="KKT-Core-1",
        message="Interface TenGigE0/0/0/2, Detected Local Fault",
        interface_name="TenGigE0/0/0/2",
    )
    assert title == "RXFault-KKT-Core-1 - TGE0/0/0/2 - Local Fault"


def test_build_incident_title_updown_with_state() -> None:
    """UPDOWN → mnemonic + state + iface (lines 179-186)."""
    title = routes_mod.build_incident_title(
        mnemonic="UPDOWN",
        device_name="DHK-Core-3",
        message="Interface TenGigE0/0/0/0, changed state to Down",
        interface_name="TenGigE0/0/0/0",
    )
    assert title == "UPDOWN — DHK-Core-3 Down - TGE0/0/0/0"


def test_build_incident_title_lineproto_up_no_iface() -> None:
    """LINEPROTO 'Up' with no interface name exercises the Up branch."""
    title = routes_mod.build_incident_title(
        mnemonic="LINEPROTO",
        device_name="DHK-Core-3",
        message="Line protocol changed state to Up",
    )
    assert title == "LINEPROTO — DHK-Core-3 Up"


def test_build_incident_title_default_branch() -> None:
    """Unknown mnemonic → generic '<mnemonic> — <device>, <iface>' (188-191)."""
    title = routes_mod.build_incident_title(
        mnemonic="MAXPFX",
        device_name="EQ-RTR-01",
        message="prefixes reached",
        interface_name="TenGigE0/0/0/1",
    )
    assert title == "MAXPFX — EQ-RTR-01, TGE0/0/0/1"


# ---------------------------------------------------------------------------
# Module-level setters (lines 267, 273, 278) + maintenance accessor
# ---------------------------------------------------------------------------


def test_set_alerts_processed_and_increment(clean_stores: None) -> None:
    """_set_alerts_processed and increment_alerts_processed mutate counter."""
    orig = routes_mod._alerts_processed  # noqa: SLF001
    try:
        routes_mod._set_alerts_processed(42)  # noqa: SLF001
        assert routes_mod._alerts_processed == 42  # noqa: SLF001
        routes_mod.increment_alerts_processed()
        assert routes_mod._alerts_processed == 43  # noqa: SLF001
    finally:
        routes_mod._set_alerts_processed(orig)  # noqa: SLF001


def test_set_active_connections(clean_stores: None) -> None:
    """set_active_connections updates the module counter (line 273)."""
    orig = routes_mod._active_connections  # noqa: SLF001
    try:
        routes_mod.set_active_connections(7)
        assert routes_mod._active_connections == 7  # noqa: SLF001
    finally:
        routes_mod.set_active_connections(orig)


def test_add_alert_appends(clean_stores: None) -> None:
    """add_alert appends a raw dict to the store (line 278)."""
    routes_mod.add_alert({"id": 1, "classification": "INFO"})
    assert routes_mod._alerts_store[-1]["id"] == 1  # noqa: SLF001


def test_get_maintenance_store_returns_list(clean_stores: None) -> None:
    """get_maintenance_store returns the live list object."""
    assert (
        routes_mod.get_maintenance_store() is routes_mod._maintenance_store
    )  # noqa: SLF001


# ---------------------------------------------------------------------------
# MaintenanceWindowCreate validator (lines 253-254)
# ---------------------------------------------------------------------------


def test_maintenance_window_end_before_start_raises() -> None:
    """end_time <= start_time raises a validation error (lines 253-254)."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        routes_mod.MaintenanceWindowCreate(
            device_name="EQ-RTR-01",
            start_time=datetime(2026, 6, 1, 4, 0, tzinfo=UTC),
            end_time=datetime(2026, 6, 1, 2, 0, tzinfo=UTC),
        )


# ---------------------------------------------------------------------------
# _period_to_time_range (lines 499-517)
# ---------------------------------------------------------------------------


def test_period_to_time_range_all_branches() -> None:
    """Every recognised period plus 'all'/None/unknown (lines 499-517)."""
    assert routes_mod._period_to_time_range(None) == (None, None)
    assert routes_mod._period_to_time_range("all") == (None, None)
    assert routes_mod._period_to_time_range("bogus") == (None, None)

    today_start, today_end = routes_mod._period_to_time_range("today")
    assert today_start is not None
    assert today_end is None

    y_start, y_end = routes_mod._period_to_time_range("yesterday")
    assert y_start is not None
    assert y_end is not None
    assert y_start < y_end

    for period in ("7d", "30d", "1y"):
        start, end = routes_mod._period_to_time_range(period)
        assert start is not None
        assert end is None


# ---------------------------------------------------------------------------
# /api/alerts — in-memory device filter (line 561) + pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_in_memory_device_filter(
    client: AsyncClient, clean_stores: None
) -> None:
    """device= filter on the in-memory fallback path (line 561)."""
    routes_mod._db_engine = None  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"id": 1, "classification": "CRITICAL", "device": "EQ-RTR-01"}
    )
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"id": 2, "classification": "WARNING", "device": "KKT-Core-1"}
    )
    async with client as c:
        resp = await c.get("/api/alerts", params={"device": "EQ-RTR-01"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["device"] == "EQ-RTR-01"


@pytest.mark.asyncio
async def test_get_alerts_in_memory_severity_and_pagination(
    client: AsyncClient, clean_stores: None
) -> None:
    """severity filter + offset/limit slice on the in-memory path."""
    routes_mod._db_engine = None  # noqa: SLF001
    for i in range(5):
        routes_mod._alerts_store.append(  # noqa: SLF001
            {"id": i, "classification": "CRITICAL", "device": "EQ-RTR-01"}
        )
    async with client as c:
        resp = await c.get(
            "/api/alerts",
            params={"severity": "critical", "limit": 2, "offset": 1},
        )
    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_get_alerts_invalid_limit_returns_422(
    client: AsyncClient,
) -> None:
    """limit above the allowed max → 422 validation error."""
    async with client as c:
        resp = await c.get("/api/alerts", params={"limit": 99999})
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /api/alerts — DB-backed path (lines 564-587)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_db_backed_with_filters(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """DB path with severity + device + period filters (lines 564-587)."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    # Recent (yesterday) timestamp so the alert is always inside the "7d" window
    # regardless of the time of day the suite runs — a fixed past date drifts
    # out of the window as wall-clock time advances.
    bdt_now = datetime.now(routes_mod._BDT).replace(tzinfo=None)  # noqa: SLF001
    recent_ts = bdt_now - timedelta(days=1)
    async with AsyncSession(async_db) as session:
        session.add(
            AlertLog(
                timestamp=recent_ts,
                source_ip="192.168.203.1",
                device_name="EQ-RTR-01",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="neighbor X Down",
                raw="raw",
                classification="CRITICAL",
                interface_name="TenGigE0/0/0/0",
            )
        )
        await session.commit()

    async with client as c:
        resp = await c.get(
            "/api/alerts",
            params={"severity": "CRITICAL", "device": "EQ-RTR-01", "period": "7d"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["device"] == "EQ-RTR-01"
    assert body[0]["classification"] == "CRITICAL"


@pytest.mark.asyncio
async def test_get_alerts_db_backed_yesterday_period(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """'yesterday' applies both start and end bounds (line 580-581)."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/alerts", params={"period": "yesterday"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ---------------------------------------------------------------------------
# /api/alerts/count — in-memory + DB (lines 634-636, 643-667)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alerts_count_in_memory(
    client: AsyncClient, clean_stores: None
) -> None:
    """Count from in-memory store (lines 634-636)."""
    routes_mod._db_engine = None  # noqa: SLF001
    routes_mod._alerts_store.append({"classification": "CRITICAL"})  # noqa: SLF001
    routes_mod._alerts_store.append({"classification": "CRITICAL"})  # noqa: SLF001
    routes_mod._alerts_store.append({"classification": "WARNING"})  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/alerts/count", params={"period": "all"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["CRITICAL"] == 2
    assert body["counts"]["WARNING"] == 1
    assert body["total"] == 3


@pytest.mark.asyncio
async def test_get_alerts_count_db_backed(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """Count grouped by classification from the DB (lines 643-667)."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    async with AsyncSession(async_db) as session:
        for cls in ("CRITICAL", "CRITICAL", "INFO"):
            session.add(
                AlertLog(
                    timestamp=datetime(2026, 5, 23, 12, 0, 0),
                    source_ip="192.168.203.1",
                    device_name="EQ-RTR-01",
                    hostname="h",
                    facility="ROUTING",
                    severity_level=5,
                    mnemonic="ADJCHANGE",
                    message="m",
                    raw="r",
                    classification=cls,
                )
            )
        await session.commit()

    async with client as c:
        resp = await c.get("/api/alerts/count", params={"period": "all"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["CRITICAL"] == 2
    assert body["counts"]["INFO"] == 1
    assert body["total"] == 3


@pytest.mark.asyncio
async def test_get_alerts_count_db_backed_with_period_bounds(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """Count with a bounded period applies start+end where clauses (655, 657, 660)."""
    from datetime import timedelta

    routes_mod._db_engine = async_db  # noqa: SLF001
    # 'yesterday' yields BDT-naive start AND end bounds; seed a row inside it.
    bdt_now = datetime.now(routes_mod._BDT).replace(tzinfo=None)  # noqa: SLF001
    yesterday_noon = (bdt_now - timedelta(days=1)).replace(
        hour=12, minute=0, second=0, microsecond=0
    )
    async with AsyncSession(async_db) as session:
        session.add(
            AlertLog(
                timestamp=yesterday_noon,
                source_ip="192.168.203.1",
                device_name="EQ-RTR-01",
                hostname="h",
                facility="ROUTING",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="m",
                raw="r",
                classification="WARNING",
            )
        )
        await session.commit()

    async with client as c:
        resp = await c.get("/api/alerts/count", params={"period": "yesterday"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["period"] == "yesterday"
    assert body["counts"]["WARNING"] == 1


# ---------------------------------------------------------------------------
# /api/alerts/{id} found (lines 689-690)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_alert_by_id_found(client: AsyncClient, clean_stores: None) -> None:
    """Existing alert id returns the alert dict (lines 689-690)."""
    routes_mod._alerts_store.append(  # noqa: SLF001
        {"id": 555, "classification": "CRITICAL", "device": "EQ-RTR-01"}
    )
    async with client as c:
        resp = await c.get("/api/alerts/555")
    assert resp.status_code == 200
    assert resp.json()["id"] == 555


# ---------------------------------------------------------------------------
# /api/incidents — store path (708) + DB synthesis (727, 739-764)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incidents_from_store(
    client: AsyncClient, clean_stores: None
) -> None:
    """Non-empty store is returned directly (line 708)."""
    routes_mod._incidents_store.append({"id": "INC-1", "title": "x"})  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/incidents")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["id"] == "INC-1"


@pytest.mark.asyncio
async def test_get_incidents_db_synthesis_and_resolution(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """Empty store + DB rows → synthesised incidents with recovery filtering.

    Exercises lines 727, 739-743, 749, 752-754, 757, 761-764: the recovery
    detection first pass (BGP ADJCHANGE Up resolving a Down, and an
    INTF Up resolving an interface fault), the dedup/alert_count merge, and
    the silent-fault exclusion clause.
    """
    routes_mod._db_engine = async_db  # noqa: SLF001
    # Disable noise toggle so silent-fault exclusion clause (727) is the only
    # filter we rely on for RX_FAULT — but we deliberately keep one to ensure
    # the ~mnemonic.in_ clause is hit. Toggle ON exercises line 727.
    routes_mod._hardware_defects_as_noise = True  # noqa: SLF001

    base = datetime(2026, 5, 23, 12, 0, 0)
    rows = [
        # BGP Down on AS 9077 that is NEVER cleared → stays active and forces the
        # unresolved-ADJCHANGE discriminator branch (lines 751-754).
        AlertLog(
            timestamp=base,
            source_ip="192.168.203.1",
            device_name="EQ-RTR-01",
            hostname="h",
            facility="ROUTING",
            severity_level=5,
            mnemonic="ADJCHANGE",
            message="neighbor Y Down - reason (AS: 9077)",
            raw="r",
            classification="CRITICAL",
            as_number=9077,
            as_name="TCLOUD",
        ),
        # BGP Down on AS 24482, later an Up on same AS → resolved (lines 740-741)
        AlertLog(
            timestamp=base,
            source_ip="192.168.203.1",
            device_name="EQ-RTR-01",
            hostname="h",
            facility="ROUTING",
            severity_level=5,
            mnemonic="ADJCHANGE",
            message="neighbor X Down - reason (AS: 24482)",
            raw="r",
            classification="CRITICAL",
            as_number=24482,
            as_name="SG.GS",
        ),
        AlertLog(
            timestamp=base.replace(minute=5),
            source_ip="192.168.203.1",
            device_name="EQ-RTR-01",
            hostname="h",
            facility="ROUTING",
            severity_level=5,
            mnemonic="ADJCHANGE",
            message="neighbor X Up (AS: 24482)",
            raw="r",
            classification="CRITICAL",
            as_number=24482,
            as_name="SG.GS",
        ),
        # An interface UPDOWN Down that stays active, plus a duplicate to bump
        # alert_count via the seen-key path (lines 761-764).
        AlertLog(
            timestamp=base.replace(minute=1),
            source_ip="192.168.200.11",
            device_name="DHK-Core-3",
            hostname="h",
            facility="PKT_INFRA",
            severity_level=3,
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/9, changed state to Down",
            raw="r",
            classification="CRITICAL",
            interface_name="TenGigE0/0/0/9",
        ),
        AlertLog(
            timestamp=base.replace(minute=2),
            source_ip="192.168.200.11",
            device_name="DHK-Core-3",
            hostname="h",
            facility="PKT_INFRA",
            severity_level=3,
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/9, changed state to Down",
            raw="r",
            classification="CRITICAL",
            interface_name="TenGigE0/0/0/9",
        ),
        # An interface fault later cleared by an Up on the SAME iface → resolved
        # via the iface discriminator branch (lines 742-743, 756-757).
        AlertLog(
            timestamp=base.replace(minute=3),
            source_ip="192.168.200.11",
            device_name="DHK-Core-3",
            hostname="h",
            facility="PKT_INFRA",
            severity_level=3,
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/4, changed state to Down",
            raw="r",
            classification="CRITICAL",
            interface_name="TenGigE0/0/0/4",
        ),
        AlertLog(
            timestamp=base.replace(minute=6),
            source_ip="192.168.200.11",
            device_name="DHK-Core-3",
            hostname="h",
            facility="PKT_INFRA",
            severity_level=3,
            mnemonic="UPDOWN",
            message="Interface TenGigE0/0/0/4, changed state to Up",
            raw="r",
            classification="CRITICAL",
            interface_name="TenGigE0/0/0/4",
        ),
    ]
    async with AsyncSession(async_db) as session:
        session.add_all(rows)
        await session.commit()

    async with client as c:
        resp = await c.get("/api/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    adjchange = [i for i in incidents if i["mnemonic"] == "ADJCHANGE"]
    # The unresolved BGP-down (AS 9077) appears via the AS discriminator branch.
    assert any(i["as_name"] == "TCLOUD" for i in adjchange)
    # The resolved BGP session (AS 24482) must NOT appear.
    assert not any(i["as_name"] == "SG.GS" for i in adjchange)
    # The unresolved UPDOWN on /0/0/0/9 must appear, merged to alert_count 2.
    updown = [i for i in incidents if i["mnemonic"] == "UPDOWN"]
    assert any(i["interface"] == "TenGigE0/0/0/9" for i in updown)
    nine = next(i for i in updown if i["interface"] == "TenGigE0/0/0/9")
    assert nine["alert_count"] == 2
    # The cleared /0/0/0/4 interface must NOT appear.
    assert not any(i["interface"] == "TenGigE0/0/0/4" for i in updown)


@pytest.mark.asyncio
async def test_get_incidents_empty_store_no_engine(
    client: AsyncClient, clean_stores: None
) -> None:
    """Empty store + no engine returns [] (line 710-711)."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/incidents")
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# /api/incidents/{id} found (808-809) + acknowledge found (828-830)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incident_by_id_found(
    client: AsyncClient, clean_stores: None
) -> None:
    """Existing incident id returns the record (lines 808-809)."""
    routes_mod._incidents_store.append(
        {"id": "INC-42", "title": "boom"}
    )  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/incidents/INC-42")
    assert resp.status_code == 200
    assert resp.json()["id"] == "INC-42"


@pytest.mark.asyncio
async def test_acknowledge_incident_found(
    client: AsyncClient, clean_stores: None
) -> None:
    """Acknowledging an existing incident flips the flag (lines 828-830)."""
    routes_mod._incidents_store.append({"id": "INC-43", "title": "x"})  # noqa: SLF001
    async with client as c:
        resp = await c.post("/api/incidents/INC-43/acknowledge")
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"
    assert routes_mod._incidents_store[0]["acknowledged"] is True  # noqa: SLF001


# ---------------------------------------------------------------------------
# stats daily / weekly counting loops (848-850, 867-869)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stats_daily_and_weekly_count(
    client: AsyncClient, clean_stores: None
) -> None:
    """daily + weekly stats count matching classifications (848-850, 867-869)."""
    # Use a timestamp that is "now" so it falls within today and this week.
    now_ts = (
        datetime.now(routes_mod._BDT).replace(tzinfo=None).isoformat()
    )  # noqa: SLF001
    routes_mod._alerts_store.append(
        {"classification": "CRITICAL", "timestamp": now_ts}
    )  # noqa: SLF001
    routes_mod._alerts_store.append(
        {"classification": "INFO", "timestamp": now_ts}
    )  # noqa: SLF001
    routes_mod._alerts_store.append(
        {"classification": "BOGUS", "timestamp": now_ts}
    )  # noqa: SLF001
    async with client as c:
        daily = await c.get("/api/stats/daily")
        weekly = await c.get("/api/stats/weekly")
    for resp, period in ((daily, "daily"), (weekly, "weekly")):
        assert resp.status_code == 200
        body = resp.json()
        assert body["period"] == period
        assert body["counts"]["CRITICAL"] == 1
        assert body["counts"]["INFO"] == 1
        # BOGUS is ignored (not a known classification)
        assert body["total"] == 2


# ---------------------------------------------------------------------------
# hardware-noise GET/POST (968, 980-981)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hardware_noise_get_and_set(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET reflects state; POST toggles it (lines 968, 980-981)."""
    async with client as c:
        get_resp = await c.get("/api/settings/hardware-noise")
        assert get_resp.status_code == 200
        assert "hardware_defects_as_noise" in get_resp.json()

        off = await c.post("/api/settings/hardware-noise", params={"enabled": False})
        assert off.status_code == 200
        assert off.json()["hardware_defects_as_noise"] is False
        assert routes_mod._hardware_defects_as_noise is False  # noqa: SLF001

        on = await c.post("/api/settings/hardware-noise", params={"enabled": True})
        assert on.json()["hardware_defects_as_noise"] is True


# ---------------------------------------------------------------------------
# /api/maintenance edge branches (1011, 1014-1015)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_maintenance_window_naive_and_bad_endtime(
    client: AsyncClient, clean_stores: None
) -> None:
    """Naive future end_time is made aware (1011); bad end_time kept (1014-1015)."""
    # Naive (no tzinfo) future end → goes through the replace(tzinfo=UTC) branch.
    routes_mod._maintenance_store.append(  # noqa: SLF001
        {
            "id": 1,
            "device_name": "EQ-RTR-01",
            "start_time": "2030-01-01T00:00:00",
            "end_time": "2030-01-01T02:00:00",
            "reason": "naive future",
            "created_by": "ops",
        }
    )
    # Unparseable end_time → exception path skips the window (corrupt data).
    routes_mod._maintenance_store.append(  # noqa: SLF001
        {
            "id": 2,
            "device_name": "KKT-Core-1",
            "start_time": "bad",
            "end_time": "not-a-date",
            "reason": "garbage end",
            "created_by": "ops",
        }
    )
    async with client as c:
        resp = await c.get("/api/maintenance")
    assert resp.status_code == 200
    ids = {w["id"] for w in resp.json()}
    # Only the valid future window should appear; corrupt window is skipped
    assert ids == {1}


# ---------------------------------------------------------------------------
# /api/bgp/peers with a neighbor (lines 1203-1213)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bgp_peers_dedup_by_neighbor(
    client: AsyncClient, clean_stores: None
) -> None:
    """Alerts with a neighbor produce a deduped peer list (lines 1203-1213)."""
    routes_mod._alerts_store.append(  # noqa: SLF001
        {
            "neighbor": "103.16.153.22",
            "as_number": 132602,
            "as_name": "BSCCL",
            "device": "EQ-RTR-01",
            "classification": "CRITICAL",
        }
    )
    # Same neighbor again → must collapse to one entry.
    routes_mod._alerts_store.append(  # noqa: SLF001
        {
            "neighbor": "103.16.153.22",
            "as_number": 132602,
            "as_name": "BSCCL",
            "device": "EQ-RTR-01",
            "classification": "WARNING",
        }
    )
    # No neighbor → skipped (the `continue` branch).
    routes_mod._alerts_store.append({"neighbor": "", "device": "X"})  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/bgp/peers")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["neighbor"] == "103.16.153.22"
    # last_state reflects the most recent (WARNING) alert.
    assert body[0]["last_state"] == "WARNING"


# ---------------------------------------------------------------------------
# add_alert_to_store branches (348, 353, 357, 359, 381, 392-417, 426-427)
# ---------------------------------------------------------------------------


def test_add_alert_to_store_recovery_resolves_by_interface(
    clean_stores: None,
) -> None:
    """INTF_UP recovery resolves a matching DOWN incident by interface.

    Covers lines 346-359: the recovery loop, interface match (352-353),
    and the pop (358-359).
    """
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-1",
            "device": "DHK-Core-3",
            "mnemonic": "UPDOWN",
            "message": "Interface TenGigE0/0/0/0, changed state to Down",
            "interface": "TenGigE0/0/0/0",
        }
    )
    # An incident on a DIFFERENT device must be skipped (line 348 continue).
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-2",
            "device": "OTHER-DEV",
            "mnemonic": "UPDOWN",
            "message": "Interface TenGigE0/0/0/0, changed state to Down",
            "interface": "TenGigE0/0/0/0",
        }
    )
    enriched = _make_enriched(
        device_name="DHK-Core-3",
        source_ip="192.168.200.11",
        mnemonic="UPDOWN",
        message="Interface TenGigE0/0/0/0, changed state to Up",
        interface_name="TenGigE0/0/0/0",
        rule_id="INTF_UP",
    )
    routes_mod.add_alert_to_store(enriched, _make_correlated())
    remaining = {i["id"] for i in routes_mod._incidents_store}  # noqa: SLF001
    assert "ALERT-1" not in remaining
    assert "ALERT-2" in remaining


def test_add_alert_to_store_recovery_resolves_bgp_by_as(
    clean_stores: None,
) -> None:
    """BGP_UP recovery resolves a matching ADJCHANGE incident by AS number.

    Covers lines 354-357: the neighbor/AS match branch when no interface
    match applies.
    """
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-9",
            "device": "EQ-RTR-01",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor X Down (AS: 24482)",
            "interface": "",
        }
    )
    enriched = _make_enriched(
        device_name="EQ-RTR-01",
        source_ip="192.168.203.1",
        mnemonic="ADJCHANGE",
        message="neighbor X Up (AS: 24482)",
        bgp_neighbor="X",
        as_number=24482,
        rule_id="BGP_UP",
    )
    # IX peer (not in bundle map) → the BGP-UP silent-fault block is skipped.
    routes_mod.add_alert_to_store(enriched, _make_correlated())
    assert not any(
        i["id"] == "ALERT-9" for i in routes_mod._incidents_store  # noqa: SLF001
    )


def test_add_alert_to_store_recovery_resolves_bgp_without_as_number(
    clean_stores: None,
) -> None:
    """BGP_UP recovery resolves ADJCHANGE incident even when AS number is 0.

    Real IOS-XR BGP UP messages often omit the AS number:
        neighbor 10.0.0.1 Up
    The recovery matching must not require as_number to be truthy.
    """
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-BGP-NO-AS",
            "device": "KKT-Core-2",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor 103.120.178.9 Down (Ceasing) (AS: 38553)",
            "interface": "",
            "neighbor": "103.120.178.9",
            "as_number": 38553,
        }
    )
    enriched = _make_enriched(
        device_name="KKT-Core-2",
        source_ip="192.168.202.130",
        mnemonic="ADJCHANGE",
        message="neighbor 103.120.178.9 Up",
        bgp_neighbor="103.120.178.9",
        as_number=0,
        rule_id="BGP_UP",
    )
    routes_mod.add_alert_to_store(enriched, _make_correlated())
    assert not any(
        i["id"] == "ALERT-BGP-NO-AS"
        for i in routes_mod._incidents_store  # noqa: SLF001
    )


def test_add_alert_to_store_recovery_resolves_bgp_via_neighbor_field(
    clean_stores: None,
) -> None:
    """BGP recovery matches on stored neighbor field rather than message substring."""
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-BGP-NEIGHBOR",
            "device": "COX-Core-1",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor 10.45.22.1 Down",
            "interface": "",
            "neighbor": "10.45.22.1",
            "as_number": 0,
        }
    )
    enriched = _make_enriched(
        device_name="COX-Core-1",
        source_ip="192.168.200.8",
        mnemonic="ADJCHANGE",
        message="neighbor 10.45.22.1 Up",
        bgp_neighbor="10.45.22.1",
        as_number=0,
        rule_id="BGP_UP",
    )
    routes_mod.add_alert_to_store(enriched, _make_correlated())
    assert not any(
        i["id"] == "ALERT-BGP-NEIGHBOR"
        for i in routes_mod._incidents_store  # noqa: SLF001
    )


def test_add_alert_to_store_incident_stores_neighbor_and_as(
    clean_stores: None,
) -> None:
    """Newly created incidents include neighbor and as_number fields."""
    routes_mod._hardware_defects_as_noise = False  # noqa: SLF001
    enriched = _make_enriched(
        device_name="EQ-RTR-01",
        source_ip="192.168.203.1",
        mnemonic="ADJCHANGE",
        message="neighbor 2001:de8:4::2:4482:1 Down",
        bgp_neighbor="2001:de8:4::2:4482:1",
        as_number=24482,
        classification="CRITICAL",
    )
    correlated = _make_correlated(incident_id="INC-BGP-FIELDS")
    routes_mod.add_alert_to_store(enriched, correlated)
    incs = [
        i for i in routes_mod._incidents_store if i["id"] == "INC-BGP-FIELDS"
    ]  # noqa: SLF001
    assert len(incs) == 1
    assert incs[0]["neighbor"] == "2001:de8:4::2:4482:1"
    assert incs[0]["as_number"] == 24482


def test_prune_recovered_incidents_resolves_stale_bgp(
    clean_stores: None,
) -> None:
    """The recovery cross-check prune removes BGP incidents superseded by UP alerts."""
    routes_mod._last_recovery_prune = 0.0  # noqa: SLF001
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "STALE-BGP-1",
            "device": "KKT-Core-2",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor 103.120.178.9 Down",
            "interface": "",
            "neighbor": "103.120.178.9",
            "started_at": "2026-05-27T10:00:00",
        }
    )
    routes_mod._alerts_store.append(  # noqa: SLF001
        {
            "device": "KKT-Core-2",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor 103.120.178.9 Up",
            "interface": "",
            "neighbor": "103.120.178.9",
            "timestamp": "2026-05-27T10:01:00",
        }
    )
    routes_mod._prune_recovered_incidents()  # noqa: SLF001
    assert not any(
        i["id"] == "STALE-BGP-1" for i in routes_mod._incidents_store  # noqa: SLF001
    )


def test_prune_recovered_incidents_resolves_stale_interface(
    clean_stores: None,
) -> None:
    """Recovery prune removes interface incidents superseded by UP."""
    routes_mod._last_recovery_prune = 0.0  # noqa: SLF001
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "STALE-INTF-1",
            "device": "COX-Core-1",
            "mnemonic": "UPDOWN",
            "message": "Interface GigabitEthernet0/0/0/5, changed state to Down",
            "interface": "GigabitEthernet0/0/0/5",
            "neighbor": "",
            "started_at": "2026-05-27T17:00:00",
        }
    )
    routes_mod._alerts_store.append(  # noqa: SLF001
        {
            "device": "COX-Core-1",
            "mnemonic": "UPDOWN",
            "message": "Interface GigabitEthernet0/0/0/5, changed state to Up",
            "interface": "GigabitEthernet0/0/0/5",
            "neighbor": "",
            "timestamp": "2026-05-27T17:01:00",
        }
    )
    routes_mod._prune_recovered_incidents()  # noqa: SLF001
    assert not any(
        i["id"] == "STALE-INTF-1" for i in routes_mod._incidents_store  # noqa: SLF001
    )


def test_add_alert_to_store_creates_and_merges_critical_incident(
    clean_stores: None,
) -> None:
    """A CRITICAL non-recovery alert creates an incident, then merges a dup.

    Covers the incident-create path and the existing-incident merge
    (lines 424-427: alert_count increment + last_alert update).
    """
    routes_mod._hardware_defects_as_noise = False  # noqa: SLF001
    enriched = _make_enriched(
        device_name="COX-Core-1",
        source_ip="192.168.200.8",
        mnemonic="ADDRESS_DUPLICATE",
        message="Duplicate address detected on Bundle-Ether191",
        interface_name="Bundle-Ether191",
        classification="CRITICAL",
    )
    correlated = _make_correlated(incident_id="INC-DUP-1")
    routes_mod.add_alert_to_store(enriched, correlated)
    routes_mod.add_alert_to_store(enriched, correlated)
    incs = [
        i for i in routes_mod._incidents_store if i["id"] == "INC-DUP-1"
    ]  # noqa: SLF001
    assert len(incs) == 1
    assert incs[0]["alert_count"] == 2


def test_add_alert_to_store_incident_includes_client(
    clean_stores: None,
) -> None:
    """Incident created by add_alert_to_store includes client_name from enriched log."""
    routes_mod._hardware_defects_as_noise = False  # noqa: SLF001
    enriched = _make_enriched(
        device_name="DHK-Core-3",
        source_ip="192.168.200.6",
        mnemonic="RX_FAULT",
        message="Interface TenGigE0/0/0/0, Detected Remote Fault",
        interface_name="TenGigE0/0/0/0",
        classification="CRITICAL",
        client_name="DHK-KKT-BH-LINK-02-VIA-F@H-KKT-Te0/1/0/23-121492",
    )
    correlated = _make_correlated(incident_id="INC-CLIENT-1")
    routes_mod.add_alert_to_store(enriched, correlated)
    incs = [
        i for i in routes_mod._incidents_store if i["id"] == "INC-CLIENT-1"
    ]  # noqa: SLF001
    assert len(incs) == 1
    assert incs[0]["client"] == "DHK-KKT-BH-LINK-02-VIA-F@H-KKT-Te0/1/0/23-121492"


@pytest.mark.asyncio
async def test_add_alert_to_store_bgp_up_schedules_db_task(
    clean_stores: None, async_db: Any
) -> None:
    """BGP-UP on a backbone bundle with a DB engine schedules a resolution task.

    Covers lines 379-417: the silent-fault incident pop on bundle members AND
    the `loop.create_task(_resolve_with_logging())` DB-persistence branch
    (only reachable when a running loop + DB engine both exist). The awaited
    task marks the seeded RX_FAULT alert resolved in the DB.
    """
    from sqlalchemy import select

    routes_mod._db_engine = async_db  # noqa: SLF001
    routes_mod._hardware_defects_as_noise = False  # noqa: SLF001

    # A non-silent-fault incident on the SAME device → skipped by the
    # BGP-resolution loop's `continue` (line 381) and must survive.
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-299",
            "device": "KKT-Core-1",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor Z Down (AS: 4755)",
            "interface": "",
        }
    )
    # In-memory incident for a bundle member of KKT-Core-1 Bundle-Ether500.
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "ALERT-300",
            "device": "KKT-Core-1",
            "mnemonic": "RX_FAULT",
            "message": "Interface TenGigE0/0/1/5, Detected Remote Fault",
            "interface": "TenGigE0/0/1/5",
        }
    )
    # Persist a matching RX_FAULT row so the DB task has something to resolve.
    async with AsyncSession(async_db) as session:
        session.add(
            AlertLog(
                timestamp=datetime.now(UTC),
                source_ip="192.168.202.2",
                device_name="KKT-Core-1",
                hostname="BSCCL-KKT-CORE-RTR-01",
                facility="PLATFORM",
                severity_level=2,
                mnemonic="RX_FAULT",
                message="Interface TenGigE0/0/1/5, Detected Remote Fault",
                raw="r",
                classification="CRITICAL",
                interface_name="TenGigE0/0/1/5",
            )
        )
        await session.commit()

    enriched = _make_enriched(
        device_name="KKT-Core-1",
        source_ip="192.168.202.2",
        mnemonic="ADJCHANGE",
        message="neighbor 103.16.153.21 Up (VRF: network) (AS: 132602)",
        bgp_neighbor="103.16.153.21",
        as_number=132602,
        rule_id="BGP_UP",
    )
    routes_mod.add_alert_to_store(enriched, _make_correlated())

    # The in-memory silent-fault incident is popped synchronously.
    assert not any(
        i["id"] == "ALERT-300" for i in routes_mod._incidents_store  # noqa: SLF001
    )
    # The unrelated ADJCHANGE incident (different AS) is skipped, not resolved.
    assert any(
        i["id"] == "ALERT-299" for i in routes_mod._incidents_store  # noqa: SLF001
    )

    # Let the scheduled DB-resolution task run to completion.
    pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    if pending:
        await asyncio.gather(*pending)

    async with AsyncSession(async_db) as session:
        row = (
            await session.execute(
                select(AlertLog).where(AlertLog.mnemonic == "RX_FAULT")
            )
        ).scalar_one()
    assert row.resolved_at is not None
    assert row.resolution_reason == "bgp_up_inferred"


# ---------------------------------------------------------------------------
# Hardware-noise toggle — BUG regression tests (RED phase)
# ---------------------------------------------------------------------------
# Bug 1: get_incidents() returns _incidents_store as-is without filtering
#         noise incidents even when _hardware_defects_as_noise is True.
# Bug 2: add_alert_to_store creates an incident via the correlated.incident_id
#         path even after the alert has been reclassified as NOISE.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_incidents_filters_noise_when_toggle_enabled(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/incidents must exclude NOISE-classified incidents when the
    hardware-defects-as-noise toggle is enabled.

    BUG: _incidents_store is returned as-is (line 863-864 in routes.py)
    without filtering out RX_FAULT/SIGNAL/RFI incidents, so backbone hardware
    fault incidents appear in the Active Incidents panel even when the operator
    has toggled them off.

    This test must FAIL until get_incidents() applies the noise filter.
    """
    routes_mod._hardware_defects_as_noise = True  # noqa: SLF001
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "INC-NOISE-RX",
            "title": "RXFault-DHK-Core-3 - TGE0/0/0/0 - Remote Fault",
            "severity": "NOISE",
            "device": "DHK-Core-3",
            "mnemonic": "RX_FAULT",
            "message": "Interface TenGigE0/0/0/0, Detected Remote Fault",
            "status": "active",
            "alert_count": 1,
        }
    )
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "INC-BGP-DOWN",
            "title": "ADJCHANGE — EQ-RTR-01 DOWN - Orange",
            "severity": "CRITICAL",
            "device": "EQ-RTR-01",
            "mnemonic": "ADJCHANGE",
            "message": "neighbor X Down - reason",
            "status": "active",
            "alert_count": 1,
        }
    )
    async with client as c:
        resp = await c.get("/api/incidents")
    assert resp.status_code == 200
    body = resp.json()
    # The RX_FAULT noise incident must NOT appear in the response.
    noise_ids = [i["id"] for i in body if i["mnemonic"] == "RX_FAULT"]
    assert "INC-NOISE-RX" not in noise_ids, (
        "BUG: RX_FAULT incident appeared in /api/incidents "
        "despite hardware_defects_as_noise=True"
    )
    # The legitimate ADJCHANGE incident MUST still appear.
    assert any(i["id"] == "INC-BGP-DOWN" for i in body)


@pytest.mark.asyncio
async def test_noise_toggle_purges_existing_incidents(
    client: AsyncClient, clean_stores: None
) -> None:
    """POST /api/settings/hardware-noise?enabled=true must remove any
    existing RX_FAULT/SIGNAL/RFI incidents from _incidents_store.

    BUG: The POST handler (routes.py ~line 1152) only sets the flag and
    persists it to DB — it never purges incidents that are already in
    _incidents_store with a noise mnemonic.  Enabling the toggle after
    incidents have been created leaves stale noise incidents visible.

    This test must FAIL until the POST handler purges stale incidents.
    """
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": "INC-STALE-RX",
            "title": "RXFault-DHK-Core-3 - TGE0/0/0/0 - Remote Fault",
            "severity": "CRITICAL",
            "device": "DHK-Core-3",
            "mnemonic": "RX_FAULT",
            "message": "Interface TenGigE0/0/0/0, Detected Remote Fault",
            "status": "active",
            "alert_count": 3,
        }
    )
    async with client as c:
        resp = await c.post("/api/settings/hardware-noise", params={"enabled": True})
    assert resp.status_code == 200
    # After enabling the toggle the stale RX_FAULT incident must be gone.
    remaining_ids = [i["id"] for i in routes_mod._incidents_store]  # noqa: SLF001
    assert "INC-STALE-RX" not in remaining_ids, (
        "BUG: enabling hardware_defects_as_noise did not purge existing "
        "RX_FAULT incident from _incidents_store"
    )


# ---------------------------------------------------------------------------
# /api/stats/heatmap (7x24 alert matrix)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_heatmap_returns_7x24_matrix(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/stats/heatmap returns a 7x24 matrix with max_count and period."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/stats/heatmap")
    assert resp.status_code == 200
    body = resp.json()
    assert body["period"] == "30d"
    assert len(body["data"]) == 7
    for row in body["data"]:
        assert len(row) == 24
    assert body["max_count"] == 0


@pytest.mark.asyncio
async def test_heatmap_empty_db_returns_zeros(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """Heatmap with empty DB returns all-zero 7x24 matrix."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/stats/heatmap", params={"period": "30d"})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 7
    for row in body["data"]:
        assert all(v == 0 for v in row)
    assert body["max_count"] == 0


@pytest.mark.asyncio
async def test_heatmap_with_db_data(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """Heatmap reflects DB rows grouped by (day_of_week, hour)."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    # Wednesday 2026-05-27 14:00 BDT (but timestamps stored as naive).
    # datetime(2026, 5, 27, 14, 0) is a Wednesday → weekday()=2.
    ts = datetime(2026, 5, 27, 14, 30, 0)
    async with AsyncSession(async_db) as session:
        for _ in range(3):
            session.add(
                AlertLog(
                    timestamp=ts,
                    source_ip="192.168.203.1",
                    device_name="EQ-RTR-01",
                    hostname="h",
                    facility="ROUTING",
                    severity_level=5,
                    mnemonic="ADJCHANGE",
                    message="m",
                    raw="r",
                    classification="CRITICAL",
                )
            )
        await session.commit()

    async with client as c:
        resp = await c.get("/api/stats/heatmap", params={"period": "all"})
    assert resp.status_code == 200
    body = resp.json()
    # Wednesday = day index 2 (strftime %w: Wed=3, mapped to (3-1)%7=2)
    assert body["data"][2][14] == 3
    assert body["max_count"] == 3


@pytest.mark.asyncio
async def test_heatmap_with_period_param(
    client: AsyncClient, clean_stores: None
) -> None:
    """Heatmap accepts 7d, 30d, 1y, all period parameters."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        for period in ("7d", "30d", "1y", "all"):
            resp = await c.get("/api/stats/heatmap", params={"period": period})
            assert resp.status_code == 200
            assert resp.json()["period"] == period


@pytest.mark.asyncio
async def test_heatmap_invalid_period_returns_400(
    client: AsyncClient, clean_stores: None
) -> None:
    """Invalid period returns 400."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get("/api/stats/heatmap", params={"period": "bogus"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_heatmap_in_memory_fallback(
    client: AsyncClient, clean_stores: None
) -> None:
    """Heatmap counts correctly from in-memory store when no DB engine."""
    routes_mod._db_engine = None  # noqa: SLF001
    # Thursday 2026-05-28 09:15 → weekday()=3, hour=9
    ts = datetime(2026, 5, 28, 9, 15, 0)
    for _ in range(5):
        routes_mod._alerts_store.append(  # noqa: SLF001
            {"classification": "WARNING", "timestamp": ts.isoformat()}
        )
    async with client as c:
        resp = await c.get("/api/stats/heatmap", params={"period": "all"})
    assert resp.status_code == 200
    body = resp.json()
    # Thursday = day index 3, hour 9
    assert body["data"][3][9] == 5
    assert body["max_count"] == 5


# ---------------------------------------------------------------------------
# /api/alerts/export — CSV export endpoint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_csv_returns_200_with_csv_content_type(
    client: AsyncClient, clean_stores: None
) -> None:
    """GET /api/alerts/export returns 200 with text/csv media type."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "csv"},
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")


@pytest.mark.asyncio
async def test_export_csv_header_row(client: AsyncClient, clean_stores: None) -> None:
    """CSV export contains the expected header columns."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "csv"},
        )
    assert resp.status_code == 200
    lines = resp.text.strip().split("\n")
    header = lines[0]
    expected_cols = [
        "timestamp",
        "device",
        "mnemonic",
        "classification",
        "message",
        "interface",
        "client",
        "as_name",
        "incident_id",
    ]
    for col in expected_cols:
        assert col in header, f"Missing column '{col}' in CSV header"


@pytest.mark.asyncio
async def test_export_csv_empty_db_returns_header_only(
    client: AsyncClient, clean_stores: None
) -> None:
    """With an empty DB, the CSV contains only the header row (no data rows)."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "csv"},
        )
    assert resp.status_code == 200
    lines = resp.text.strip().split("\n")
    # Only the header row
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_export_csv_content_disposition_filename(
    client: AsyncClient, clean_stores: None
) -> None:
    """Content-Disposition header has the correct filename format."""
    routes_mod._db_engine = None  # noqa: SLF001
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "csv"},
        )
    assert resp.status_code == 200
    cd = resp.headers.get("content-disposition", "")
    assert "attachment" in cd
    assert "netwatch-alerts-" in cd
    assert ".csv" in cd


@pytest.mark.asyncio
async def test_export_csv_with_in_memory_data(
    client: AsyncClient, clean_stores: None
) -> None:
    """In-memory fallback path populates CSV rows from the alerts store."""
    routes_mod._db_engine = None  # noqa: SLF001
    routes_mod._alerts_store.append(  # noqa: SLF001
        {
            "id": 1,
            "timestamp": "2026-05-23T12:00:00",
            "device": "EQ-RTR-01",
            "mnemonic": "ADJCHANGE",
            "classification": "CRITICAL",
            "message": "neighbor X Down",
            "interface": "TenGigE0/0/0/0",
            "client": "TestClient",
            "as_name": "BSCCL",
            "incident_id": "INC-1",
        }
    )
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "csv"},
        )
    assert resp.status_code == 200
    lines = resp.text.strip().split("\n")
    assert len(lines) == 2  # header + 1 data row
    assert "EQ-RTR-01" in lines[1]
    assert "ADJCHANGE" in lines[1]


@pytest.mark.asyncio
async def test_export_csv_db_backed(
    client: AsyncClient, clean_stores: None, async_db: Any
) -> None:
    """DB-backed path returns alert data in the CSV."""
    routes_mod._db_engine = async_db  # noqa: SLF001
    async with AsyncSession(async_db) as session:
        session.add(
            AlertLog(
                timestamp=datetime(2026, 5, 23, 12, 0, 0),
                source_ip="192.168.203.1",
                device_name="EQ-RTR-01",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="neighbor X Down",
                raw="raw",
                classification="CRITICAL",
                interface_name="TenGigE0/0/0/0",
                client_name="TestClient",
                as_name="BSCCL",
                incident_id="INC-1",
            )
        )
        await session.commit()

    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "all", "format": "csv"},
        )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    lines = resp.text.strip().split("\n")
    assert len(lines) == 2  # header + 1 data row
    assert "EQ-RTR-01" in lines[1]
    assert "CRITICAL" in lines[1]


@pytest.mark.asyncio
async def test_export_csv_invalid_period(
    client: AsyncClient, clean_stores: None
) -> None:
    """Invalid period returns 400."""
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "bogus", "format": "csv"},
        )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_csv_invalid_format(
    client: AsyncClient, clean_stores: None
) -> None:
    """Invalid format returns 400."""
    async with client as c:
        resp = await c.get(
            "/api/alerts/export",
            params={"period": "today", "format": "json"},
        )
    assert resp.status_code == 400


def test_add_alert_to_store_skips_incident_for_noise_reclassified(
    clean_stores: None,
) -> None:
    """add_alert_to_store must NOT create an incident when the alert has been
    reclassified as NOISE via the hardware-defects-as-noise toggle, even
    when correlated.incident_id is non-empty.

    BUG: The incident-creation guard at routes.py ~line 501-503 checks:
        alert["classification"] == "CRITICAL"
        OR (correlated.incident_id and not correlated.is_symptom)
    The NOISE reclassification at line 407 sets alert["classification"]="NOISE",
    which neutralises the first condition — but the second condition fires
    whenever correlated.incident_id is non-empty, bypassing the noise filter
    entirely and inserting a noise incident into _incidents_store.

    TenGigE0/0/0/0 IS a member of Bundle-Ether400 on 192.168.200.11
    (DHK-Core-03), so is_backhaul_member() returns True and the
    reclassification is expected to trigger.

    This test must FAIL until the incident-creation guard is fixed.
    """
    routes_mod._hardware_defects_as_noise = True  # noqa: SLF001
    enriched = _make_enriched(
        device_name="DHK-Core-3",
        source_ip="192.168.200.11",
        mnemonic="RX_FAULT",
        message="Interface TenGigE0/0/0/0, Detected Remote Fault",
        interface_name="TenGigE0/0/0/0",
        classification="CRITICAL",
    )
    # Non-empty incident_id simulates the correlator having assigned an ID,
    # which is the bypass path that triggers the bug.
    correlated = _make_correlated(incident_id="INC-NOISE-1", is_symptom=False)
    routes_mod.add_alert_to_store(enriched, correlated)
    assert not any(  # noqa: SLF001
        i["id"] == "INC-NOISE-1" for i in routes_mod._incidents_store
    ), (
        "BUG: noise-reclassified RX_FAULT alert created incident INC-NOISE-1 "
        "via the correlated.incident_id bypass path"
    )
