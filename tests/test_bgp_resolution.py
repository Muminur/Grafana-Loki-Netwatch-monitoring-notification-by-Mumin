"""Tests for BGP-UP auto-resolution of silent hardware faults."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.data.bgp_bundle_map import lookup_bundle_for_bgp_peer
from src.data.topology import NETWORK_TOPOLOGY, is_backhaul_member
from src.database.models import AlertLog

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enriched(
    device_name: str,
    source_ip: str,
    mnemonic: str,
    message: str,
    interface_name: str = "",
    bgp_neighbor: str = "",
    as_number: int = 0,
    as_name: str = "",
    classification: str = "CRITICAL",
    rule_id: str = "",
    vrf: str = "",
    event_type: str = "",
    client_name: str = "",
    interface_description: str = "",
):
    enriched = MagicMock()
    enriched.device_name = device_name
    enriched.interface_name = interface_name
    enriched.bgp_neighbor = bgp_neighbor
    enriched.as_number = as_number
    enriched.as_name = as_name
    enriched.classification = classification
    enriched.rule_id = rule_id
    enriched.vrf = vrf
    enriched.event_type = event_type
    enriched.client_name = client_name
    enriched.interface_description = interface_description
    enriched.parsed = MagicMock()
    enriched.parsed.source_ip = source_ip
    enriched.parsed.mnemonic = mnemonic
    enriched.parsed.message = message
    enriched.parsed.timestamp = MagicMock()
    enriched.parsed.timestamp.isoformat.return_value = "2026-05-23T16:22:56"
    enriched.parsed.hostname = device_name
    enriched.parsed.facility = "PLATFORM"
    return enriched


def _make_correlated(
    incident_id: str = "",
    is_symptom: bool = False,
    is_flapping: bool = False,
):
    correlated = MagicMock()
    correlated.incident_id = incident_id
    correlated.is_symptom = is_symptom
    correlated.is_flapping = is_flapping
    correlated.suppress_notification = False
    return correlated


# ---------------------------------------------------------------------------
# Task 1: BGP Bundle Map Tests
# ---------------------------------------------------------------------------


class TestBgpBundleMap:
    def test_eq01_to_kkt01_ipv4(self):
        result = lookup_bundle_for_bgp_peer("192.168.203.1", "103.16.153.22")
        assert result == "Bundle-Ether500"

    def test_eq01_to_kkt01_ipv6(self):
        result = lookup_bundle_for_bgp_peer("192.168.203.1", "2406:4b00:a:2:1::6")
        assert result == "Bundle-Ether500"

    def test_kkt01_to_eq01_ipv4(self):
        result = lookup_bundle_for_bgp_peer("192.168.202.2", "103.16.153.21")
        assert result == "Bundle-Ether500"

    def test_kkt01_to_dhk03_ipv4(self):
        result = lookup_bundle_for_bgp_peer("192.168.202.2", "103.16.152.81")
        assert result == "Bundle-Ether400"

    def test_eq01_to_eq02_ipv4(self):
        result = lookup_bundle_for_bgp_peer("192.168.203.1", "103.16.153.18")
        assert result == "Bundle-Ether600"

    def test_unknown_peer_returns_none(self):
        result = lookup_bundle_for_bgp_peer("192.168.203.1", "2001:de8:4::2:4482:1")
        assert result is None

    def test_unknown_device_returns_none(self):
        result = lookup_bundle_for_bgp_peer("10.0.0.1", "103.16.153.22")
        assert result is None


# ---------------------------------------------------------------------------
# Task 2: Topology Member Tests
# ---------------------------------------------------------------------------


class TestTopologyMembers:
    def test_kkt01_be500_has_members(self):
        topo = NETWORK_TOPOLOGY["192.168.202.2"]
        members = topo.upstreams["Bundle-Ether500"].members
        assert len(members) >= 10
        assert "TenGigE0/0/1/5" in members
        assert "TenGigE0/1/0/17" in members
        assert "TenGigE0/5/1/3" in members

    def test_kkt01_be505_has_members(self):
        topo = NETWORK_TOPOLOGY["192.168.202.2"]
        members = topo.upstreams["Bundle-Ether505"].members
        assert len(members) >= 5
        assert "TenGigE0/0/1/0" in members
        assert "TenGigE0/1/0/20" in members

    def test_kkt01_be500_member_lookup(self):
        is_member, bundle = is_backhaul_member("192.168.202.2", "TenGigE0/1/0/17")
        assert is_member is True
        assert bundle == "Bundle-Ether500"

    def test_kkt01_be505_member_lookup(self):
        is_member, bundle = is_backhaul_member("192.168.202.2", "TenGigE0/0/1/0")
        assert is_member is True
        assert bundle == "Bundle-Ether505"


# ---------------------------------------------------------------------------
# Task 3: AlertLog Model Fields
# ---------------------------------------------------------------------------


class TestAlertLogResolutionFields:
    def test_resolved_at_field_exists(self):
        columns = {c.name for c in AlertLog.__table__.columns}
        assert "resolved_at" in columns

    def test_resolution_reason_field_exists(self):
        columns = {c.name for c in AlertLog.__table__.columns}
        assert "resolution_reason" in columns

    def test_resolved_at_defaults_to_none(self):
        col = AlertLog.__table__.columns["resolved_at"]
        assert col.nullable is True

    def test_resolution_reason_defaults_to_empty(self):
        col = AlertLog.__table__.columns["resolution_reason"]
        assert col.default.arg == ""


# ---------------------------------------------------------------------------
# Task 4: BGP-UP Resolution Logic
# ---------------------------------------------------------------------------


class TestBgpUpResolution:
    def setup_method(self):
        from src.api.routes import _incidents_store

        _incidents_store.clear()

    def test_bgp_up_resolves_rx_fault_on_bundle_members(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-100",
                "title": "RXFault-Equinix-RTR-1 - TGE0/0/0/7 - Remote Fault",
                "severity": "CRITICAL",
                "device": "Equinix-RTR-1",
                "mnemonic": "RX_FAULT",
                "message": "Interface TenGigE0/0/0/7, Detected Remote Fault",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "TenGigE0/0/0/7",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.22 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.22",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        rx_faults = [i for i in _incidents_store if i["mnemonic"] == "RX_FAULT"]
        assert len(rx_faults) == 0

    def test_bgp_up_resolves_signal_fault(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-101",
                "title": "SIGNAL — KKT-Core-1, TGE0/1/0/17",
                "severity": "CRITICAL",
                "device": "KKT-Core-1",
                "mnemonic": "SIGNAL",
                "message": "Interface TenGigE0/1/0/17, Signal failure",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "TenGigE0/1/0/17",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="KKT-Core-1",
            source_ip="192.168.202.2",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.21 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.21",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        signal_incidents = [i for i in _incidents_store if i["mnemonic"] == "SIGNAL"]
        assert len(signal_incidents) == 0

    def test_bgp_up_does_not_resolve_non_member_interface(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-102",
                "title": "RXFault-Equinix-RTR-1 - HGE0/3/1/1 - Remote Fault",
                "severity": "CRITICAL",
                "device": "Equinix-RTR-1",
                "mnemonic": "RX_FAULT",
                "message": "Interface HundredGigE0/3/1/1, Detected Remote Fault",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "HundredGigE0/3/1/1",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.22 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.22",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        assert any(i["interface"] == "HundredGigE0/3/1/1" for i in _incidents_store)

    def test_bgp_up_ignores_ix_peers(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-103",
                "title": "RXFault-Equinix-RTR-1 - TGE0/0/0/2 - Remote Fault",
                "severity": "CRITICAL",
                "device": "Equinix-RTR-1",
                "mnemonic": "RX_FAULT",
                "message": "Interface TenGigE0/0/0/2, Detected Remote Fault",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "TenGigE0/0/0/2",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 2001:de8:4::2:4482:1 Up (VRF: network) (AS: 24482)",
            bgp_neighbor="2001:de8:4::2:4482:1",
            as_number=24482,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        assert len([i for i in _incidents_store if i["mnemonic"] == "RX_FAULT"]) == 1

    def test_bgp_up_does_not_resolve_adjchange_incidents(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-104",
                "title": "BGP Down — Equinix-RTR-1, AS24482",
                "severity": "CRITICAL",
                "device": "Equinix-RTR-1",
                "mnemonic": "ADJCHANGE",
                "message": "neighbor 2001:de8:4::2:4482:1 Down",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "",
                "client": "",
                "as_name": "SG.GS",
            }
        )

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.22 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.22",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        adjchange = [i for i in _incidents_store if i["mnemonic"] == "ADJCHANGE"]
        assert len(adjchange) == 1

    def test_flapping_bgp_does_not_resolve(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-105",
                "title": "RXFault-Equinix-RTR-1 - TGE0/0/0/5 - Remote Fault",
                "severity": "CRITICAL",
                "device": "Equinix-RTR-1",
                "mnemonic": "RX_FAULT",
                "message": "Interface TenGigE0/0/0/5, Detected Remote Fault",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "TenGigE0/0/0/5",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.22 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.22",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated(is_flapping=True)
        add_alert_to_store(enriched, correlated)

        assert len([i for i in _incidents_store if i["mnemonic"] == "RX_FAULT"]) == 1


# ---------------------------------------------------------------------------
# Task 5: DB Persistence Tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def async_db():
    from sqlalchemy.ext.asyncio import create_async_engine

    from src.database.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


class TestBgpUpDbPersistence:
    @pytest.mark.asyncio
    async def test_resolved_alerts_marked_in_db(self, async_db):
        from datetime import UTC, datetime

        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession

        from src.api.routes import resolve_silent_faults_in_db

        async with AsyncSession(async_db) as session:
            alert = AlertLog(
                timestamp=datetime(2026, 5, 23, 16, 22, 55, tzinfo=UTC),
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="PLATFORM",
                subfacility="DPA",
                severity_level=2,
                mnemonic="RX_FAULT",
                message="Interface TenGigE0/0/0/7, Detected Remote Fault",
                raw="raw log line",
                classification="CRITICAL",
                interface_name="TenGigE0/0/0/7",
            )
            session.add(alert)
            await session.commit()

        await resolve_silent_faults_in_db(
            engine=async_db,
            device_name="Equinix-RTR-1",
            bundle_members={"TenGigE0/0/0/7", "TenGigE0/0/0/5"},
        )

        async with AsyncSession(async_db) as session:
            stmt = select(AlertLog).where(AlertLog.mnemonic == "RX_FAULT")
            result = await session.execute(stmt)
            row = result.scalar_one()
            assert row.resolved_at is not None
            assert row.resolution_reason == "bgp_up_inferred"

    @pytest.mark.asyncio
    async def test_unrelated_alerts_not_marked(self, async_db):
        from datetime import UTC, datetime

        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import AsyncSession

        from src.api.routes import resolve_silent_faults_in_db

        async with AsyncSession(async_db) as session:
            alert = AlertLog(
                timestamp=datetime(2026, 5, 23, 16, 22, 55, tzinfo=UTC),
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="PLATFORM",
                subfacility="DPA",
                severity_level=2,
                mnemonic="RX_FAULT",
                message="Interface HundredGigE0/3/1/1, Detected Remote Fault",
                raw="raw log line",
                classification="CRITICAL",
                interface_name="HundredGigE0/3/1/1",
            )
            session.add(alert)
            await session.commit()

        await resolve_silent_faults_in_db(
            engine=async_db,
            device_name="Equinix-RTR-1",
            bundle_members={"TenGigE0/0/0/7"},
        )

        async with AsyncSession(async_db) as session:
            stmt = select(AlertLog).where(AlertLog.mnemonic == "RX_FAULT")
            result = await session.execute(stmt)
            row = result.scalar_one()
            assert row.resolved_at is None
            assert row.resolution_reason == ""


# ---------------------------------------------------------------------------
# Task 6: Restart Filtering Test
# ---------------------------------------------------------------------------


class TestIncidentReconstructionFiltering:
    @pytest.mark.asyncio
    async def test_resolved_alerts_excluded_on_restart(self, async_db):
        from datetime import UTC, datetime

        from sqlalchemy.ext.asyncio import AsyncSession

        from src.api import routes

        async with AsyncSession(async_db) as session:
            resolved_alert = AlertLog(
                timestamp=datetime(2026, 5, 23, 16, 22, 55, tzinfo=UTC),
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="PLATFORM",
                subfacility="DPA",
                severity_level=2,
                mnemonic="RX_FAULT",
                message="Interface TenGigE0/0/0/7, Detected Remote Fault",
                raw="raw log line",
                classification="CRITICAL",
                interface_name="TenGigE0/0/0/7",
                resolved_at=datetime(2026, 5, 23, 16, 25, 0, tzinfo=UTC),
                resolution_reason="bgp_up_inferred",
            )
            unresolved_alert = AlertLog(
                timestamp=datetime(2026, 5, 23, 16, 22, 56, tzinfo=UTC),
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="PLATFORM",
                subfacility="DPA",
                severity_level=2,
                mnemonic="RX_FAULT",
                message="Interface HundredGigE0/3/1/1, Detected Remote Fault",
                raw="raw log line",
                classification="CRITICAL",
                interface_name="HundredGigE0/3/1/1",
            )
            session.add_all([resolved_alert, unresolved_alert])
            await session.commit()

        routes._incidents_store.clear()  # noqa: SLF001
        old_engine = routes._db_engine  # noqa: SLF001
        routes._db_engine = async_db  # noqa: SLF001

        try:
            incidents = await routes.get_incidents()
        finally:
            routes._db_engine = old_engine  # noqa: SLF001

        assert len(incidents) == 1
        assert "HundredGigE0/3/1/1" in incidents[0]["message"]


# ---------------------------------------------------------------------------
# Task 7: Integration Tests
# ---------------------------------------------------------------------------


class TestBgpUpResolutionIntegration:
    def setup_method(self):
        from src.api.routes import _incidents_store

        _incidents_store.clear()

    def test_full_scenario_eq01_kkt01_bundle500(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        faults = [
            (
                "Equinix-RTR-1",
                "192.168.203.1",
                "RX_FAULT",
                "Interface TenGigE0/0/0/7, Detected Remote Fault",
                "TenGigE0/0/0/7",
            ),
            (
                "Equinix-RTR-1",
                "192.168.203.1",
                "RX_FAULT",
                "Interface TenGigE0/0/0/6, Detected Local Fault",
                "TenGigE0/0/0/6",
            ),
            (
                "Equinix-RTR-1",
                "192.168.203.1",
                "RX_FAULT",
                "Interface TenGigE0/0/0/5, Detected Remote Fault",
                "TenGigE0/0/0/5",
            ),
            (
                "Equinix-RTR-1",
                "192.168.203.1",
                "RX_FAULT",
                "Interface TenGigE0/0/0/2, Detected Local Fault",
                "TenGigE0/0/0/2",
            ),
        ]
        for dev, src_ip, mnem, msg, iface in faults:
            enriched = _make_enriched(
                device_name=dev,
                source_ip=src_ip,
                mnemonic=mnem,
                message=msg,
                interface_name=iface,
            )
            correlated = _make_correlated()
            add_alert_to_store(enriched, correlated)

        assert len([i for i in _incidents_store if i["mnemonic"] == "RX_FAULT"]) == 4

        enriched = _make_enriched(
            device_name="Equinix-RTR-1",
            source_ip="192.168.203.1",
            mnemonic="ADJCHANGE",
            message="neighbor 103.16.153.22 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="103.16.153.22",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        remaining_faults = [i for i in _incidents_store if i["mnemonic"] == "RX_FAULT"]
        assert len(remaining_faults) == 0

    def test_kkt01_signal_faults_resolved_by_ipv6_bgp_up(self):
        from src.api.routes import _incidents_store, add_alert_to_store

        _incidents_store.append(
            {
                "id": "ALERT-200",
                "title": "SIGNAL — KKT-Core-1, TGE0/1/0/20",
                "severity": "CRITICAL",
                "device": "KKT-Core-1",
                "mnemonic": "SIGNAL",
                "message": "Interface TenGigE0/1/0/20, Signal failure",
                "status": "active",
                "alert_count": 1,
                "started_at": "2026-05-23T16:22:55",
                "last_alert": "2026-05-23T16:22:55",
                "interface": "TenGigE0/1/0/20",
                "client": "",
                "as_name": "",
            }
        )

        enriched = _make_enriched(
            device_name="KKT-Core-1",
            source_ip="192.168.202.2",
            mnemonic="ADJCHANGE",
            message="neighbor 2406:4b00:a:2:1::16 Up (VRF: network) (AS: 132602)",
            bgp_neighbor="2406:4b00:a:2:1::16",
            as_number=132602,
            rule_id="BGP_UP",
        )
        correlated = _make_correlated()
        add_alert_to_store(enriched, correlated)

        assert len([i for i in _incidents_store if i["mnemonic"] == "SIGNAL"]) == 0
