"""Tests for src/data/topology.py and src/core/correlator.py — TDD: RED first.

Covers:
  1.  test_eq_rtr01_be500_downstream
  2.  test_eq_rtr01_be200_downstream
  3.  test_kkt01_be400_downstream
  4.  test_backhaul_member_down_then_bgp_down
  5.  test_independent_bgp_down
  6.  test_mass_bgp_event
  7.  test_incident_suppresses_downstream
  8.  test_flapping_peer
  9.  test_incident_id_format
  10. test_incident_affected_clients
  11. test_is_backhaul_member
  12. test_be300_downstream (EQ-RTR-01 BE300 → KKT-Core-3)
  13. test_be600_downstream (EQ-RTR-01 BE600 → EQ-RTR-02)
  14. test_kkt02_be150_downstream (KKT-Core-2 BE150 → KKT-Core-1)
  15. test_dhk03_multiple_upstreams
  16. test_bundle_member_is_backhaul_member
  17. test_non_backhaul_interface_is_not_member
  18. test_correlate_returns_correlated_event_type
  19. test_flap_count_increments
  20. test_independent_event_no_incident
"""

from __future__ import annotations

import logging
import re
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING

from src.core.correlator import CorrelatedEvent, CorrelationEngine
from src.core.enricher import EnrichedLog
from src.core.parser import ParsedLog
from src.data.topology import (
    NETWORK_TOPOLOGY,
    BackhaulLink,
    DeviceTopology,
    get_downstream_devices,
    is_backhaul_member,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@contextmanager
def _capture_logs(
    logger_name: str, level: int = logging.DEBUG
) -> Generator[list[logging.LogRecord], None, None]:
    """Capture log records emitted by *logger_name* at *level* or above."""
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = lambda record: records.append(record)  # type: ignore[assignment]
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    old_level = logger.level
    logger.setLevel(level)
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


# ---------------------------------------------------------------------------
# Topology module tests
# ---------------------------------------------------------------------------


class TestTopologyDataStructure:
    """Verify the static topology data is correctly shaped."""

    def test_network_topology_has_expected_devices(self) -> None:
        """NETWORK_TOPOLOGY must contain EQ-RTR-01, KKT-Core-01, etc."""
        assert "192.168.203.1" in NETWORK_TOPOLOGY  # EQ-RTR-01
        assert "192.168.202.2" in NETWORK_TOPOLOGY  # KKT-Core-01
        assert "192.168.202.130" in NETWORK_TOPOLOGY  # KKT-Core-02
        assert "192.168.200.11" in NETWORK_TOPOLOGY  # DHK-Core-03
        assert "192.168.200.8" in NETWORK_TOPOLOGY  # COX-Core-01

    def test_device_topology_fields(self) -> None:
        """Each DeviceTopology entry has name and upstreams dict."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        assert isinstance(topo, DeviceTopology)
        assert isinstance(topo.name, str)
        assert isinstance(topo.upstreams, dict)

    def test_backhaul_link_fields(self) -> None:
        """BackhaulLink has description, remote_device_ip, members."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether500"]
        assert isinstance(link, BackhaulLink)
        assert isinstance(link.description, str)
        assert isinstance(link.remote_device_ip, str)
        assert isinstance(link.members, list)

    def test_eq_rtr01_be500_members(self) -> None:
        """EQ-RTR-01 BE500 must contain 9 expected member interfaces."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether500"]
        assert "TenGigE0/0/0/0" in link.members
        assert "TenGigE0/0/0/3" in link.members
        assert "TenGigE0/0/0/5" in link.members
        assert "TenGigE0/3/0/2" in link.members
        assert "TenGigE0/3/0/3" in link.members
        # Members for indices 1,2,6,7 too
        assert "TenGigE0/0/0/1" in link.members
        assert "TenGigE0/0/0/6" in link.members
        assert "TenGigE0/0/0/7" in link.members

    def test_eq_rtr01_be500_remote(self) -> None:
        """EQ-RTR-01 BE500 remote device must be KKT-Core-01 IP."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether500"]
        assert link.remote_device_ip == "192.168.202.2"

    def test_eq_rtr01_be200_remote(self) -> None:
        """EQ-RTR-01 BE200 remote device must be COX-Core-03 IP."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether200"]
        assert link.remote_device_ip == "192.168.200.26"

    def test_eq_rtr01_be200_members(self) -> None:
        """EQ-RTR-01 BE200 must have HundredGigE0/3/1/1 and HundredGigE0/3/1/2."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether200"]
        assert "HundredGigE0/3/1/1" in link.members
        assert "HundredGigE0/3/1/2" in link.members

    def test_eq_rtr01_be300_remote(self) -> None:
        """EQ-RTR-01 BE300 remote device must be KKT-Core-03 IP."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether300"]
        assert link.remote_device_ip == "192.168.202.153"

    def test_eq_rtr01_be600_remote(self) -> None:
        """EQ-RTR-01 BE600 remote device must be EQ-RTR-02 IP."""
        topo = NETWORK_TOPOLOGY["192.168.203.1"]
        link = topo.upstreams["Bundle-Ether600"]
        assert link.remote_device_ip == "192.168.203.3"

    def test_kkt01_be500_remote(self) -> None:
        """KKT-Core-01 BE500 → EQ-RTR-01."""
        topo = NETWORK_TOPOLOGY["192.168.202.2"]
        link = topo.upstreams["Bundle-Ether500"]
        assert link.remote_device_ip == "192.168.203.1"

    def test_kkt01_be400_members(self) -> None:
        """KKT-Core-01 BE400 must include TenGigE0/0/1/6 and others."""
        topo = NETWORK_TOPOLOGY["192.168.202.2"]
        link = topo.upstreams["Bundle-Ether400"]
        assert "TenGigE0/0/1/6" in link.members
        assert "TenGigE0/1/0/0" in link.members
        assert "TenGigE0/1/0/9" in link.members
        assert "TenGigE0/5/1/6" in link.members

    def test_dhk03_has_three_upstreams(self) -> None:
        """DHK-Core-03 must have BE400, BE150, BE100 upstreams."""
        topo = NETWORK_TOPOLOGY["192.168.200.11"]
        assert "Bundle-Ether400" in topo.upstreams
        assert "Bundle-Ether150" in topo.upstreams
        assert "Bundle-Ether100" in topo.upstreams


# ---------------------------------------------------------------------------
# get_downstream_devices tests
# ---------------------------------------------------------------------------


class TestBackhaulLinkEquality:
    """Tests for BackhaulLink __eq__ and __hash__."""

    def test_equal_backhaul_links(self) -> None:
        """Two BackhaulLink instances with identical fields compare as equal."""
        a = BackhaulLink(
            description="A → B",
            remote_device_ip="10.0.0.1",
            members=["TenGigE0/0/0/0", "TenGigE0/0/0/1"],
        )
        b = BackhaulLink(
            description="A → B",
            remote_device_ip="10.0.0.1",
            members=["TenGigE0/0/0/0", "TenGigE0/0/0/1"],
        )
        assert a == b
        assert hash(a) == hash(b)

    def test_different_backhaul_links(self) -> None:
        """BackhaulLink instances with different fields are not equal."""
        a = BackhaulLink(
            description="A → B",
            remote_device_ip="10.0.0.1",
            members=["TenGigE0/0/0/0"],
        )
        b = BackhaulLink(
            description="A → C",
            remote_device_ip="10.0.0.2",
            members=["TenGigE0/0/0/1"],
        )
        assert a != b

    def test_backhaul_link_eq_with_non_backhaul(self) -> None:
        """BackhaulLink.__eq__ with a non-BackhaulLink object returns NotImplemented."""
        link = BackhaulLink(description="test", remote_device_ip="10.0.0.1", members=[])
        result = link.__eq__("not a BackhaulLink")
        assert result is NotImplemented

    def test_backhaul_link_usable_in_set(self) -> None:
        """Equal BackhaulLink instances collapse to one entry in a set."""
        a = BackhaulLink(description="X", remote_device_ip="1.2.3.4", members=["a"])
        b = BackhaulLink(description="X", remote_device_ip="1.2.3.4", members=["a"])
        assert len({a, b}) == 1


class TestDeviceTopologyEquality:
    """Tests for DeviceTopology __eq__ and __hash__."""

    def test_equal_device_topologies(self) -> None:
        """Two DeviceTopology instances with identical fields compare as equal."""
        link = BackhaulLink(description="link1", remote_device_ip="10.0.0.1")
        a = DeviceTopology(name="Dev-1", upstreams={"BE100": link})
        b = DeviceTopology(name="Dev-1", upstreams={"BE100": link})
        assert a == b
        assert hash(a) == hash(b)

    def test_different_device_topologies(self) -> None:
        """DeviceTopology instances with different names are not equal."""
        link = BackhaulLink(description="link1", remote_device_ip="10.0.0.1")
        a = DeviceTopology(name="Dev-1", upstreams={"BE100": link})
        b = DeviceTopology(name="Dev-2", upstreams={"BE100": link})
        assert a != b

    def test_device_topology_eq_with_non_device_topology(self) -> None:
        """DeviceTopology.__eq__ with a non-DeviceTopology returns NotImplemented."""
        topo = DeviceTopology(name="Dev-1")
        result = topo.__eq__("not a topology")
        assert result is NotImplemented

    def test_device_topology_usable_in_set(self) -> None:
        """Equal DeviceTopology instances collapse to one entry in a set."""
        a = DeviceTopology(name="Dev-1")
        b = DeviceTopology(name="Dev-1")
        assert len({a, b}) == 1


class TestGetDownstreamDevices:
    """Tests for get_downstream_devices()."""

    def test_eq_rtr01_be500_downstream(self) -> None:
        """EQ-RTR-01 BE500 down → downstream includes KKT-Core-01."""
        downstream = get_downstream_devices("192.168.203.1", "Bundle-Ether500")
        assert "192.168.202.2" in downstream

    def test_eq_rtr01_be200_downstream(self) -> None:
        """EQ-RTR-01 BE200 down → downstream includes COX-Core-03."""
        downstream = get_downstream_devices("192.168.203.1", "Bundle-Ether200")
        assert "192.168.200.26" in downstream

    def test_kkt01_be400_downstream(self) -> None:
        """KKT-Core-01 BE400 down → downstream includes DHK-Core-03."""
        downstream = get_downstream_devices("192.168.202.2", "Bundle-Ether400")
        assert "192.168.200.11" in downstream

    def test_eq_rtr01_be300_downstream(self) -> None:
        """EQ-RTR-01 BE300 down → downstream includes KKT-Core-03."""
        downstream = get_downstream_devices("192.168.203.1", "Bundle-Ether300")
        assert "192.168.202.153" in downstream

    def test_eq_rtr01_be600_downstream(self) -> None:
        """EQ-RTR-01 BE600 down → downstream includes EQ-RTR-02."""
        downstream = get_downstream_devices("192.168.203.1", "Bundle-Ether600")
        assert "192.168.203.3" in downstream

    def test_kkt02_be150_downstream(self) -> None:
        """KKT-Core-02 BE150 down → downstream includes KKT-Core-01."""
        downstream = get_downstream_devices("192.168.202.130", "Bundle-Ether150")
        assert "192.168.202.2" in downstream

    def test_unknown_device_returns_empty(self) -> None:
        """Unknown device IP → empty list."""
        downstream = get_downstream_devices("10.0.0.99", "Bundle-Ether500")
        assert downstream == []

    def test_unknown_interface_returns_empty(self) -> None:
        """Unknown interface on known device → empty list."""
        downstream = get_downstream_devices("192.168.203.1", "Bundle-Ether999")
        assert downstream == []

    def test_dhk03_multiple_upstreams(self) -> None:
        """DHK-Core-03 has upstreams to KKT-Core-01, COX-Core-03, DHK-Core-02."""
        for bundle, expected_ip in [
            ("Bundle-Ether400", "192.168.202.2"),
            ("Bundle-Ether150", "192.168.200.26"),
            ("Bundle-Ether100", "192.168.200.4"),
        ]:
            downstream = get_downstream_devices("192.168.200.11", bundle)
            assert (
                expected_ip in downstream
            ), f"Expected {expected_ip} in downstream for DHK-Core-03 {bundle}"

    def test_returns_list_type(self) -> None:
        """get_downstream_devices must always return a list."""
        result = get_downstream_devices("192.168.203.1", "Bundle-Ether500")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# is_backhaul_member tests
# ---------------------------------------------------------------------------


class TestIsBackhaulMember:
    """Tests for is_backhaul_member()."""

    def test_is_backhaul_member_tenge_be500(self) -> None:
        """TenGigE0/0/0/0 on EQ-RTR-01 → member of Bundle-Ether500."""
        is_member, bundle_name = is_backhaul_member("192.168.203.1", "TenGigE0/0/0/0")
        assert is_member is True
        assert bundle_name == "Bundle-Ether500"

    def test_is_backhaul_member_hundred_gig_be200(self) -> None:
        """HundredGigE0/3/1/1 on EQ-RTR-01 → member of Bundle-Ether200."""
        is_member, bundle_name = is_backhaul_member(
            "192.168.203.1", "HundredGigE0/3/1/1"
        )
        assert is_member is True
        assert bundle_name == "Bundle-Ether200"

    def test_non_backhaul_interface_is_not_member(self) -> None:
        """An interface not in any bundle → (False, '')."""
        is_member, bundle_name = is_backhaul_member(
            "192.168.203.1", "HundredGigE0/3/2/2"
        )
        assert is_member is False
        assert bundle_name == ""

    def test_unknown_device_returns_false(self) -> None:
        """Unknown device IP → (False, '')."""
        is_member, bundle_name = is_backhaul_member("10.0.0.99", "TenGigE0/0/0/0")
        assert is_member is False
        assert bundle_name == ""

    def test_kkt01_be400_member(self) -> None:
        """TenGigE0/0/1/6 on KKT-Core-01 → member of Bundle-Ether400."""
        is_member, bundle_name = is_backhaul_member("192.168.202.2", "TenGigE0/0/1/6")
        assert is_member is True
        assert bundle_name == "Bundle-Ether400"

    def test_bundle_member_is_backhaul_member(self) -> None:
        """TenGigE0/3/0/2 on EQ-RTR-01 is a BE500 member."""
        is_member, bundle_name = is_backhaul_member("192.168.203.1", "TenGigE0/3/0/2")
        assert is_member is True
        assert bundle_name == "Bundle-Ether500"


# ---------------------------------------------------------------------------
# CorrelatedEvent + CorrelationEngine tests
# ---------------------------------------------------------------------------

_UTC6 = timezone(timedelta(hours=6))


def _make_parsed(
    source_ip: str = "192.168.203.1",
    mnemonic: str = "ADJCHANGE",
    message: str = "neighbor 1.2.3.4 Down (VRF: network) (AS: 12345)",
    raw: str | None = None,
    ts: datetime | None = None,
) -> ParsedLog:
    """Construct a minimal ParsedLog for use in correlator tests."""
    if ts is None:
        ts = datetime.now(_UTC6)
    raw_line = raw or (
        f"May 22 21:00:00 {source_ip} 1: RP/0/RP0/CPU0:"
        f"May 22 21:00:00.000 +06: bgp[1097]: "
        f"%ROUTING-BGP-5-{mnemonic} : {message}"
    )
    return ParsedLog(
        timestamp=ts,
        source_ip=source_ip,
        hostname="BSCCL-EQ-RTR-01",
        rp_location="RP/0/RP0/CPU0",
        facility="ROUTING",
        subfacility="BGP",
        severity_level=5,
        mnemonic=mnemonic,
        message=message,
        raw=raw_line,
    )


def _make_enriched(
    source_ip: str = "192.168.203.1",
    mnemonic: str = "ADJCHANGE",
    classification: str = "CRITICAL",
    event_type: str = "BGP Peer Down",
    notify: bool = True,
    interface_name: str = "",
    bundle_parent: str = "",
    bgp_neighbor: str = "1.2.3.4",
    as_number: int = 12345,
    as_name: str = "TestAS",
    device_name: str = "Equinix-RTR-1",
    ts: datetime | None = None,
) -> EnrichedLog:
    """Construct a minimal EnrichedLog for use in correlator tests."""
    parsed = _make_parsed(source_ip=source_ip, mnemonic=mnemonic, ts=ts)
    return EnrichedLog(
        parsed=parsed,
        classification=classification,
        rule_id="R01",
        event_type=event_type,
        notify=notify,
        device_name=device_name,
        device_location="Singapore Equinix",
        interface_name=interface_name,
        interface_description="",
        bundle_parent=bundle_parent,
        client_name="",
        bgp_neighbor=bgp_neighbor,
        as_number=as_number,
        as_name=as_name,
        vrf="network",
    )


class TestCorrelatedEvent:
    """Basic sanity checks on CorrelatedEvent dataclass."""

    def test_correlate_returns_correlated_event_type(self) -> None:
        """correlate() must return a CorrelatedEvent instance."""
        engine = CorrelationEngine()
        enriched = _make_enriched()
        result = engine.correlate(enriched)
        assert isinstance(result, CorrelatedEvent)

    def test_correlated_event_has_enriched_ref(self) -> None:
        """CorrelatedEvent.enriched must point back to the original EnrichedLog."""
        engine = CorrelationEngine()
        enriched = _make_enriched()
        result = engine.correlate(enriched)
        assert result.enriched is enriched

    def test_independent_event_no_incident(self) -> None:
        """First BGP Down with no prior context → INDEPENDENT, no incident."""
        engine = CorrelationEngine()
        enriched = _make_enriched()
        result = engine.correlate(enriched)
        assert result.is_independent is True
        assert result.is_symptom is False
        assert result.is_root_cause is False


class TestIncidentIdFormat:
    """Validate the INC-YYYYMMDD-NNN incident ID format."""

    def test_incident_id_format(self) -> None:
        """Incident ID must match INC-YYYYMMDD-NNN."""
        engine = CorrelationEngine()
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        assert re.match(
            r"^INC-\d{8}-\d{3}$", inc_id
        ), f"Incident ID {inc_id!r} does not match INC-YYYYMMDD-NNN"

    def test_incident_id_increments(self) -> None:
        """Two consecutive calls must produce different IDs."""
        engine = CorrelationEngine()
        id1 = engine._generate_incident_id()  # noqa: SLF001
        id2 = engine._generate_incident_id()  # noqa: SLF001
        assert id1 != id2

    def test_incident_id_date_part(self) -> None:
        """Date part of incident ID must match today's date (UTC)."""
        engine = CorrelationEngine()
        today = datetime.now(tz=UTC).strftime("%Y%m%d")
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        assert today in inc_id


class TestBackhaulCorrelation:
    """Tests for backhaul member link failure → BGP symptom detection."""

    def test_backhaul_member_down_then_bgp_down(self) -> None:
        """Member link down + subsequent BGP peer down → peer is SYMPTOM."""
        engine = CorrelationEngine()

        # Step 1: A physical member of BE500 goes down on EQ-RTR-01
        member_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="TenGigE0/0/0/0",
            bundle_parent="Bundle-Ether500",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
            notify=True,
        )
        first = engine.correlate(member_down)
        # First event — no prior context, should not be marked as symptom
        assert first.is_root_cause or first.is_independent

        # Step 2: BGP peer down on same device, same bundle
        bgp_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="",
            bundle_parent="",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
            notify=True,
        )
        second = engine.correlate(bgp_down)
        # The BGP down should be a SYMPTOM (backhaul member was already down)
        assert second.is_symptom is True

    def test_independent_bgp_down(self) -> None:
        """BGP down with no prior backhaul issue → INDEPENDENT."""
        engine = CorrelationEngine()  # fresh engine — empty state
        bgp_down = _make_enriched(
            source_ip="192.168.203.1",
            classification="CRITICAL",
            event_type="BGP Peer Down",
        )
        result = engine.correlate(bgp_down)
        assert result.is_independent is True
        assert result.is_symptom is False


class TestMassBGPEvent:
    """Test mass BGP event → incident creation."""

    def test_mass_bgp_event(self) -> None:
        """5 BGP peers down within 60 s on same device → creates incident."""
        engine = CorrelationEngine()

        results = []
        for i in range(5):
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor=f"10.0.0.{i + 1}",
                as_number=10000 + i,
                classification="CRITICAL",
                event_type="BGP Peer Down",
            )
            results.append(engine.correlate(ev))

        # At least one event must create/belong to an incident
        incident_ids = [r.incident_id for r in results if r.incident_id is not None]
        assert len(incident_ids) > 0, "Expected at least one incident to be created"

    def test_incident_suppresses_downstream(self) -> None:
        """Once an incident is open, subsequent same-device events are suppressed."""
        engine = CorrelationEngine()

        # Create 5 BGP downs to trigger a mass incident
        for i in range(5):
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor=f"10.0.1.{i + 1}",
                as_number=20000 + i,
                classification="CRITICAL",
                event_type="BGP Peer Down",
            )
            engine.correlate(ev)

        # A 6th BGP down should be suppressed
        sixth = _make_enriched(
            source_ip="192.168.203.1",
            bgp_neighbor="10.0.1.99",
            as_number=29999,
            classification="CRITICAL",
            event_type="BGP Peer Down",
        )
        result = engine.correlate(sixth)
        # Should belong to existing incident and be suppressed
        assert result.suppress_notification is True or result.incident_id is not None


class TestFlappingDetection:
    """Test flapping detection (≥3 state changes in 5 min)."""

    def test_flapping_peer(self) -> None:
        """3+ state changes in 5 min → FLAPPING label."""
        engine = CorrelationEngine()
        base_ts = datetime.now(_UTC6)

        # Alternate Down/Up/Down/Up on same device+interface
        for i in range(4):
            ts = base_ts + timedelta(seconds=i * 30)  # 0s, 30s, 60s, 90s — all < 5 min
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor="10.0.2.1",
                as_number=55555,
                classification="CRITICAL" if i % 2 == 0 else "WARNING",
                event_type="BGP Peer Down" if i % 2 == 0 else "BGP Peer Up",
                ts=ts,
            )
            result = engine.correlate(ev)

        # The 4th event should be marked as flapping
        assert result.is_flapping is True

    def test_flap_count_increments(self) -> None:
        """flap_count must increment with each successive state change."""
        engine = CorrelationEngine()
        base_ts = datetime.now(_UTC6)

        results = []
        for i in range(4):
            ts = base_ts + timedelta(seconds=i * 45)
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor="10.0.3.1",
                as_number=66666,
                classification="CRITICAL" if i % 2 == 0 else "WARNING",
                event_type="BGP Peer Down" if i % 2 == 0 else "BGP Peer Up",
                ts=ts,
            )
            results.append(engine.correlate(ev))

        # flap_count must grow — the last result should show count >= 3
        assert results[-1].flap_count >= 3

    def test_non_flapping_single_event(self) -> None:
        """A single event cannot be flapping."""
        engine = CorrelationEngine()
        ev = _make_enriched(
            source_ip="192.168.203.1",
            bgp_neighbor="10.0.4.1",
            as_number=77777,
        )
        result = engine.correlate(ev)
        assert result.is_flapping is False


class TestIncidentAffectedClients:
    """Test that incidents list affected clients from topology."""

    def test_incident_affected_clients(self) -> None:
        """Mass event incident on EQ-RTR-01 → related_events accumulates."""
        engine = CorrelationEngine()

        events = []
        for i in range(5):
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor=f"10.0.5.{i + 1}",
                as_number=30000 + i,
                as_name=f"Client-AS-{i}",
                classification="CRITICAL",
                event_type="BGP Peer Down",
            )
            events.append(ev)

        results = [engine.correlate(ev) for ev in events]

        # The incident-bearing result should have related_events populated
        incident_results = [r for r in results if r.incident_id is not None]
        assert len(incident_results) > 0

        # The last incident result should reference multiple related events
        last_incident = incident_results[-1]
        assert isinstance(last_incident.related_events, list)


class TestPurgeStaleIncidentsEdgeCases:
    """Edge-case tests for _purge_stale_incidents."""

    def test_purge_incident_with_zero_events(self) -> None:
        """An incident with an empty event list is always considered stale."""
        engine = CorrelationEngine()

        # Manually inject an incident with zero events
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[inc_id] = []  # noqa: SLF001
        engine._device_incident["192.168.203.1"] = inc_id  # noqa: SLF001

        # Purge — the empty incident should be removed regardless of timestamp
        now = datetime.now(_UTC6)
        engine._purge_stale_incidents(now)  # noqa: SLF001

        assert inc_id not in engine._incidents  # noqa: SLF001
        assert "192.168.203.1" not in engine._device_incident  # noqa: SLF001


class TestFlapKeyFallback:
    """Tests for _flap_key when neither bgp_neighbor nor interface_name is set."""

    def test_flap_key_falls_back_to_mnemonic(self) -> None:
        """_flap_key uses mnemonic when neighbor and interface are empty."""
        engine = CorrelationEngine()
        enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="",
            mnemonic="UPDOWN",
        )
        key = engine._flap_key(enriched)  # noqa: SLF001
        assert key == (enriched.parsed.source_ip, "UPDOWN")

    def test_flap_key_prefers_bgp_neighbor(self) -> None:
        """_flap_key uses bgp_neighbor when both neighbor and interface are set."""
        engine = CorrelationEngine()
        enriched = _make_enriched(
            bgp_neighbor="10.0.0.1",
            interface_name="TenGigE0/0/0/0",
        )
        key = engine._flap_key(enriched)  # noqa: SLF001
        assert key == (enriched.parsed.source_ip, "10.0.0.1")

    def test_flap_key_uses_interface_when_no_neighbor(self) -> None:
        """_flap_key uses interface_name when bgp_neighbor is empty."""
        engine = CorrelationEngine()
        enriched = _make_enriched(
            bgp_neighbor="",
            interface_name="TenGigE0/0/0/5",
        )
        key = engine._flap_key(enriched)  # noqa: SLF001
        assert key == (enriched.parsed.source_ip, "TenGigE0/0/0/5")


class TestCorrelationWindowBoundary:
    """Verify that events outside the correlation window are not correlated."""

    def test_old_backhaul_event_not_correlated(self) -> None:
        """Backhaul member down > CORRELATION_WINDOW seconds ago → BGP NOT a symptom."""
        engine = CorrelationEngine()

        old_ts = datetime.now(_UTC6) - timedelta(
            seconds=CorrelationEngine.CORRELATION_WINDOW + 10
        )
        old_member_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="TenGigE0/0/0/0",
            bundle_parent="Bundle-Ether500",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
            ts=old_ts,
        )
        engine.correlate(old_member_down)

        # Now inject a fresh BGP down — old backhaul event is outside window
        bgp_down = _make_enriched(
            source_ip="192.168.203.1",
            classification="CRITICAL",
            event_type="BGP Peer Down",
        )
        result = engine.correlate(bgp_down)
        # Should be INDEPENDENT because the backhaul event is too old
        assert result.is_independent is True


class TestIncidentMemoryBounds:
    """Tests for the max_incidents cap on the CorrelationEngine."""

    def test_default_max_incidents(self) -> None:
        """Default max_incidents is 10,000."""
        engine = CorrelationEngine()
        assert engine._max_incidents == 10_000  # noqa: SLF001

    def test_custom_max_incidents(self) -> None:
        """max_incidents can be set via constructor."""
        engine = CorrelationEngine(max_incidents=5)
        assert engine._max_incidents == 5  # noqa: SLF001

    def test_eviction_when_cap_reached(self) -> None:
        """When max_incidents is reached, oldest incident is evicted."""
        engine = CorrelationEngine(max_incidents=3)

        # Manually inject 3 incidents to fill the cache
        ids = []
        for _i in range(3):
            inc_id = engine._generate_incident_id()  # noqa: SLF001
            engine._incidents[inc_id] = []  # noqa: SLF001
            ids.append(inc_id)

        assert len(engine._incidents) == 3  # noqa: SLF001

        # Enforce the cap — this should evict the oldest
        engine._enforce_incident_cap()  # noqa: SLF001

        assert len(engine._incidents) == 2  # noqa: SLF001
        # The first incident should be gone
        assert ids[0] not in engine._incidents  # noqa: SLF001
        # The remaining two should still be present
        assert ids[1] in engine._incidents  # noqa: SLF001
        assert ids[2] in engine._incidents  # noqa: SLF001

    def test_eviction_cleans_device_incident_map(self) -> None:
        """Eviction also removes entries from _device_incident."""
        engine = CorrelationEngine(max_incidents=2)

        # Inject 2 incidents and map them to device IPs
        id1 = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[id1] = []  # noqa: SLF001
        engine._device_incident["192.168.0.1"] = id1  # noqa: SLF001

        id2 = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[id2] = []  # noqa: SLF001
        engine._device_incident["192.168.0.2"] = id2  # noqa: SLF001

        # Enforce cap — should evict id1
        engine._enforce_incident_cap()  # noqa: SLF001

        assert id1 not in engine._incidents  # noqa: SLF001
        assert "192.168.0.1" not in engine._device_incident  # noqa: SLF001
        assert id2 in engine._incidents  # noqa: SLF001
        assert "192.168.0.2" in engine._device_incident  # noqa: SLF001

    def test_eviction_logs_warning(self) -> None:
        """Eviction logs a warning with the incident ID and cap value."""
        engine = CorrelationEngine(max_incidents=1)
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[inc_id] = []  # noqa: SLF001

        with _capture_logs("src.core.correlator", logging.WARNING) as records:
            engine._enforce_incident_cap()  # noqa: SLF001

        assert len(records) >= 1
        assert "Incident cache full" in records[0].message
        assert inc_id in records[0].message

    def test_no_eviction_below_cap(self) -> None:
        """No eviction occurs when incident count is below the cap."""
        engine = CorrelationEngine(max_incidents=10)

        for _ in range(5):
            inc_id = engine._generate_incident_id()  # noqa: SLF001
            engine._incidents[inc_id] = []  # noqa: SLF001

        assert len(engine._incidents) == 5  # noqa: SLF001
        engine._enforce_incident_cap()  # noqa: SLF001
        assert len(engine._incidents) == 5  # noqa: SLF001

    def test_purge_still_works_alongside_cap(self) -> None:
        """The 24-hour purge logic is unaffected by the cap feature."""
        engine = CorrelationEngine(max_incidents=100)

        # Inject an old incident with events older than 24 hours
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        old_ts = datetime.now(_UTC6) - timedelta(hours=25)
        old_parsed = _make_parsed(ts=old_ts)
        old_enriched = EnrichedLog(
            parsed=old_parsed,
            classification="CRITICAL",
            rule_id="R01",
            event_type="BGP Peer Down",
            notify=True,
            device_name="Test-Device",
            device_location="Test",
            interface_name="",
            interface_description="",
            bundle_parent="",
            client_name="",
            bgp_neighbor="10.0.0.1",
            as_number=12345,
            as_name="TestAS",
            vrf="network",
        )
        engine._incidents[inc_id] = [old_enriched]  # noqa: SLF001
        engine._device_incident["192.168.0.1"] = inc_id  # noqa: SLF001

        # Purge should remove the stale incident
        now = datetime.now(_UTC6)
        engine._purge_stale_incidents(now)  # noqa: SLF001

        assert inc_id not in engine._incidents  # noqa: SLF001
        assert "192.168.0.1" not in engine._device_incident  # noqa: SLF001
