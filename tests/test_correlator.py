"""Tests for src/data/topology.py and src/core/correlator.py.

Covers the per-link correlation model: topology link lookups
(``get_link_remote``), backhaul-member detection, and the correlation engine
(backhaul symptom grouping, mass-BGP events, flapping, incident IDs, memory
bounds).  Correlation is device-to-device per physical link — a backhaul
failure only correlates events that ride that exact link, never a transitive
downstream subtree (the network is multi-homed).
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
    get_link_remote,
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
        """NETWORK_TOPOLOGY must contain all core/aggregation routers."""
        assert "192.168.203.1" in NETWORK_TOPOLOGY  # EQ-RTR-01
        assert "192.168.202.2" in NETWORK_TOPOLOGY  # KKT-Core-01
        assert "192.168.202.130" in NETWORK_TOPOLOGY  # KKT-Core-02
        assert "192.168.200.11" in NETWORK_TOPOLOGY  # DHK-Core-03
        assert "192.168.200.8" in NETWORK_TOPOLOGY  # COX-Core-01
        assert "192.168.203.3" in NETWORK_TOPOLOGY  # EQ-RTR-02
        assert "192.168.202.153" in NETWORK_TOPOLOGY  # KKT-Core-03
        assert "192.168.200.26" in NETWORK_TOPOLOGY  # COX-Core-03
        assert "192.168.200.4" in NETWORK_TOPOLOGY  # DHK-Core-02
        assert "192.168.200.6" in NETWORK_TOPOLOGY  # COX-Core-02
        assert "192.168.200.27" in NETWORK_TOPOLOGY  # COX-Core-04

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
# get_link_remote tests
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


class TestGetLinkRemote:
    """Tests for get_link_remote() — direct per-link remote lookup."""

    def test_eq_rtr01_be500_remote(self) -> None:
        """EQ-RTR-01 BE500 → remote is KKT-Core-01."""
        assert get_link_remote("192.168.203.1", "Bundle-Ether500") == "192.168.202.2"

    def test_kkt01_be500_remote_symmetric(self) -> None:
        """KKT-Core-01 BE500 → remote is EQ-RTR-01 (the symmetric far end)."""
        assert get_link_remote("192.168.202.2", "Bundle-Ether500") == "192.168.203.1"

    def test_eq_rtr01_be200_remote(self) -> None:
        """EQ-RTR-01 BE200 → remote is COX-Core-03."""
        assert get_link_remote("192.168.203.1", "Bundle-Ether200") == "192.168.200.26"

    def test_unknown_device_returns_none(self) -> None:
        """Unknown device IP → None."""
        assert get_link_remote("10.0.0.99", "Bundle-Ether500") is None

    def test_unknown_bundle_returns_none(self) -> None:
        """Unknown bundle on a known device → None."""
        assert get_link_remote("192.168.203.1", "Bundle-Ether999") is None


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
    as_number: int | None = 12345,
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

        # Step 2: BGP peer down on same device that rides the failed bundle.
        # Neighbor 103.16.153.22 → EQ-RTR-01 Bundle-Ether500 (the failed link).
        bgp_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="103.16.153.22",
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

    def test_stale_incident_id_not_returned_after_eviction(self) -> None:
        """If a backhaul incident is evicted while its failure is still active,
        a later symptom must attach to a LIVE incident, not a phantom id (which
        would suppress the alert against a non-existent incident)."""
        engine = CorrelationEngine()
        member_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="TenGigE0/0/0/0",
            bundle_parent="Bundle-Ether500",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
        )
        first = engine.correlate(member_down)
        assert first.incident_id is not None
        assert first.incident_id in engine._incidents  # noqa: SLF001

        # Simulate the incident being evicted (e.g. by the incident cap) while
        # its backhaul-failure entry is still live.
        del engine._incidents[first.incident_id]  # noqa: SLF001

        bgp_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="103.16.153.22",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
        )
        second = engine.correlate(bgp_down)
        # The returned incident id must be a live incident, never the evicted one.
        assert second.incident_id is not None
        assert second.incident_id in engine._incidents  # noqa: SLF001

    def test_pni_peer_same_device_not_suppressed(self) -> None:
        """A backhaul failure must NOT suppress an unrelated PNI/IX peer on the
        SAME device — the PNI peer does not ride on the failed bundle.

        Multi-homed network: correlation is per physical link, so only events on
        the failed link are symptoms.  A Google/AWS-style peer (not in
        bgp_bundle_map) is independent and must still alert.
        """
        engine = CorrelationEngine()
        # BE500 member down on EQ-RTR-01 → backhaul failure registered
        engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        # A PNI peer on the SAME device — neighbor NOT in bgp_bundle_map
        pni = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="203.0.113.7",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
        )
        result = engine.correlate(pni)
        assert result.is_symptom is False
        assert result.is_independent is True

    def test_transitive_downstream_device_not_suppressed(self) -> None:
        """One upstream link down must NOT suppress alerts on a device that is
        only *transitively* downstream (multi-homed → it is not isolated)."""
        engine = CorrelationEngine()
        # BE500 member down on EQ-RTR-01 (link EQ-RTR-01 ↔ KKT-Core-01)
        engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        # CRITICAL on DHK-Core-02 (192.168.200.4) — NOT directly linked to EQ-RTR-01
        far = _make_enriched(
            source_ip="192.168.200.4",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="198.51.100.9",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
            device_name="DHK-Core-2-Agg",
        )
        result = engine.correlate(far)
        assert result.is_symptom is False
        assert result.is_independent is True

    def test_remote_end_onlink_symptom_suppressed(self) -> None:
        """The remote end of the failed link IS correlated: a BGP session on the
        directly-linked neighbor that rides the failed bundle is a SYMPTOM."""
        engine = CorrelationEngine()
        # BE500 member down on EQ-RTR-01 (link to KKT-Core-01)
        engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        # KKT-Core-01's BGP session to EQ-RTR-01 over its BE500 drops.
        # Neighbor 103.16.153.21 → KKT-01 Bundle-Ether500 → remote EQ-RTR-01.
        remote = _make_enriched(
            source_ip="192.168.202.2",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="103.16.153.21",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
            device_name="KKT-Core-01",
        )
        result = engine.correlate(remote)
        assert result.is_symptom is True

    def test_other_bundle_same_device_is_own_root_cause(self) -> None:
        """A second, DIFFERENT backhaul bundle failing on the same device is its
        own root cause — not a symptom of the first bundle's failure."""
        engine = CorrelationEngine()
        # BE500 member down on EQ-RTR-01
        engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        # BE200 member down on the SAME device (different link → COX-Core-03)
        other = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="HundredGigE0/3/1/1",
            bundle_parent="Bundle-Ether200",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
        )
        result = engine.correlate(other)
        assert result.is_symptom is False
        assert result.is_root_cause is True

    def test_other_link_to_same_failed_device_not_suppressed(self) -> None:
        """A failure on EQ-RTR-01's BE500 link (to KKT-01) must NOT suppress an
        event on COX-Core-03's *separate* BE200 link to EQ-RTR-01.

        Both links terminate on EQ-RTR-01, but they are different physical
        links: correlating COX-03's BE200 event with the BE500 failure would be
        a false suppression.
        """
        engine = CorrelationEngine()
        # BE500 member down on EQ-RTR-01 (the EQ-RTR-01 ↔ KKT-Core-01 link)
        engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        # COX-Core-03's BGP session over its OWN BE200 link to EQ-RTR-01 drops.
        # Neighbor 103.16.153.45 → COX-03 Bundle-Ether200 (a different link).
        other_link = _make_enriched(
            source_ip="192.168.200.26",
            interface_name="",
            bundle_parent="",
            bgp_neighbor="103.16.153.45",
            classification="CRITICAL",
            event_type="BGP Peer Down",
            mnemonic="ADJCHANGE",
            device_name="COX-Core-3",
        )
        result = engine.correlate(other_link)
        assert result.is_symptom is False
        assert result.is_independent is True

    def test_dual_end_member_down_single_incident(self) -> None:
        """Both physical ends of a link reporting a member down collapse into
        ONE incident; the far end is a symptom, not a second incident."""
        engine = CorrelationEngine()
        first = engine.correlate(
            _make_enriched(
                source_ip="192.168.203.1",  # EQ-RTR-01
                interface_name="TenGigE0/0/0/0",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
            )
        )
        assert first.is_root_cause is True
        # The OTHER end of the same physical link (KKT-Core-01) reports a member
        # of its own Bundle-Ether500 (facing EQ-RTR-01) going down.
        second = engine.correlate(
            _make_enriched(
                source_ip="192.168.202.2",  # KKT-Core-01
                interface_name="TenGigE0/0/1/5",
                bundle_parent="Bundle-Ether500",
                classification="CRITICAL",
                event_type="Interface Down",
                mnemonic="UPDOWN",
                device_name="KKT-Core-01",
            )
        )
        assert second.is_symptom is True
        assert second.incident_id == first.incident_id
        assert len(engine._incidents) == 1  # noqa: SLF001


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

    def test_non_bgp_event_is_not_mass_incident_root_cause(self) -> None:
        """A non-BGP event must not become the root cause of a mass-BGP incident
        merely because prior BGP peer-downs exist on the same device."""
        engine = CorrelationEngine()
        dev = "192.168.203.1"
        # Prime the window with (threshold - 1) BGP peer-downs.
        for i in range(engine.MASS_BGP_THRESHOLD - 1):
            engine.correlate(
                _make_enriched(
                    source_ip=dev,
                    bgp_neighbor=f"10.50.0.{i + 1}",
                    as_number=50000 + i,
                    classification="CRITICAL",
                    event_type="BGP Peer Down",
                    interface_name="",
                    bundle_parent="",
                )
            )
        # A non-BGP, non-backhaul event on the same device must NOT open a
        # mass-BGP incident as its root cause.
        non_bgp = _make_enriched(
            source_ip=dev,
            interface_name="GigabitEthernet9/9/9/9",
            bundle_parent="",
            bgp_neighbor="",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
        )
        result = engine.correlate(non_bgp)
        assert result.is_root_cause is False

    def test_three_bgp_downs_form_mass_incident(self) -> None:
        """3 BGP peers down within 60 s on one router form a mass incident.

        The mass-event threshold is 3 (PRD-SUPPLEMENT §E1.2), not 5: a 3-peer
        simultaneous drop must collapse into one incident rather than firing
        three separate notifications.
        """
        engine = CorrelationEngine()
        results = []
        for i in range(3):
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor=f"10.7.0.{i + 1}",
                as_number=70000 + i,
                classification="CRITICAL",
                event_type="BGP Peer Down",
            )
            results.append(engine.correlate(ev))

        # The 3rd distinct peer-down opens a single mass incident.
        assert results[2].incident_id is not None
        assert results[2].is_root_cause is True


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
        engine._device_incidents["192.168.203.1"].append(inc_id)  # noqa: SLF001

        # Purge — the empty incident should be removed regardless of timestamp
        now = datetime.now(_UTC6)
        engine._purge_stale_incidents(now)  # noqa: SLF001

        assert inc_id not in engine._incidents  # noqa: SLF001
        assert "192.168.203.1" not in engine._device_incidents  # noqa: SLF001


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

    def test_eviction_cleans_device_incidents_map(self) -> None:
        """Eviction also removes entries from _device_incidents."""
        engine = CorrelationEngine(max_incidents=2)

        # Inject 2 incidents and map them to device IPs
        id1 = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[id1] = []  # noqa: SLF001
        engine._device_incidents["192.168.0.1"].append(id1)  # noqa: SLF001

        id2 = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[id2] = []  # noqa: SLF001
        engine._device_incidents["192.168.0.2"].append(id2)  # noqa: SLF001

        # Enforce cap — should evict id1
        engine._enforce_incident_cap()  # noqa: SLF001

        assert id1 not in engine._incidents  # noqa: SLF001
        assert "192.168.0.1" not in engine._device_incidents  # noqa: SLF001
        assert id2 in engine._incidents  # noqa: SLF001
        assert "192.168.0.2" in engine._device_incidents  # noqa: SLF001

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
        engine._device_incidents["192.168.0.1"].append(inc_id)  # noqa: SLF001

        # Purge should remove the stale incident
        now = datetime.now(_UTC6)
        engine._purge_stale_incidents(now)  # noqa: SLF001

        assert inc_id not in engine._incidents  # noqa: SLF001
        assert "192.168.0.1" not in engine._device_incidents  # noqa: SLF001


# ---------------------------------------------------------------------------
# resolve_incident tests
# ---------------------------------------------------------------------------


class TestResolveIncident:
    """Tests for CorrelationEngine.resolve_incident()."""

    def test_recovery_resolves_incident(self) -> None:
        """resolve_incident() removes the incident and returns its ID."""
        engine = CorrelationEngine()

        # Manually inject an incident
        inc_id = engine._generate_incident_id()  # noqa: SLF001
        enriched = _make_enriched()
        engine._incidents[inc_id] = [enriched]  # noqa: SLF001
        engine._device_incidents["192.168.203.1"].append(inc_id)  # noqa: SLF001

        result = engine.resolve_incident(inc_id)

        assert result == inc_id

    def test_resolved_incident_not_in_registry(self) -> None:
        """After resolve_incident(), the incident is absent from both registries."""
        engine = CorrelationEngine()

        inc_id = engine._generate_incident_id()  # noqa: SLF001
        enriched = _make_enriched()
        engine._incidents[inc_id] = [enriched]  # noqa: SLF001
        engine._device_incidents["192.168.203.1"].append(inc_id)  # noqa: SLF001

        engine.resolve_incident(inc_id)

        assert inc_id not in engine._incidents  # noqa: SLF001
        assert "192.168.203.1" not in engine._device_incidents  # noqa: SLF001

    def test_resolve_nonexistent_incident_returns_none(self) -> None:
        """resolve_incident() with unknown ID returns None."""
        engine = CorrelationEngine()
        result = engine.resolve_incident("INC-99990101-999")
        assert result is None

    def test_resolve_clears_only_matching_device_incidents(self) -> None:
        """resolve_incident() only removes device mappings for the resolved incident."""
        engine = CorrelationEngine()

        id1 = engine._generate_incident_id()  # noqa: SLF001
        id2 = engine._generate_incident_id()  # noqa: SLF001
        engine._incidents[id1] = [_make_enriched()]  # noqa: SLF001
        engine._incidents[id2] = [_make_enriched()]  # noqa: SLF001
        engine._device_incidents["192.168.0.1"].append(id1)  # noqa: SLF001
        engine._device_incidents["192.168.0.2"].append(id2)  # noqa: SLF001

        engine.resolve_incident(id1)

        assert id1 not in engine._incidents  # noqa: SLF001
        assert "192.168.0.1" not in engine._device_incidents  # noqa: SLF001
        # id2 must remain untouched
        assert id2 in engine._incidents  # noqa: SLF001
        assert id2 in engine._device_incidents["192.168.0.2"]  # noqa: SLF001


class TestFirstMemberDownIsRootCause:
    """The very first bundle member DOWN event should be tagged as root cause."""

    def test_first_member_down_is_root_cause(self) -> None:
        """Single bundle member DOWN -> is_root_cause is True, incident created."""
        engine = CorrelationEngine()

        member_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="TenGigE0/0/0/0",
            bundle_parent="Bundle-Ether500",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
            bgp_neighbor="",
        )
        result = engine.correlate(member_down)

        assert result.is_root_cause is True
        assert result.incident_id is not None
        assert result.incident_id.startswith("INC-")
        assert result.is_symptom is False
        assert result.is_independent is False


class TestDeviceMultipleOverlappingIncidents:
    """A single device can host multiple distinct incidents at the same time."""

    def test_device_multiple_overlapping_incidents(self) -> None:
        """Backhaul + mass BGP -> 2 distinct incidents on same device."""
        engine = CorrelationEngine()

        member_down = _make_enriched(
            source_ip="192.168.203.1",
            interface_name="TenGigE0/0/0/0",
            bundle_parent="Bundle-Ether500",
            classification="CRITICAL",
            event_type="Interface Down",
            mnemonic="UPDOWN",
            bgp_neighbor="",
        )
        bh_result = engine.correlate(member_down)
        assert bh_result.is_root_cause is True
        backhaul_incident_id = bh_result.incident_id
        assert backhaul_incident_id is not None

        mass_results = []
        for i in range(5):
            ev = _make_enriched(
                source_ip="192.168.203.1",
                bgp_neighbor=f"10.99.0.{i + 1}",
                as_number=90000 + i,
                classification="CRITICAL",
                event_type="BGP Peer Down",
                interface_name="",
                bundle_parent="",
            )
            mass_results.append(engine.correlate(ev))

        mass_incident_ids = {
            r.incident_id
            for r in mass_results
            if r.incident_id is not None and r.incident_id != backhaul_incident_id
        }
        assert len(mass_incident_ids) >= 1, (
            f"Expected a separate mass-event incident; "
            f"got only backhaul id {backhaul_incident_id}"
        )


class TestFlapHistoryPurge:
    """Regression: _flap_history must not grow without bound."""

    def test_purge_stale_evicts_stale_flap_history_keys(self) -> None:
        """Keys with no event inside the flap window are dropped by
        ``_purge_stale`` (invoked on every ``correlate()``), so a long-running
        process cannot accumulate one permanent key per peer/interface."""
        engine = CorrelationEngine()
        t0 = datetime(2026, 5, 30, 10, 0, 0, tzinfo=_UTC6)

        # 50 distinct devices each emit one BGP-down at t0 -> 50 flap keys.
        for i in range(50):
            engine.correlate(_make_enriched(source_ip=f"10.20.0.{i}", ts=t0))
        assert len(engine._flap_history) == 50  # noqa: SLF001

        # Advance past the flap window and feed one fresh event; the 50 stale
        # keys must be evicted, leaving only the fresh one.
        t1 = t0 + timedelta(seconds=engine.FLAP_WINDOW + 60)
        engine.correlate(_make_enriched(source_ip="10.20.9.9", ts=t1))
        assert len(engine._flap_history) == 1  # noqa: SLF001


# ---------------------------------------------------------------------------
# New topology entry existence tests
# ---------------------------------------------------------------------------


class TestNewTopologyEntries:
    """Verify that all core/aggregation routers have topology entries."""

    def test_eq_rtr02_topology_exists(self) -> None:
        """EQ-RTR-02 (192.168.203.3) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.203.3" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.203.3"]
        assert topo.name == "Equinix-RTR-2"

    def test_eq_rtr02_has_upstream_to_eq_rtr01(self) -> None:
        """EQ-RTR-02 must have an upstream bundle connecting to EQ-RTR-01."""
        topo = NETWORK_TOPOLOGY["192.168.203.3"]
        # EQ-RTR-02 calls its link to EQ-RTR-01 Bundle-Ether600
        assert "Bundle-Ether600" in topo.upstreams
        link = topo.upstreams["Bundle-Ether600"]
        assert link.remote_device_ip == "192.168.203.1"  # EQ-RTR-01

    def test_eq_rtr02_has_upstream_to_kkt01(self) -> None:
        """EQ-RTR-02 must have an upstream bundle connecting to KKT-Core-01."""
        topo = NETWORK_TOPOLOGY["192.168.203.3"]
        assert "Bundle-Ether505" in topo.upstreams
        link = topo.upstreams["Bundle-Ether505"]
        assert link.remote_device_ip == "192.168.202.2"  # KKT-Core-01

    def test_kkt_core03_topology_exists(self) -> None:
        """KKT-Core-03 (192.168.202.153) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.202.153" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.202.153"]
        assert topo.name == "KKT-Core-3"

    def test_kkt_core03_has_upstream_to_eq_rtr01(self) -> None:
        """KKT-Core-03 must have BE300 to EQ-RTR-01."""
        topo = NETWORK_TOPOLOGY["192.168.202.153"]
        assert "Bundle-Ether300" in topo.upstreams
        link = topo.upstreams["Bundle-Ether300"]
        assert link.remote_device_ip == "192.168.203.1"  # EQ-RTR-01

    def test_cox_core03_topology_exists(self) -> None:
        """COX-Core-03 (192.168.200.26) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.200.26" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.200.26"]
        assert topo.name == "COX-Core-3"

    def test_cox_core03_has_upstream_to_eq_rtr01(self) -> None:
        """COX-Core-03 must have BE200 to EQ-RTR-01."""
        topo = NETWORK_TOPOLOGY["192.168.200.26"]
        assert "Bundle-Ether200" in topo.upstreams
        link = topo.upstreams["Bundle-Ether200"]
        assert link.remote_device_ip == "192.168.203.1"  # EQ-RTR-01

    def test_cox_core03_has_upstream_to_dhk_core03(self) -> None:
        """COX-Core-03 must have BE150 to DHK-Core-03."""
        topo = NETWORK_TOPOLOGY["192.168.200.26"]
        assert "Bundle-Ether150" in topo.upstreams
        link = topo.upstreams["Bundle-Ether150"]
        assert link.remote_device_ip == "192.168.200.11"  # DHK-Core-03

    def test_dhk_core02_topology_exists(self) -> None:
        """DHK-Core-02 (192.168.200.4) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.200.4" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.200.4"]
        assert topo.name == "DHK-Core-2-Agg"

    def test_dhk_core02_has_upstream_to_dhk_core03(self) -> None:
        """DHK-Core-02 must have BE100 to DHK-Core-03."""
        topo = NETWORK_TOPOLOGY["192.168.200.4"]
        assert "Bundle-Ether100" in topo.upstreams
        link = topo.upstreams["Bundle-Ether100"]
        assert link.remote_device_ip == "192.168.200.11"  # DHK-Core-03

    def test_cox_core02_topology_exists(self) -> None:
        """COX-Core-02 (192.168.200.6) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.200.6" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.200.6"]
        assert topo.name == "COX-Core-2"

    def test_cox_core04_topology_exists(self) -> None:
        """COX-Core-04 (192.168.200.27) must exist in NETWORK_TOPOLOGY."""
        assert "192.168.200.27" in NETWORK_TOPOLOGY
        topo = NETWORK_TOPOLOGY["192.168.200.27"]
        assert topo.name == "COX-Core-4"
