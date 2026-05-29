"""Tests for incident dedup anomalies A and D.

Anomaly A  (live path)
    Repeated independent CRITICAL events produce duplicate incident cards
    because add_alert_to_store keys each card on f"ALERT-{alert['id']}"
    where alert['id'] = next(_alert_id_counter). Since the counter is
    monotonic, every dispatch produces a unique id, the lookup
        next((i for i in _incidents_store if i["id"] == inc_id), None)
    always returns None, and a fresh card is appended instead of
    incrementing alert_count on the existing one.

Anomaly D  (DB-synthesis path)
    get_incidents() builds a recovery-state key of dev:BGP:<bgp_neighbor>
    when the row has bgp_neighbor set, or dev:BGP:<as_number> when it only
    has as_number. A DOWN row that carries bgp_neighbor and its UP row that
    only carries as_number get different keys, so the UP never supersedes
    the DOWN and a stale active incident survives.
"""

# ruff: noqa: SLF001, DTZ001, ARG001, ARG002
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import src.api.routes as routes_mod
from src.database.models import AlertLog, Base

_BDT = timezone(timedelta(hours=6))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    timestamp_isoformat: str = "2026-05-23T16:22:56",
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
    enriched.parsed.facility = "ROUTING"
    enriched.parsed.timestamp = MagicMock()
    enriched.parsed.timestamp.isoformat.return_value = timestamp_isoformat
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
# Fixture: clean global state before / after each test
# ---------------------------------------------------------------------------


@pytest.fixture
def clean_stores():
    """Snapshot and restore in-memory stores + module flags."""
    orig_alerts = list(routes_mod._alerts_store)
    orig_incidents = list(routes_mod._incidents_store)
    orig_noise = routes_mod._hardware_defects_as_noise
    orig_engine = routes_mod._db_engine

    routes_mod._alerts_store.clear()
    routes_mod._incidents_store.clear()
    routes_mod._hardware_defects_as_noise = False
    routes_mod._db_engine = None

    try:
        yield
    finally:
        routes_mod._alerts_store.clear()
        routes_mod._alerts_store.extend(orig_alerts)
        routes_mod._incidents_store.clear()
        routes_mod._incidents_store.extend(orig_incidents)
        routes_mod._hardware_defects_as_noise = orig_noise
        routes_mod._db_engine = orig_engine


@pytest.fixture
async def async_db():
    """In-memory SQLite async engine with the full schema."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


# ---------------------------------------------------------------------------
# Anomaly A — three identical BGP DOWN dispatches produce exactly 1 incident
# ---------------------------------------------------------------------------

_BGP_DOWN_MSG = (
    "neighbor 2001:de8:4::2:4482:1 Down - BGP Notification received, "
    "maximum number of prefixes reached (VRF: network) (AS: 24482)"
)


class TestAnomalyA:
    """Repeated independent CRITICAL events must collapse to one incident card."""

    def test_three_dispatches_produce_one_incident(self, clean_stores: None) -> None:
        """3x BGP ADJCHANGE Down (same device+neighbor, incident_id='') = 1 incident.

        Pins Anomaly A: dedup key must come from logical event identity
        (device + mnemonic + discriminator), NOT the monotonic alert counter.
        """
        from src.api.routes import _incidents_store, add_alert_to_store

        for _ in range(3):
            enriched = _make_enriched(
                device_name="Equinix-RTR-1",
                source_ip="192.168.203.1",
                mnemonic="ADJCHANGE",
                message=_BGP_DOWN_MSG,
                bgp_neighbor="2001:de8:4::2:4482:1",
                as_number=24482,
                as_name="SG.GS",
                classification="CRITICAL",
            )
            correlated = _make_correlated(incident_id="")
            add_alert_to_store(enriched, correlated)

        matching = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        assert len(matching) == 1, (
            f"Expected 1 incident card; got {len(matching)}. "
            "Anomaly A: each dispatch created a new ALERT-N id instead of "
            "updating the existing incident."
        )

    def test_three_dispatches_alert_count_equals_three(
        self, clean_stores: None
    ) -> None:
        """The single collapsed incident must record alert_count == 3."""
        from src.api.routes import _incidents_store, add_alert_to_store

        for _ in range(3):
            enriched = _make_enriched(
                device_name="Equinix-RTR-1",
                source_ip="192.168.203.1",
                mnemonic="ADJCHANGE",
                message=_BGP_DOWN_MSG,
                bgp_neighbor="2001:de8:4::2:4482:1",
                as_number=24482,
                as_name="SG.GS",
                classification="CRITICAL",
            )
            correlated = _make_correlated(incident_id="")
            add_alert_to_store(enriched, correlated)

        matching = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        # If count is wrong the earlier test already fails; report clearly here too.
        if len(matching) != 1:
            pytest.fail(
                f"Expected 1 incident; got {len(matching)}. "
                "Cannot assert alert_count without a single collapsed card."
            )
        assert (
            matching[0].get("alert_count") == 3
        ), f"alert_count should be 3, got {matching[0].get('alert_count')}"

    def test_three_dispatches_last_alert_updated_to_most_recent(
        self, clean_stores: None
    ) -> None:
        """last_alert on the collapsed incident must equal the most recent timestamp."""
        from src.api.routes import _incidents_store, add_alert_to_store

        timestamps = [
            "2026-05-23T16:22:56",
            "2026-05-23T16:22:57",
            "2026-05-23T16:22:58",
        ]
        for ts in timestamps:
            enriched = _make_enriched(
                device_name="Equinix-RTR-1",
                source_ip="192.168.203.1",
                mnemonic="ADJCHANGE",
                message=_BGP_DOWN_MSG,
                bgp_neighbor="2001:de8:4::2:4482:1",
                as_number=24482,
                as_name="SG.GS",
                classification="CRITICAL",
                timestamp_isoformat=ts,
            )
            correlated = _make_correlated(incident_id="")
            add_alert_to_store(enriched, correlated)

        matching = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        if len(matching) != 1:
            pytest.fail(
                f"Expected 1 incident; got {len(matching)}. "
                "Cannot assert last_alert."
            )
        assert matching[0]["last_alert"] == "2026-05-23T16:22:58", (
            f"last_alert should be the most recent timestamp, "
            f"got {matching[0]['last_alert']!r}"
        )

    def test_two_different_neighbors_same_device_produce_two_incidents(
        self, clean_stores: None
    ) -> None:
        """Guard against over-collapsing: 2 distinct neighbors = 2 incidents."""
        from src.api.routes import _incidents_store, add_alert_to_store

        for neighbor, as_num in [
            ("2001:de8:4::2:4482:1", 24482),
            ("2001:de8:4::39:9077:1", 399077),
        ]:
            enriched = _make_enriched(
                device_name="Equinix-RTR-1",
                source_ip="192.168.203.1",
                mnemonic="ADJCHANGE",
                message=(
                    f"neighbor {neighbor} Down - BGP Notification received, "
                    f"maximum number of prefixes reached "
                    f"(VRF: network) (AS: {as_num})"
                ),
                bgp_neighbor=neighbor,
                as_number=as_num,
                classification="CRITICAL",
            )
            correlated = _make_correlated(incident_id="")
            add_alert_to_store(enriched, correlated)

        matching = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        assert len(matching) == 2, (
            f"Different neighbors must produce separate incidents; "
            f"got {len(matching)}."
        )


# ---------------------------------------------------------------------------
# Anomaly D — DOWN (bgp_neighbor set) + UP (only as_number) → no active incident
# ---------------------------------------------------------------------------


class TestAnomalyD:
    """DB-synthesis must resolve ADJCHANGE DOWN when UP row omits bgp_neighbor."""

    @pytest.mark.asyncio
    async def test_up_with_only_asn_cancels_down_with_neighbor(self, async_db) -> None:
        """DOWN (bgp_neighbor="2001:de8:4::2:4482:1") followed by UP (bgp_neighbor="").

        With _incidents_store empty, get_incidents() uses the DB-synthesis path.
        DESIRED: no active incident — the UP (even with bgp_neighbor empty) must
        cancel the DOWN via the shared as_number=24482.

        Current bug: DOWN key = "Equinix-RTR-1:BGP:2001:de8:4::2:4482:1"
                     UP key   = "Equinix-RTR-1:BGP:24482"
        They never match in latest_state, so state stays "active" and the
        stale incident card is returned.
        """
        down_ts = datetime(2026, 5, 23, 13, 0, 0)  # naive BDT face value
        up_ts = datetime(2026, 5, 23, 13, 5, 0)  # 5 minutes later (newer)

        async with AsyncSession(async_db) as session:
            down_row = AlertLog(
                timestamp=down_ts,
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                subfacility="BGP",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message=(
                    "neighbor 2001:de8:4::2:4482:1 Down - BGP Notification received, "
                    "maximum number of prefixes reached (VRF: network) (AS: 24482)"
                ),
                raw="raw-down",
                classification="CRITICAL",
                bgp_neighbor="2001:de8:4::2:4482:1",
                as_number=24482,
                as_name="SG.GS",
            )
            # UP row deliberately omits bgp_neighbor to reproduce the mismatch.
            up_row = AlertLog(
                timestamp=up_ts,
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                subfacility="BGP",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message=("neighbor 2001:de8:4::2:4482:1 Up (VRF: network) (AS: 24482)"),
                raw="raw-up",
                classification="WARNING",
                bgp_neighbor="",  # <-- the discriminator mismatch
                as_number=24482,
                as_name="SG.GS",
                resolved_at=None,
            )
            session.add_all([down_row, up_row])
            await session.commit()

        orig_store = list(routes_mod._incidents_store)
        orig_engine = routes_mod._db_engine
        orig_noise = routes_mod._hardware_defects_as_noise

        routes_mod._incidents_store.clear()
        routes_mod._db_engine = async_db
        routes_mod._hardware_defects_as_noise = False

        try:
            incidents = await routes_mod.get_incidents()
        finally:
            routes_mod._incidents_store.clear()
            routes_mod._incidents_store.extend(orig_store)
            routes_mod._db_engine = orig_engine
            routes_mod._hardware_defects_as_noise = orig_noise

        active = [
            i
            for i in incidents
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        assert len(active) == 0, (
            f"Expected 0 active ADJCHANGE incidents (session recovered), "
            f"got {len(active)}. "
            "Anomaly D: DOWN key=dev:BGP:<neighbor> vs UP key=dev:BGP:<as_number> "
            "never match in latest_state so the stale DOWN persists."
        )


# ---------------------------------------------------------------------------
# M-1 — DB-synthesis must key incidents identically to the live path.
#
# The live path keys every card through _incident_group_key, which for a
# non-ADJCHANGE event keys on f"{device}:{mnemonic}:{interface}" and
# deliberately IGNORES bgp_neighbor. The DB-synthesis path in get_incidents()
# previously folded bgp_neighbor into the key for non-ADJCHANGE rows, so the
# two paths disagreed: a pair of MAXPFX events that differ only by neighbor
# showed as ONE card live but split into N cards after a restart.
# ---------------------------------------------------------------------------


class TestNonAdjchangeKeyConsistency:
    """get_incidents() must reuse the canonical _incident_group_key.

    Pins M-1: live and DB-synthesis grouping must not diverge for
    non-ADJCHANGE BGP events that carry bgp_neighbor but no interface.
    """

    @pytest.mark.asyncio
    async def test_two_maxpfx_differing_only_by_neighbor_collapse_to_one(
        self, async_db
    ) -> None:
        """Two MAXPFX rows (no interface, different neighbor) → one card.

        Live _incident_group_key returns f"{device}:MAXPFX:" for both (the
        interface is empty and non-ADJCHANGE ignores the neighbor), collapsing
        them. DB-synthesis must agree.

        Current bug: DB-synthesis seen_key = f"{device}:MAXPFX:{bgp_neighbor}"
        so the two rows get different keys and produce two cards.
        """
        base_ts = datetime(2026, 5, 23, 13, 0, 0)  # naive BDT face value
        neighbors = ["2001:de8:4::2:4482:1", "2001:de8:4::39:9077:1"]
        async with AsyncSession(async_db) as session:
            for offset, neighbor in enumerate(neighbors):
                session.add(
                    AlertLog(
                        timestamp=base_ts + timedelta(seconds=offset),
                        source_ip="192.168.203.1",
                        device_name="Equinix-RTR-1",
                        hostname="BSCCL-EQ-RTR-01",
                        facility="ROUTING",
                        subfacility="BGP",
                        severity_level=4,
                        mnemonic="MAXPFX",
                        message=(
                            f"Number of prefixes received from neighbor {neighbor} "
                            "has reached the warning threshold"
                        ),
                        raw=f"raw-maxpfx-{offset}",
                        classification="CRITICAL",
                        interface_name="",
                        bgp_neighbor=neighbor,
                        as_number=24482,
                        as_name="SG.GS",
                        resolved_at=None,
                    )
                )
            await session.commit()

        orig_store = list(routes_mod._incidents_store)
        orig_engine = routes_mod._db_engine
        orig_noise = routes_mod._hardware_defects_as_noise

        routes_mod._incidents_store.clear()
        routes_mod._db_engine = async_db
        routes_mod._hardware_defects_as_noise = False

        try:
            incidents = await routes_mod.get_incidents()
        finally:
            routes_mod._incidents_store.clear()
            routes_mod._incidents_store.extend(orig_store)
            routes_mod._db_engine = orig_engine
            routes_mod._hardware_defects_as_noise = orig_noise

        matching = [
            i
            for i in incidents
            if i["mnemonic"] == "MAXPFX" and i["device"] == "Equinix-RTR-1"
        ]
        assert len(matching) == 1, (
            f"Expected 1 collapsed MAXPFX card (live keys non-ADJCHANGE on "
            f"interface only, ignoring bgp_neighbor); got {len(matching)}. "
            "DB-synthesis diverged from _incident_group_key by folding "
            "bgp_neighbor into the key."
        )
        assert matching[0].get("alert_count") == 2, (
            "Collapsed card must record alert_count == 2, got "
            f"{matching[0].get('alert_count')}."
        )

    @pytest.mark.asyncio
    async def test_two_updown_on_different_interfaces_stay_separate(
        self, async_db
    ) -> None:
        """Guard against over-collapsing: distinct interfaces = distinct cards."""
        base_ts = datetime(2026, 5, 23, 13, 0, 0)  # naive BDT face value
        interfaces = ["TenGigE0/0/1/3", "TenGigE0/0/1/7"]
        async with AsyncSession(async_db) as session:
            for offset, iface in enumerate(interfaces):
                session.add(
                    AlertLog(
                        timestamp=base_ts + timedelta(seconds=offset),
                        source_ip="192.168.203.1",
                        device_name="Equinix-RTR-1",
                        hostname="BSCCL-EQ-RTR-01",
                        facility="PKT_INFRA",
                        subfacility="LINK",
                        severity_level=3,
                        mnemonic="UPDOWN",
                        message=(f"Interface {iface}, changed state to Down"),
                        raw=f"raw-updown-{offset}",
                        classification="CRITICAL",
                        interface_name=iface,
                        bgp_neighbor="",
                        as_number=0,
                        as_name="",
                        resolved_at=None,
                    )
                )
            await session.commit()

        orig_store = list(routes_mod._incidents_store)
        orig_engine = routes_mod._db_engine
        orig_noise = routes_mod._hardware_defects_as_noise

        routes_mod._incidents_store.clear()
        routes_mod._db_engine = async_db
        routes_mod._hardware_defects_as_noise = False

        try:
            incidents = await routes_mod.get_incidents()
        finally:
            routes_mod._incidents_store.clear()
            routes_mod._incidents_store.extend(orig_store)
            routes_mod._db_engine = orig_engine
            routes_mod._hardware_defects_as_noise = orig_noise

        matching = [
            i
            for i in incidents
            if i["mnemonic"] == "UPDOWN" and i["device"] == "Equinix-RTR-1"
        ]
        assert len(matching) == 2, (
            f"Distinct interfaces must produce separate cards; got "
            f"{len(matching)}. The fix must key on interface, not collapse all "
            "non-ADJCHANGE events for a device."
        )
