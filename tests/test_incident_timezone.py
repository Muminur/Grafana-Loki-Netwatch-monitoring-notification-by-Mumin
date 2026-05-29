"""Tests for incident timestamp timezone anomalies B and C.

Anomaly B  (multiple write sites)
    Several code paths write datetime.now(UTC) into DB columns that are
    supposed to carry NAIVE Bangladesh-time (UTC+6) face values:
      - acknowledge_incident: IncidentAck.created_at and AlertLog.acknowledged_at
      - _resolve_noise_alerts_on_startup: AlertLog.resolved_at
      - crud.update_incident_status / resolve_incident: Incident.resolved_at
      - Model column defaults: IncidentAck.created_at, ShiftHandoff.created_at
    DESIRED: each of these stores a tzinfo=None datetime whose face value
    matches Bangladesh local time (UTC+6), i.e. ~datetime.now(UTC) + 6h.

Anomaly C  (live path timestamp format)
    alert["timestamp"] and incident started_at / last_alert come from
    enriched.parsed.timestamp.isoformat(), which for a real tz-aware datetime
    produces "...+06:00". The DB path stores naive isoformat.
    The prune helpers compare these as raw strings, so the "+06:00" suffix
    breaks lexicographic ordering.
    DESIRED: add_alert_to_store must strip the UTC-offset and store only the
    naive BDT face value (no "+06:00" suffix).
"""

# ruff: noqa: SLF001, DTZ001, DTZ005, ARG001, ARG002, N801
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

import src.api.routes as routes_mod
from src.database.models import AlertLog, Base, Incident, IncidentAck, ShiftHandoff

_UTC = UTC
_BDT = timezone(timedelta(hours=6))

_NOW_TOLERANCE_SECONDS = 120  # face value must be within 2 min of BDT now


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bdt_now_naive() -> datetime:
    """Return current BDT time as a naive datetime (tzinfo=None)."""
    return datetime.now(_BDT).replace(tzinfo=None)


def _utc_now_naive() -> datetime:
    return datetime.now(_UTC).replace(tzinfo=None)


@pytest.fixture
async def async_db():
    """In-memory SQLite async engine with the full schema."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def client():
    """httpx AsyncClient bound to the FastAPI app."""
    from src.main import app

    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.fixture
def clean_stores():
    """Snapshot and restore all in-memory stores + module flags."""
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


# ---------------------------------------------------------------------------
# Anomaly B — crud.resolve_incident writes naive BDT, not UTC
# ---------------------------------------------------------------------------


class TestAnomalyB_CrudResolveIncident:
    """crud.resolve_incident must write naive BDT timestamps, not UTC."""

    @pytest.mark.asyncio
    async def test_resolved_at_is_naive_bdt_when_none_passed(self, async_db) -> None:
        """resolve_incident(resolved_at=None) must store naive BDT face value.

        Pins that resolved_at.tzinfo is None AND the face value is close
        to now-in-BDT (not 6 hours behind).
        """
        from sqlalchemy import select

        from src.database.crud import resolve_incident

        # Seed: an Incident row and an AlertLog row that carries the same
        # incident_id so the UPDATE on AlertLog also fires.
        incident_id = "INC-20260523-001"
        bdt_now_naive = _bdt_now_naive()

        async with AsyncSession(async_db) as session:
            inc = Incident(
                id=incident_id,
                title="Test incident",
                created_at=bdt_now_naive,
            )
            alert = AlertLog(
                timestamp=bdt_now_naive,
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                subfacility="",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="neighbor 2001:de8:4::2:4482:1 Down",
                raw="raw",
                classification="CRITICAL",
                incident_id=incident_id,
            )
            session.add_all([inc, alert])
            await session.commit()

        async with AsyncSession(async_db) as session:
            await resolve_incident(session, incident_id, resolved_at=None)
            await session.commit()

        # Read back the Incident row
        async with AsyncSession(async_db) as session:
            result = await session.execute(
                select(Incident).where(Incident.id == incident_id)
            )
            row = result.scalar_one()
            assert row.resolved_at is not None, "resolved_at must be set"
            # Must be naive (tzinfo=None)
            assert row.resolved_at.tzinfo is None, (
                f"resolved_at.tzinfo must be None (naive), "
                f"got {row.resolved_at.tzinfo!r}. "
                "Anomaly B: crud.resolve_incident uses datetime.now(UTC)."
            )
            # Face value must be close to now-in-BDT, NOT 6h behind
            delta = abs((row.resolved_at - _bdt_now_naive()).total_seconds())
            assert delta < _NOW_TOLERANCE_SECONDS, (
                f"resolved_at face value {row.resolved_at.isoformat()} is "
                f"{delta:.0f}s away from BDT now. "
                "Expected naive BDT face value (UTC+6), got UTC (6h behind)."
            )


# ---------------------------------------------------------------------------
# Anomaly B — IncidentAck.created_at model default is naive BDT
# ---------------------------------------------------------------------------


class TestAnomalyB_IncidentAckDefault:
    """IncidentAck.created_at column default must produce naive BDT."""

    @pytest.mark.asyncio
    async def test_incident_ack_created_at_default_is_naive_bdt(self, async_db) -> None:
        """Inserting an IncidentAck without created_at → naive BDT face value.

        The current default is lambda: datetime.now(UTC), which stores a
        value ~6h behind Bangladesh local time.
        """
        from sqlalchemy import select

        async with AsyncSession(async_db) as session:
            ack = IncidentAck(
                incident_id="ALERT-999",
                operator_name="test-operator",
                comment="test comment",
                # created_at deliberately omitted to exercise the column default
            )
            session.add(ack)
            await session.flush()
            await session.refresh(ack)
            ack_id = ack.id
            await session.commit()

        async with AsyncSession(async_db) as session:
            result = await session.execute(
                select(IncidentAck).where(IncidentAck.id == ack_id)
            )
            row = result.scalar_one()
            assert row.created_at is not None, "created_at must be populated by default"
            assert row.created_at.tzinfo is None, (
                f"IncidentAck.created_at.tzinfo must be None (naive BDT), "
                f"got {row.created_at.tzinfo!r}. "
                "Anomaly B: model default is lambda: datetime.now(UTC)."
            )
            delta = abs((row.created_at - _bdt_now_naive()).total_seconds())
            assert delta < _NOW_TOLERANCE_SECONDS, (
                f"IncidentAck.created_at face value {row.created_at.isoformat()} "
                f"is {delta:.0f}s from BDT now. "
                "Expected naive BDT (UTC+6); got UTC (6h behind)."
            )


# ---------------------------------------------------------------------------
# Anomaly B — ShiftHandoff.created_at model default is naive BDT
# ---------------------------------------------------------------------------


class TestAnomalyB_ShiftHandoffDefault:
    """ShiftHandoff.created_at column default must produce naive BDT."""

    @pytest.mark.asyncio
    async def test_shift_handoff_created_at_default_is_naive_bdt(
        self, async_db
    ) -> None:
        """Inserting a ShiftHandoff without created_at → naive BDT face value."""
        from sqlalchemy import select

        async with AsyncSession(async_db) as session:
            handoff = ShiftHandoff(
                shift_name="night",
                shift_date="2026-05-23",
                operator_name="test-noc",
                notes="handover note",
                # created_at deliberately omitted
            )
            session.add(handoff)
            await session.flush()
            await session.refresh(handoff)
            hid = handoff.id
            await session.commit()

        async with AsyncSession(async_db) as session:
            result = await session.execute(
                select(ShiftHandoff).where(ShiftHandoff.id == hid)
            )
            row = result.scalar_one()
            assert row.created_at.tzinfo is None, (
                f"ShiftHandoff.created_at.tzinfo must be None (naive BDT), "
                f"got {row.created_at.tzinfo!r}. "
                "Anomaly B: model default is lambda: datetime.now(UTC)."
            )
            delta = abs((row.created_at - _bdt_now_naive()).total_seconds())
            assert delta < _NOW_TOLERANCE_SECONDS, (
                f"ShiftHandoff.created_at face value {row.created_at.isoformat()} "
                f"is {delta:.0f}s from BDT now. "
                "Expected naive BDT (UTC+6); got UTC (6h behind)."
            )


# ---------------------------------------------------------------------------
# Anomaly B — acknowledge_incident API endpoint stores naive BDT
# ---------------------------------------------------------------------------


class TestAnomalyB_AcknowledgeEndpoint:
    """The /api/incidents/{id}/acknowledge endpoint must write naive BDT."""

    @pytest.mark.asyncio
    async def test_acknowledged_at_json_is_naive_bdt(
        self, client: AsyncClient, clean_stores: None, async_db
    ) -> None:
        """POST /api/incidents/{id}/acknowledge → acknowledged_at is naive BDT.

        The API response's acknowledged_at must parse to a naive datetime
        whose face value is close to now-in-BDT (not 6h behind UTC).
        """

        # Seed in-memory store and wire up the DB engine
        incident_id = "ALERT-5001"
        routes_mod._incidents_store.append(
            {"id": incident_id, "title": "BGP Down SG.GS"}
        )
        routes_mod._db_engine = async_db

        # Seed the AlertLog row so the DB UPDATE path is also exercised
        bdt_now_naive = _bdt_now_naive()
        async with AsyncSession(async_db) as session:
            alert = AlertLog(
                id=5001,
                timestamp=bdt_now_naive,
                source_ip="192.168.203.1",
                device_name="Equinix-RTR-1",
                hostname="BSCCL-EQ-RTR-01",
                facility="ROUTING",
                subfacility="",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="neighbor 2001:de8:4::2:4482:1 Down",
                raw="raw",
                classification="CRITICAL",
            )
            session.add(alert)
            await session.commit()

        async with client as c:
            resp = await c.post(
                f"/api/incidents/{incident_id}/acknowledge",
                json={"operator_name": "test-noc", "comment": "ack from test"},
            )

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        body = resp.json()
        assert "acknowledged_at" in body

        ack_ts_str = body["acknowledged_at"]
        # Must parse without error
        ack_dt = datetime.fromisoformat(ack_ts_str)
        # DESIRED: naive (no +06:00 / +00:00 suffix)
        assert ack_dt.tzinfo is None, (
            f"acknowledged_at in JSON must be naive BDT (no offset), "
            f"got {ack_ts_str!r}. "
            "Anomaly B: acknowledge_incident uses datetime.now(UTC)."
        )
        # Face value must be BDT now, not 6h behind
        delta = abs((ack_dt - _bdt_now_naive()).total_seconds())
        assert delta < _NOW_TOLERANCE_SECONDS, (
            f"acknowledged_at face value {ack_ts_str} is {delta:.0f}s from BDT now. "
            "Expected naive BDT (UTC+6)."
        )

    @pytest.mark.asyncio
    async def test_incident_ack_row_created_at_is_naive_bdt(
        self, client: AsyncClient, clean_stores: None, async_db
    ) -> None:
        """IncidentAck persisted by acknowledge_incident must carry naive BDT."""
        from sqlalchemy import select

        incident_id = "ALERT-5002"
        routes_mod._incidents_store.append(
            {"id": incident_id, "title": "BGP Down TCLOUD"}
        )
        routes_mod._db_engine = async_db

        async with client as c:
            resp = await c.post(
                f"/api/incidents/{incident_id}/acknowledge",
                json={"operator_name": "noc-ops", "comment": ""},
            )
        assert resp.status_code == 200

        async with AsyncSession(async_db) as session:
            result = await session.execute(
                select(IncidentAck).where(IncidentAck.incident_id == incident_id)
            )
            row = result.scalar_one_or_none()
        assert row is not None, "IncidentAck row must have been persisted"
        assert row.created_at.tzinfo is None, (
            f"Persisted IncidentAck.created_at.tzinfo must be None (naive BDT), "
            f"got {row.created_at.tzinfo!r}. "
            "Anomaly B: acknowledge_incident passes datetime.now(UTC) to IncidentAck."
        )
        delta = abs((row.created_at - _bdt_now_naive()).total_seconds())
        assert delta < _NOW_TOLERANCE_SECONDS, (
            f"IncidentAck.created_at face value {row.created_at.isoformat()} "
            f"is {delta:.0f}s from BDT now. Expected UTC+6 naive."
        )


# ---------------------------------------------------------------------------
# Anomaly C — add_alert_to_store must strip +06:00 from tz-aware timestamps
# ---------------------------------------------------------------------------


def _make_enriched_tz_aware(
    *,
    device_name: str = "Equinix-RTR-1",
    source_ip: str = "192.168.203.1",
    mnemonic: str = "ADJCHANGE",
    message: str = (
        "neighbor 2001:de8:4::2:4482:1 Down - BGP Notification received, "
        "maximum number of prefixes reached (VRF: network) (AS: 24482)"
    ),
    bgp_neighbor: str = "2001:de8:4::2:4482:1",
    as_number: int = 24482,
    as_name: str = "SG.GS",
    classification: str = "CRITICAL",
    rule_id: str = "",
) -> MagicMock:
    """Build a mock EnrichedLog with a REAL tz-aware datetime on parsed.timestamp.

    Unlike the helpers in test_bgp_resolution.py that return a fake
    isoformat string, this sets parsed.timestamp to a real datetime object
    so that .isoformat() naturally yields "2026-05-23T16:22:56+06:00".
    This exposes Anomaly C where the "+06:00" offset leaks into stored strings.
    """
    real_ts = datetime(2026, 5, 23, 16, 22, 56, tzinfo=_BDT)

    enriched = MagicMock()
    enriched.device_name = device_name
    enriched.interface_name = ""
    enriched.interface_description = ""
    enriched.bgp_neighbor = bgp_neighbor
    enriched.as_number = as_number
    enriched.as_name = as_name
    enriched.classification = classification
    enriched.event_type = ""
    enriched.client_name = ""
    enriched.vrf = ""
    enriched.rule_id = rule_id
    enriched.parsed = MagicMock()
    enriched.parsed.source_ip = source_ip
    enriched.parsed.mnemonic = mnemonic
    enriched.parsed.message = message
    enriched.parsed.hostname = device_name
    enriched.parsed.facility = "ROUTING"
    # Use the REAL datetime so .isoformat() produces "...+06:00"
    enriched.parsed.timestamp = real_ts
    return enriched


class TestAnomalyC:
    """Timestamps stored by add_alert_to_store must be naive (no +06:00 suffix)."""

    def test_alert_timestamp_has_no_tz_offset_suffix(self, clean_stores: None) -> None:
        """alert['timestamp'] in _alerts_store must not contain '+06:00' or '+06'.

        CRITICAL TEST NUANCE: parsed.timestamp is a REAL tz-aware datetime
        (not a mock with a pre-set isoformat string), so .isoformat() yields
        '2026-05-23T16:22:56+06:00'. The code under test must strip the offset
        before storing.
        """
        from src.api.routes import _alerts_store, add_alert_to_store

        enriched = _make_enriched_tz_aware()
        correlated = MagicMock()
        correlated.incident_id = ""
        correlated.is_symptom = False
        correlated.is_flapping = False
        correlated.suppress_notification = False

        add_alert_to_store(enriched, correlated)

        assert _alerts_store, "At least one alert must have been appended"
        stored_ts = _alerts_store[-1]["timestamp"]
        assert "+" not in stored_ts, (
            f"alert['timestamp'] must not contain a UTC offset, "
            f"got {stored_ts!r}. "
            "Anomaly C: enriched.parsed.timestamp.isoformat() returns '...+06:00' "
            "and this is stored verbatim instead of being stripped to naive BDT."
        )

    def test_alert_timestamp_parses_to_naive_datetime(self, clean_stores: None) -> None:
        """datetime.fromisoformat(alert['timestamp']).tzinfo must be None."""
        from src.api.routes import _alerts_store, add_alert_to_store

        enriched = _make_enriched_tz_aware()
        correlated = MagicMock()
        correlated.incident_id = ""
        correlated.is_symptom = False
        correlated.is_flapping = False
        correlated.suppress_notification = False

        add_alert_to_store(enriched, correlated)

        stored_ts = _alerts_store[-1]["timestamp"]
        parsed = datetime.fromisoformat(stored_ts)
        assert parsed.tzinfo is None, (
            f"Stored timestamp {stored_ts!r} parses to a tz-aware datetime. "
            "Anomaly C: must be naive BDT face value."
        )

    def test_incident_started_at_has_no_tz_offset_suffix(
        self, clean_stores: None
    ) -> None:
        """Incident started_at in _incidents_store must not contain '+06:00'."""
        from src.api.routes import _incidents_store, add_alert_to_store

        enriched = _make_enriched_tz_aware()
        correlated = MagicMock()
        correlated.incident_id = ""
        correlated.is_symptom = False
        correlated.is_flapping = False
        correlated.suppress_notification = False

        add_alert_to_store(enriched, correlated)

        adjchange = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        assert adjchange, "An ADJCHANGE incident must have been created"
        started_at = adjchange[0]["started_at"]
        assert "+" not in started_at, (
            f"incident started_at must not contain a UTC offset, "
            f"got {started_at!r}. "
            "Anomaly C: offset leaked from enriched.parsed.timestamp.isoformat()."
        )

    def test_incident_last_alert_has_no_tz_offset_suffix(
        self, clean_stores: None
    ) -> None:
        """Incident last_alert in _incidents_store must not contain '+06:00'."""
        from src.api.routes import _incidents_store, add_alert_to_store

        enriched = _make_enriched_tz_aware()
        correlated = MagicMock()
        correlated.incident_id = ""
        correlated.is_symptom = False
        correlated.is_flapping = False
        correlated.suppress_notification = False

        add_alert_to_store(enriched, correlated)

        adjchange = [
            i
            for i in _incidents_store
            if i["mnemonic"] == "ADJCHANGE" and i["device"] == "Equinix-RTR-1"
        ]
        assert adjchange, "An ADJCHANGE incident must have been created"
        last_alert = adjchange[0]["last_alert"]
        assert "+" not in last_alert, (
            f"incident last_alert must not contain a UTC offset, "
            f"got {last_alert!r}. "
            "Anomaly C: offset leaked from enriched.parsed.timestamp.isoformat()."
        )


# ---------------------------------------------------------------------------
# Test 1 — Anomaly B-1 (REAL BUG): create_shift_handoff endpoint writes naive BDT
# ---------------------------------------------------------------------------


class TestAnomalyB_ShiftHandoffEndpoint:
    """POST /api/shift/handoff must store naive BDT created_at, not UTC."""

    @pytest.mark.asyncio
    async def test_shift_handoff_endpoint_created_at_is_naive_bdt(
        self, client: AsyncClient, clean_stores: None, async_db
    ) -> None:
        """POST /api/shift/handoff created_at row must be naive BDT face value.

        The endpoint does ``now = datetime.now(UTC)`` and passes
        ``created_at=now`` to ShiftHandoff(...), overriding the model default
        of ``now_bdt_naive``. The stored face value will therefore be ~6 hours
        behind Bangladesh local time.

        Anomaly B: create_shift_handoff uses datetime.now(UTC) overriding
        the model default.
        """
        from sqlalchemy import select

        routes_mod._db_engine = async_db

        async with client as c:
            resp = await c.post(
                "/api/shift/handoff",
                json={
                    "shift_name": "night",
                    "shift_date": "2026-05-29",
                    "operator_name": "test-noc",
                    "notes": "endpoint handoff",
                },
            )

        assert resp.status_code in (
            200,
            201,
        ), f"Expected 200 or 201, got {resp.status_code}: {resp.text}"

        async with AsyncSession(async_db) as session:
            result = await session.execute(
                select(ShiftHandoff).where(
                    ShiftHandoff.operator_name == "test-noc",
                    ShiftHandoff.shift_name == "night",
                )
            )
            row = result.scalar_one_or_none()

        assert row is not None, "ShiftHandoff row must have been persisted"
        assert row.created_at is not None, "created_at must be set"
        assert row.created_at.tzinfo is None, (
            f"ShiftHandoff.created_at.tzinfo must be None (naive), "
            f"got {row.created_at.tzinfo!r}. "
            "Anomaly B: create_shift_handoff uses datetime.now(UTC) overriding "
            "the model default."
        )
        delta = abs((row.created_at - _bdt_now_naive()).total_seconds())
        assert delta < _NOW_TOLERANCE_SECONDS, (
            f"ShiftHandoff.created_at face value {row.created_at.isoformat()} is "
            f"{delta:.0f}s away from BDT now. "
            "Expected naive BDT face value (UTC+6) but got UTC (6h behind). "
            "Anomaly B: create_shift_handoff uses datetime.now(UTC) overriding "
            "the model default."
        )


# ---------------------------------------------------------------------------
# Test 2 — Anomaly B/I-4 (REAL BUG): resolve_silent_faults_in_db writes UTC
# ---------------------------------------------------------------------------


class TestAnomalyB_ResolveSilentFaults:
    """resolve_silent_faults_in_db must write naive BDT resolved_at, not UTC."""

    @pytest.mark.asyncio
    async def test_resolved_at_is_naive_bdt_face_value(self, async_db) -> None:
        """resolve_silent_faults_in_db stores resolved_at as naive BDT face value.

        The function does ``now = datetime.now(UTC)`` and writes
        ``resolved_at=now``. The stored face value will therefore be ~6 hours
        behind Bangladesh local time.

        Anomaly B/I-4: resolve_silent_faults_in_db uses datetime.now(UTC).
        """
        from src.api.routes import resolve_silent_faults_in_db

        bdt_now = _bdt_now_naive()
        async with AsyncSession(async_db) as session:
            alert = AlertLog(
                timestamp=bdt_now,
                source_ip="192.168.203.1",
                device_name="EQ-RTR-01",
                hostname="BSCCL-EQ-RTR-01",
                facility="OPTICAL",
                subfacility="",
                severity_level=3,
                mnemonic="RX_FAULT",
                message="HundredGigE0/3/2/2 Rx fault detected",
                raw="raw syslog line",
                interface_name="HundredGigE0/3/2/2",
                classification="INFO",
                resolved_at=None,
            )
            session.add(alert)
            await session.flush()
            alert_id = alert.id
            await session.commit()

        count = await resolve_silent_faults_in_db(
            async_db, "EQ-RTR-01", {"HundredGigE0/3/2/2"}
        )

        async with AsyncSession(async_db) as session:
            from sqlalchemy import select as _select  # noqa: PLC0415

            result = await session.execute(
                _select(AlertLog).where(AlertLog.id == alert_id)
            )
            row = result.scalar_one()
            resolved_at = row.resolved_at

        assert resolved_at is not None, (
            f"resolved_at must be set after resolve_silent_faults_in_db "
            f"(returned count={count}). "
            "If count==0, the timestamp cutoff used datetime.now(UTC) which "
            "made the naive-BDT seeded row appear too old."
        )
        assert resolved_at.tzinfo is None, (
            f"resolved_at.tzinfo must be None (naive), "
            f"got {resolved_at.tzinfo!r}. "
            "Anomaly B/I-4: resolve_silent_faults_in_db uses datetime.now(UTC)."
        )
        delta = abs((resolved_at - _bdt_now_naive()).total_seconds())
        assert delta < _NOW_TOLERANCE_SECONDS, (
            f"resolved_at face value {resolved_at.isoformat()} is "
            f"{delta:.0f}s away from BDT now. "
            "Expected naive BDT face value (UTC+6) but got UTC (6h behind). "
            "Anomaly B/I-4: resolve_silent_faults_in_db uses datetime.now(UTC)."
        )


# ---------------------------------------------------------------------------
# Test 3 — B-2 (HARDENING, likely GREEN): _to_naive_iso contract
# ---------------------------------------------------------------------------


class TestToNaiveIso:
    """_to_naive_iso must always return a naive, offset-free ISO string."""

    def test_tz_aware_datetime_stripped_to_naive_iso(self) -> None:
        """_to_naive_iso(tz-aware BDT datetime) must produce a no-offset ISO string."""
        from src.api.routes import _to_naive_iso

        ts = datetime(2026, 5, 29, 16, 22, 56, tzinfo=_BDT)
        result = _to_naive_iso(ts)
        assert "+" not in result, (
            f"_to_naive_iso returned {result!r} which still contains '+'. "
            "Expected the UTC offset to be stripped."
        )

    def test_tz_aware_datetime_parses_to_naive(self) -> None:
        """datetime.fromisoformat(_to_naive_iso(tz-aware)) must have tzinfo=None."""
        from src.api.routes import _to_naive_iso

        ts = datetime(2026, 5, 29, 16, 22, 56, tzinfo=_BDT)
        result = _to_naive_iso(ts)
        parsed = datetime.fromisoformat(result)
        assert parsed.tzinfo is None, (
            f"_to_naive_iso({ts!r}) returned {result!r} which parses to a "
            f"tz-aware datetime (tzinfo={parsed.tzinfo!r}). Expected naive."
        )

    def test_naive_datetime_returned_verbatim(self) -> None:
        """_to_naive_iso(naive datetime) must return the face-value ISO string."""
        from src.api.routes import _to_naive_iso

        ts = datetime(2026, 5, 29, 16, 22, 56)
        result = _to_naive_iso(ts)
        assert result == "2026-05-29T16:22:56", (
            f"_to_naive_iso(naive {ts!r}) returned {result!r}; "
            "expected '2026-05-29T16:22:56'."
        )


# ---------------------------------------------------------------------------
# Test 4 — M-3 + I-2 (COVERAGE, likely GREEN): _bgp_discriminator fallback chain
# ---------------------------------------------------------------------------


class TestBgpDiscriminator:
    """_bgp_discriminator fallback chain: neighbor → message → AS → empty."""

    def test_neighbor_wins_when_present(self) -> None:
        """When neighbor is non-empty, it is returned directly."""
        from src.api.routes import _bgp_discriminator

        result = _bgp_discriminator(
            "2001:de8:4::2:4482:1", 24482, "neighbor 10.0.0.1 Up"
        )
        assert (
            result == "2001:de8:4::2:4482:1"
        ), f"Expected neighbor '2001:de8:4::2:4482:1', got {result!r}."

    def test_message_fallback_when_neighbor_empty(self) -> None:
        """When neighbor is empty, the neighbor IP in message text is used."""
        from src.api.routes import _bgp_discriminator

        result = _bgp_discriminator("", 24482, "neighbor 10.0.0.1 Up")
        assert (
            result == "10.0.0.1"
        ), f"Expected '10.0.0.1' extracted from message, got {result!r}."

    def test_as_fallback_when_no_neighbor_token_in_message(self) -> None:
        """When neighbor is empty and message has no 'neighbor' token, AS is used.

        Regression guard for Anomaly D: a message like 'Bundle-Ether10 is Down'
        has no neighbor IP, so the AS number string is the last-resort key.
        """
        from src.api.routes import _bgp_discriminator

        result = _bgp_discriminator("", 24482, "Bundle-Ether10 is Down")
        assert (
            result == "24482"
        ), f"Expected AS string '24482' as fallback, got {result!r}."

    def test_empty_when_all_inputs_empty(self) -> None:
        """When neighbor, AS, and message all provide nothing, returns empty string.

        I-2 accepted contract: _bgp_discriminator('', 0, 'no peer info here') == ''.
        """
        from src.api.routes import _bgp_discriminator

        result = _bgp_discriminator("", 0, "no peer info here")
        assert (
            result == ""
        ), f"Expected empty string for all-empty inputs, got {result!r}."
