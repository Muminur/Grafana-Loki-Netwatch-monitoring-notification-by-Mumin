"""End-to-end pipeline tests.

TDD: tests written BEFORE implementation (RED phase).

Tests the full path: raw syslog line → parse → classify → enrich →
correlate → DB store, plus the health endpoint under a real app mount.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.core.classifier import classify
from src.core.correlator import CorrelationEngine
from src.core.dedup import DedupEngine
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.database.crud import get_alerts_by_severity, insert_alert
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"

_BGP_DOWN_LINE = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Down - BGP Notification received (VRF: network) (AS: 399077)"
)


@pytest.fixture
async def db_session():
    """Fresh in-memory DB session for each test."""
    engine = await get_engine(IN_MEMORY_URL)
    await create_tables(engine)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await engine.dispose()


# ---------------------------------------------------------------------------
# 9. test_end_to_end_pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_end_to_end_pipeline(db_session: AsyncSession) -> None:
    """Full pipeline: raw log → parse → classify → enrich → correlate → DB.

    Verifies:
    - parse_syslog produces a ParsedLog
    - classify assigns a classification
    - enrich returns an EnrichedLog with device_name
    - correlator produces a CorrelatedEvent
    - AlertLog can be stored and retrieved from DB
    """
    # Step 1: Parse
    parsed = parse_syslog(_BGP_DOWN_LINE)
    assert parsed is not None, "parse_syslog must return a ParsedLog for valid input"
    assert parsed.source_ip == "192.168.203.1"
    assert parsed.mnemonic == "ADJCHANGE"

    # Step 2: Classify
    cls_result = classify(parsed)
    valid_classifications = ("CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN")
    assert cls_result.classification in valid_classifications

    # Step 3: Enrich
    enriched = enrich(parsed)
    assert enriched.device_name  # not empty
    assert enriched.classification == cls_result.classification

    # Step 4: Correlate
    correlator = CorrelationEngine()
    correlated = correlator.correlate(enriched)
    assert correlated.enriched is enriched

    # Step 5: Dedup check
    dedup = DedupEngine()
    should_send, reason = dedup.should_notify(enriched)
    assert isinstance(should_send, bool)
    assert reason in ("new", "suppressed_duplicate", "flapping", "bundle_grouped")

    # Step 6: Store in DB
    alert = AlertLog(
        timestamp=parsed.timestamp,
        source_ip=parsed.source_ip,
        device_name=enriched.device_name,
        hostname=parsed.hostname,
        rp_location=parsed.rp_location,
        facility=parsed.facility,
        subfacility=parsed.subfacility,
        severity_level=parsed.severity_level,
        mnemonic=parsed.mnemonic,
        message=parsed.message,
        raw=parsed.raw,
        classification=enriched.classification,
        interface_name=enriched.interface_name,
        interface_description=enriched.interface_description,
        client_name=enriched.client_name,
        bgp_neighbor=enriched.bgp_neighbor,
        as_number=enriched.as_number or 0,
        as_name=enriched.as_name,
        incident_id=correlated.incident_id,
        notification_sent=should_send,
    )
    saved = await insert_alert(db_session, alert)
    assert saved.id is not None

    # Step 7: Retrieve and verify
    results = await get_alerts_by_severity(db_session, enriched.classification)
    assert any(r.id == saved.id for r in results)
    assert any(r.source_ip == "192.168.203.1" for r in results)


# ---------------------------------------------------------------------------
# 10. test_health_endpoint_e2e
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_endpoint_e2e() -> None:
    """Full app: GET /health returns 200 with correct shape via ASGI test client."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "uptime_seconds" in body


# ---------------------------------------------------------------------------
# 11. test_pipeline_noise_not_stored_as_critical
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pipeline_noise_not_stored_as_critical(db_session: AsyncSession) -> None:
    """NOISE-classified logs must not be stored with CRITICAL classification."""
    # Use the port creation failure line — classified as INFO/NOISE
    noise_line = (
        "May 22 20:31:50 192.168.203.1 9238658: BSCCL-EQ-RTR-01 "
        "LC/0/3/CPU0:May 22 20:31:50.165 +06: eth_intf_ea[178]: "
        "%PLATFORM-VEEA-3-BCMDPA_L1_PORT_CREATION_FAILURE : "
        "bcmdpa l1 port create failed, ifname: HundredGigE0_3_2_2, unit:0"
    )
    parsed = parse_syslog(noise_line)
    assert parsed is not None

    enriched = enrich(parsed)
    assert enriched.classification != "CRITICAL"

    alert = AlertLog(
        timestamp=parsed.timestamp,
        source_ip=parsed.source_ip,
        device_name=enriched.device_name,
        hostname=parsed.hostname,
        rp_location=parsed.rp_location,
        facility=parsed.facility,
        subfacility=parsed.subfacility,
        severity_level=parsed.severity_level,
        mnemonic=parsed.mnemonic,
        message=parsed.message,
        raw=parsed.raw,
        classification=enriched.classification,
    )
    saved = await insert_alert(db_session, alert)
    assert saved.classification != "CRITICAL"


# ---------------------------------------------------------------------------
# 12. test_pipeline_multiple_logs_stored_independently
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pipeline_multiple_logs_stored_independently(
    db_session: AsyncSession,
) -> None:
    """Three different log lines produce three independent DB rows."""
    lines = [
        _BGP_DOWN_LINE,
        (
            "May 22 15:23:04 192.168.200.11 52474: LC/0/0/CPU0:"
            "May 22 15:23:29.243 +06: fia_driver[165]: "
            "%PLATFORM-DPA-2-RX_FAULT : Interface TenGigE0/0/0/0, "
            "Detected Remote Fault"
        ),
        (
            "May 22 20:22:37 192.168.200.11 52534: 0/RP0/ADMIN0:"
            "May 22 20:23:02.420 +06: shelf_mgr[2117]: "
            "%INFRA-SHELF_MGR-6-HW_EVENT : Rcvd HW event HW_EVENT_OK, "
            "event_reason_str 'HW Operational' for card 0/PM3"
        ),
    ]

    saved_ids = []
    for line in lines:
        parsed = parse_syslog(line)
        assert parsed is not None
        enriched = enrich(parsed)
        alert = AlertLog(
            timestamp=parsed.timestamp,
            source_ip=parsed.source_ip,
            device_name=enriched.device_name,
            hostname=parsed.hostname,
            rp_location=parsed.rp_location,
            facility=parsed.facility,
            subfacility=parsed.subfacility,
            severity_level=parsed.severity_level,
            mnemonic=parsed.mnemonic,
            message=parsed.message,
            raw=parsed.raw,
            classification=enriched.classification,
        )
        saved = await insert_alert(db_session, alert)
        saved_ids.append(saved.id)

    # All 3 must be distinct rows
    assert len(set(saved_ids)) == 3
