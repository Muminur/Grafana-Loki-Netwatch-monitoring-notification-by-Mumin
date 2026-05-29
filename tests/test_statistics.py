"""Tests for statistics engine, health score, SLA, predictions, aggregation, and digest.

TDD approach: tests written FIRST (RED) then implementation makes them GREEN.
All async tests use in-memory SQLite.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog, HourlyStats, Incident
from src.statistics.health_score import calculate_health_score
from src.statistics.predictions import predict_prefix_exhaustion

# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures
# ─────────────────────────────────────────────────────────────────────────────

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


def _make_alert(
    *,
    classification: str = "INFO",
    device_name: str = "BSCCL-EQ-RTR-01",
    timestamp: datetime | None = None,
) -> AlertLog:
    """Build a minimal AlertLog with sensible defaults."""
    ts = timestamp or datetime(2026, 5, 22, 15, 0, 0, tzinfo=UTC)
    return AlertLog(
        timestamp=ts,
        source_ip="192.168.203.1",
        device_name=device_name,
        hostname=device_name,
        facility="BGP",
        severity_level=5,
        mnemonic="TEST",
        message="test message",
        raw="raw syslog line",
        classification=classification,
    )


# ─────────────────────────────────────────────────────────────────────────────
# 1. test_health_score_perfect
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_perfect():
    """Zero criticals, warnings, incidents, flapping peers → maximum score (100)."""
    score = calculate_health_score(
        critical_count=0,
        warning_count=0,
        active_incidents=0,
        flapping_peers=0,
        total_devices=34,
    )
    # With bonuses: +5 no criticals + implied all-devices bonus → 100 (capped)
    assert score == 100.0


# ─────────────────────────────────────────────────────────────────────────────
# 2. test_health_score_deductions
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_deductions():
    """2 criticals + 1 incident → 80 (no all-devices bonus without reporting)."""
    score = calculate_health_score(
        critical_count=2,
        warning_count=0,
        active_incidents=1,
        flapping_peers=0,
        total_devices=34,
    )
    # 100 - (2*5) - (1*10) = 80. No +5 for "no criticals" (critical_count=2),
    # no +5 for "all devices" (reporting_devices defaults to 0).
    assert score == 80.0


# ─────────────────────────────────────────────────────────────────────────────
# 3. test_health_score_floor_zero
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_floor_zero():
    """Extreme deductions cannot push the score below 0."""
    score = calculate_health_score(
        critical_count=100,
        warning_count=200,
        active_incidents=50,
        flapping_peers=30,
        total_devices=34,
    )
    assert score == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 4. test_health_score_ceiling_100
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_ceiling_100():
    """Bonuses cannot push score above 100."""
    score = calculate_health_score(
        critical_count=0,
        warning_count=0,
        active_incidents=0,
        flapping_peers=0,
        total_devices=34,
    )
    assert score <= 100.0


# ─────────────────────────────────────────────────────────────────────────────
# 5. test_health_score_warning_only
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_warning_only():
    """5 warnings = -5 points. No critical → +5 bonus. All devices → +5 bonus."""
    score = calculate_health_score(
        critical_count=0,
        warning_count=5,
        active_incidents=0,
        flapping_peers=0,
        total_devices=34,
    )
    # 100 - (5 * 1) + 5 (no criticals) + 5 (all devices) = 105 → capped at 100
    assert score == 100.0


# ─────────────────────────────────────────────────────────────────────────────
# 6. test_prefix_prediction_exhaustion
# ─────────────────────────────────────────────────────────────────────────────


def test_prefix_prediction_exhaustion():
    """800/1000 prefixes at 10 prefixes/day → 20 days until exhaustion."""
    result = predict_prefix_exhaustion(
        current_count=800,
        max_count=1000,
        growth_rate=10.0,  # prefixes per day
    )
    assert result["days_until_max"] == 20
    assert result["current_count"] == 800
    assert result["max_count"] == 1000
    assert result["growth_rate"] == 10.0


# ─────────────────────────────────────────────────────────────────────────────
# 7. test_prefix_80_percent_warning
# ─────────────────────────────────────────────────────────────────────────────


def test_prefix_80_percent_warning():
    """800/1000 prefixes → 80% threshold already reached, warning active."""
    result = predict_prefix_exhaustion(
        current_count=800,
        max_count=1000,
        growth_rate=10.0,
    )
    assert result["warning_80_reached"] is True
    assert result["warning_90_reached"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 8. test_prefix_90_percent_warning
# ─────────────────────────────────────────────────────────────────────────────


def test_prefix_90_percent_warning():
    """900/1000 prefixes → both 80% and 90% thresholds reached."""
    result = predict_prefix_exhaustion(
        current_count=900,
        max_count=1000,
        growth_rate=5.0,
    )
    assert result["warning_80_reached"] is True
    assert result["warning_90_reached"] is True
    assert result["days_until_max"] == 20


# ─────────────────────────────────────────────────────────────────────────────
# 9. test_prefix_prediction_zero_growth
# ─────────────────────────────────────────────────────────────────────────────


def test_prefix_prediction_zero_growth():
    """Zero growth rate → days_until_max is None (never exhausted)."""
    result = predict_prefix_exhaustion(
        current_count=500,
        max_count=1000,
        growth_rate=0.0,
    )
    assert result["days_until_max"] is None


# ─────────────────────────────────────────────────────────────────────────────
# 10. test_hourly_aggregation
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hourly_aggregation(session: AsyncSession):
    """Insert alerts, run aggregator, verify hourly HourlyStats rows exist."""
    from src.statistics.aggregator import aggregate_hourly

    # Insert 3 CRITICAL + 2 WARNING for EQ-RTR-01 in the same hour.
    # Anchor to the current hour so the alerts always fall inside
    # aggregate_hourly's lookback window regardless of the wall-clock date.
    hour_ts = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    alerts = [
        _make_alert(
            classification="CRITICAL",
            device_name="BSCCL-EQ-RTR-01",
            timestamp=hour_ts + timedelta(minutes=i),
        )
        for i in range(3)
    ] + [
        _make_alert(
            classification="WARNING",
            device_name="BSCCL-EQ-RTR-01",
            timestamp=hour_ts + timedelta(minutes=i + 3),
        )
        for i in range(2)
    ]

    for alert in alerts:
        session.add(alert)
    await session.flush()

    # Run aggregator
    await aggregate_hourly(session)

    # Verify HourlyStats row was created
    from sqlalchemy import select

    stmt = select(HourlyStats).where(
        HourlyStats.device_name == "BSCCL-EQ-RTR-01",
        HourlyStats.hour == hour_ts,
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()

    assert row is not None, "HourlyStats row must be created after aggregation"
    assert row.critical_count == 3
    assert row.warning_count == 2
    assert row.info_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 11. test_daily_stats
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_daily_stats(session: AsyncSession):
    """Insert alerts for a day, query daily stats and verify counts."""
    from src.statistics.engine import get_daily_stats

    target_date = date(2026, 5, 22)
    base_ts = datetime(2026, 5, 22, 10, 0, 0, tzinfo=UTC)

    # 4 CRITICAL, 3 WARNING, 2 INFO alerts on the target date
    alerts = (
        [
            _make_alert(
                classification="CRITICAL", timestamp=base_ts + timedelta(hours=i)
            )
            for i in range(4)
        ]
        + [
            _make_alert(
                classification="WARNING", timestamp=base_ts + timedelta(hours=i + 4)
            )
            for i in range(3)
        ]
        + [
            _make_alert(
                classification="INFO", timestamp=base_ts + timedelta(hours=i + 7)
            )
            for i in range(2)
        ]
    )

    for alert in alerts:
        session.add(alert)
    await session.flush()

    stats = await get_daily_stats(session, target_date)

    assert stats["date"] == target_date.isoformat()
    assert stats["critical"] == 4
    assert stats["warning"] == 3
    assert stats["info"] == 2
    assert stats["total"] == 9


# ─────────────────────────────────────────────────────────────────────────────
# 12. test_weekly_stats
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_weekly_stats(session: AsyncSession):
    """Insert alerts across 7 days and verify weekly stats has 7 date entries."""
    from src.statistics.engine import get_weekly_stats

    week_start = date(2026, 5, 16)

    for day in range(7):
        ts = datetime(2026, 5, 16 + day, 12, 0, 0, tzinfo=UTC)
        alert = _make_alert(classification="CRITICAL", timestamp=ts)
        session.add(alert)
    await session.flush()

    stats = await get_weekly_stats(session, week_start)

    assert "days" in stats
    assert len(stats["days"]) == 7
    # Each day entry has at least 1 CRITICAL
    for day_entry in stats["days"]:
        assert "date" in day_entry
        assert "critical" in day_entry


# ─────────────────────────────────────────────────────────────────────────────
# 13. test_device_stats
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_device_stats(session: AsyncSession):
    """Get alert history for a specific device across last 7 days."""
    from src.statistics.engine import get_device_stats

    device = "BSCCL-EQ-RTR-01"
    # Anchor to now so the alerts stay inside get_device_stats' 7-day window.
    now = datetime.now(UTC)

    # 5 alerts for target device, 3 for another
    for i in range(5):
        session.add(_make_alert(device_name=device, timestamp=now - timedelta(hours=i)))
    for i in range(3):
        session.add(
            _make_alert(device_name="KKT-Core-02", timestamp=now - timedelta(hours=i))
        )
    await session.flush()

    stats = await get_device_stats(session, device, days=7)

    assert stats["device_name"] == device
    assert stats["total_alerts"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# 14. test_digest_format
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_digest_format(session: AsyncSession):
    """Generate a daily digest with mock data and verify required sections."""
    from src.notifications.digest import generate_daily_digest

    # Insert alerts with naive timestamps matching "today" in BDT, since
    # the digest queries using naive BDT-midnight bounds (no UTC offset).
    _bdt = timezone(timedelta(hours=6))
    today_bdt = datetime.now(tz=_bdt).date()
    base_ts = datetime(  # noqa: DTZ001
        today_bdt.year, today_bdt.month, today_bdt.day, 10, 0, 0
    )
    for i in range(3):
        session.add(
            _make_alert(
                classification="CRITICAL", timestamp=base_ts + timedelta(minutes=i)
            )
        )
    for i in range(5):
        session.add(
            _make_alert(
                classification="WARNING", timestamp=base_ts + timedelta(minutes=i + 10)
            )
        )
    session.add(
        _make_alert(classification="INFO", timestamp=base_ts + timedelta(minutes=20))
    )
    await session.flush()

    digest = await generate_daily_digest(session)

    # Must be a non-empty string
    assert isinstance(digest, str)
    assert len(digest) > 0

    # Must contain section markers
    assert "CRITICAL" in digest
    assert "WARNING" in digest
    # Must contain numeric counts
    assert "3" in digest  # 3 criticals


# ─────────────────────────────────────────────────────────────────────────────
# 15. test_digest_contains_health_score
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_digest_contains_health_score(session: AsyncSession):
    """Daily digest must include a health score section."""
    from src.notifications.digest import generate_daily_digest

    digest = await generate_daily_digest(session)
    # Health score section must appear
    assert "Health" in digest or "health" in digest or "score" in digest.lower()


# ─────────────────────────────────────────────────────────────────────────────
# 16. test_sla_calculation
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sla_calculation(session: AsyncSession):
    """SLA: client with known incident windows → correct uptime percentage."""
    from src.statistics.sla import calculate_client_sla

    # Insert incident (resolved) representing 1 hour of downtime
    now = datetime.now(UTC)
    start = now - timedelta(hours=6)
    end = now - timedelta(hours=5)

    incident = Incident(
        id="INC-20260522-001",
        title="Test outage",
        root_cause="Test",
        affected_clients='["TestClient"]',
        affected_devices="[]",
        alert_count=1,
        symptom_count=0,
        status="resolved",
        created_at=start,
        resolved_at=end,
    )
    session.add(incident)
    await session.flush()

    sla = await calculate_client_sla(session, "TestClient", days=1)

    assert sla.client_name == "TestClient"
    # 23/24 hours up → 95.83...%
    assert sla.uptime_percent < 100.0
    assert sla.uptime_percent > 90.0
    assert sla.incidents_count == 1
    assert sla.mttr_minutes > 0


# ─────────────────────────────────────────────────────────────────────────────
# 17. test_sla_perfect_uptime
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sla_perfect_uptime(session: AsyncSession):
    """Client with no incidents → 100% uptime."""
    from src.statistics.sla import calculate_client_sla

    sla = await calculate_client_sla(session, "PerfectClient", days=30)

    assert sla.client_name == "PerfectClient"
    assert sla.uptime_percent == 100.0
    assert sla.incidents_count == 0
    assert sla.mtbf_hours == 0.0  # no failures → undefined (return 0)
    assert sla.mttr_minutes == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 18. test_hourly_aggregation_multiple_devices
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hourly_aggregation_multiple_devices(session: AsyncSession):
    """Aggregator creates separate rows for different devices in same hour."""
    from src.statistics.aggregator import aggregate_hourly

    # Anchor to the current hour so alerts stay inside the lookback window.
    hour_ts = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    session.add(
        _make_alert(
            classification="CRITICAL", device_name="Device-A", timestamp=hour_ts
        )
    )
    session.add(
        _make_alert(classification="WARNING", device_name="Device-B", timestamp=hour_ts)
    )
    await session.flush()

    await aggregate_hourly(session)

    from sqlalchemy import select

    result = await session.execute(
        select(HourlyStats).where(HourlyStats.hour == hour_ts)
    )
    rows = result.scalars().all()
    device_names = {r.device_name for r in rows}

    assert "Device-A" in device_names
    assert "Device-B" in device_names


# ─────────────────────────────────────────────────────────────────────────────
# 18b. test_hourly_aggregation_upsert_idempotent
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hourly_aggregation_upsert_idempotent(session: AsyncSession):
    """Running aggregate_hourly twice with the same data must NOT double counts.

    This exercises the UPDATE branch of the upsert: the first call INSERTs a
    new HourlyStats row; the second call finds the existing row and UPDATEs
    it with the same counts.
    """
    from src.statistics.aggregator import aggregate_hourly

    # Anchor to the current hour so alerts stay inside the lookback window.
    hour_ts = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    alerts = [
        _make_alert(
            classification="CRITICAL",
            device_name="BSCCL-EQ-RTR-01",
            timestamp=hour_ts + timedelta(minutes=i),
        )
        for i in range(2)
    ] + [
        _make_alert(
            classification="WARNING",
            device_name="BSCCL-EQ-RTR-01",
            timestamp=hour_ts + timedelta(minutes=i + 5),
        )
        for i in range(3)
    ]
    for alert in alerts:
        session.add(alert)
    await session.flush()

    # First aggregation — INSERT path
    await aggregate_hourly(session)

    # Second aggregation — UPDATE path (same data, must not double counts)
    await aggregate_hourly(session)

    from sqlalchemy import select

    stmt = select(HourlyStats).where(
        HourlyStats.device_name == "BSCCL-EQ-RTR-01",
        HourlyStats.hour == hour_ts,
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()

    assert row is not None, "HourlyStats row must exist after aggregation"
    assert row.critical_count == 2, "critical_count should be 2, not doubled"
    assert row.warning_count == 3, "warning_count should be 3, not doubled"
    assert row.info_count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 19. test_health_score_flapping_deduction
# ─────────────────────────────────────────────────────────────────────────────


def test_health_score_flapping_deduction():
    """Each flapping peer deducts 3 points from health score."""
    # Use existing criticals so bonuses are suppressed and ceiling doesn't interfere.
    # 2 criticals (no +5 no-critical bonus) + 5 all-devices bonus:
    # no flap:  100 - 10 + 5 = 95
    # 2 flap:   100 - 10 + 5 - 6 = 89
    score_no_flap = calculate_health_score(
        critical_count=2,
        warning_count=0,
        active_incidents=0,
        flapping_peers=0,
        total_devices=34,
    )
    score_with_flap = calculate_health_score(
        critical_count=2,
        warning_count=0,
        active_incidents=0,
        flapping_peers=2,
        total_devices=34,
    )
    assert score_no_flap - score_with_flap == 6.0
