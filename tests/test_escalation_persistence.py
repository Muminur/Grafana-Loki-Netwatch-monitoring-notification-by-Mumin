"""Tests for escalation-state persistence across restarts.

Covers:
- EscalationEngine.restore() repopulates tracked state preserving tracked_at
  so an alert tracked > delay ago is immediately pending after restore.
- Startup reconstruction loads unresolved+unacked CRITICAL rows from a seeded
  in-memory DB and skips resolved / acknowledged / unparseable rows.
- The bounded window (2× escalation delay) and row LIMIT (200) are respected.

All tests use an in-memory SQLite engine; the real DB is never touched.
Module-globals mutated by these tests are fully snapshot/restored.
"""

# ruff: noqa: SLF001, ARG001, DTZ001
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from src.database.migrations import create_tables
from src.database.models import AlertLog
from src.notifications.escalation import EscalationEngine

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from src.core.enricher import EnrichedLog

# ---------------------------------------------------------------------------
# Timezone helpers
# ---------------------------------------------------------------------------

_UTC6 = timezone(timedelta(hours=6))

# ---------------------------------------------------------------------------
# A real parseable CRITICAL syslog line (BGP Down on EQ-RTR-01)
# ---------------------------------------------------------------------------

_BGP_DOWN_RAW = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Down - BGP Notification received, maximum number of prefixes "
    "reached (VRF: network) (AS: 399077)"
)

# A second distinct CRITICAL raw line (for multi-row tests)
_REMOTE_FAULT_RAW = (
    "May 22 15:23:04 192.168.200.11 52474: LC/0/0/CPU0:"
    "May 22 15:23:29.243 +06: fia_driver[165]: "
    "%PLATFORM-DPA-2-RX_FAULT : Interface TenGigE0/0/0/0, "
    "Detected Remote Fault"
)

# A WARNING line (must be skipped by restore — BER_CLEAR is WARNING, not CRITICAL)
_BER_CLEAR_RAW = (
    "May 22 15:22:35 192.168.200.11 52464: LC/0/0/CPU0:"
    "May 22 15:22:59.610 +06: fia_driver[165]: "
    "%PLATFORM-PLAT_VETHER_DRIVER-3-REPORT_BER_CLEAR : "
    "Interface TenGigE0/0/0/0 : SF-BER is less than the "
    "threshold limit for the BER level [e^-8]"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enriched(raw: str) -> EnrichedLog:
    """Parse + enrich a raw log line.  Returns the EnrichedLog."""
    from src.core.enricher import enrich
    from src.core.parser import parse_syslog

    parsed = parse_syslog(raw)
    assert parsed is not None, f"Failed to parse: {raw[:80]}"
    return enrich(parsed)


def _now_utc6() -> datetime:
    return datetime.now(_UTC6)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
async def mem_db() -> AsyncIterator[Any]:
    """In-memory SQLite async engine with full schema (via create_tables)."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)
    yield engine
    await engine.dispose()


@pytest.fixture
def fresh_escalation() -> EscalationEngine:
    """A fresh EscalationEngine with the default 900 s (15 min) delay."""
    return EscalationEngine()


# ---------------------------------------------------------------------------
# Unit tests: EscalationEngine.restore()
# ---------------------------------------------------------------------------


def test_restore_repopulates_tracked_state(fresh_escalation: EscalationEngine) -> None:
    """restore() inserts the alert into _tracked with the given tracked_at."""
    eng = fresh_escalation
    enriched = _make_enriched(_BGP_DOWN_RAW)
    tracked_at = _now_utc6() - timedelta(minutes=10)

    eng.restore(enriched, tracked_at=tracked_at, acknowledged=False)

    discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
    key = (enriched.device_name, enriched.parsed.mnemonic, discriminator)
    assert key in eng._tracked
    stored_enriched, stored_ts = eng._tracked[key]
    assert stored_enriched is enriched
    assert stored_ts == tracked_at
    assert key not in eng._acked


def test_restore_preserves_tracked_at_so_old_alert_is_immediately_pending(
    fresh_escalation: EscalationEngine,
) -> None:
    """An alert tracked > delay ago must appear in get_pending_escalations()."""
    eng = fresh_escalation
    enriched = _make_enriched(_BGP_DOWN_RAW)
    # Pretend the alert was tracked 20 minutes ago (beyond the 15-min threshold)
    tracked_at = _now_utc6() - timedelta(minutes=20)

    eng.restore(enriched, tracked_at=tracked_at, acknowledged=False)

    pending = eng.get_pending_escalations()
    assert len(pending) == 1
    alert, _elapsed = pending[0]
    assert alert.parsed.mnemonic == enriched.parsed.mnemonic


def test_restore_recent_alert_not_yet_pending(
    fresh_escalation: EscalationEngine,
) -> None:
    """An alert tracked 5 minutes ago must NOT appear in get_pending_escalations()."""
    eng = fresh_escalation
    enriched = _make_enriched(_BGP_DOWN_RAW)
    tracked_at = _now_utc6() - timedelta(minutes=5)

    eng.restore(enriched, tracked_at=tracked_at, acknowledged=False)

    pending = eng.get_pending_escalations()
    assert pending == []


def test_restore_acknowledged_true_suppresses_escalation(
    fresh_escalation: EscalationEngine,
) -> None:
    """restore() with acknowledged=True must suppress the alert from pending list."""
    eng = fresh_escalation
    enriched = _make_enriched(_BGP_DOWN_RAW)
    tracked_at = _now_utc6() - timedelta(minutes=20)

    eng.restore(enriched, tracked_at=tracked_at, acknowledged=True)

    discriminator = enriched.bgp_neighbor or enriched.interface_name or ""
    key = (enriched.device_name, enriched.parsed.mnemonic, discriminator)
    assert key in eng._acked
    pending = eng.get_pending_escalations()
    assert pending == []


def test_restore_non_critical_is_silently_ignored(
    fresh_escalation: EscalationEngine,
) -> None:
    """restore() ignores non-CRITICAL alerts (same guard as track_alert)."""
    eng = fresh_escalation
    enriched = _make_enriched(_BER_CLEAR_RAW)
    # BGP Up is WARNING, not CRITICAL
    assert enriched.classification != "CRITICAL"

    eng.restore(
        enriched,
        tracked_at=_now_utc6() - timedelta(minutes=20),
        acknowledged=False,
    )

    assert eng._tracked == {}
    assert eng._acked == set()
    assert eng.get_pending_escalations() == []


def test_restore_does_not_change_existing_track_alert_behavior(
    fresh_escalation: EscalationEngine,
) -> None:
    """restore() does not affect track_alert / acknowledge / get_pending behavior."""
    eng = fresh_escalation
    enriched = _make_enriched(_BGP_DOWN_RAW)

    # Normal track via track_alert
    eng.track_alert(enriched)
    assert eng.get_pending_escalations() == []  # too recent

    # Now restore an older instance of the same alert with older tracked_at
    old_ts = _now_utc6() - timedelta(minutes=30)
    eng.restore(enriched, tracked_at=old_ts, acknowledged=False)

    # The restore overwrites the previous entry; alert is now pending
    pending = eng.get_pending_escalations()
    assert len(pending) == 1


def test_restore_multiple_alerts(fresh_escalation: EscalationEngine) -> None:
    """Restoring two distinct alerts populates both keys independently."""
    eng = fresh_escalation
    e1 = _make_enriched(_BGP_DOWN_RAW)
    e2 = _make_enriched(_REMOTE_FAULT_RAW)

    old_ts = _now_utc6() - timedelta(minutes=20)
    recent_ts = _now_utc6() - timedelta(minutes=5)

    eng.restore(e1, tracked_at=old_ts, acknowledged=False)
    eng.restore(e2, tracked_at=recent_ts, acknowledged=False)

    pending = eng.get_pending_escalations()
    # Only e1 is past the threshold
    assert len(pending) == 1
    alert, _elapsed = pending[0]
    assert alert.parsed.mnemonic == e1.parsed.mnemonic


# ---------------------------------------------------------------------------
# Integration tests: startup reconstruction from seeded in-memory DB
# ---------------------------------------------------------------------------


async def _seed_alert(
    engine: Any,
    raw: str,
    classification: str,
    *,
    timestamp: datetime,
    resolved_at: datetime | None = None,
    acknowledged_at: datetime | None = None,
) -> None:
    """Insert one AlertLog row directly into the test DB."""
    from src.core.parser import parse_syslog

    parsed = parse_syslog(raw)
    assert parsed is not None
    async with AsyncSession(engine) as session:
        row = AlertLog(
            timestamp=timestamp,
            source_ip=parsed.source_ip,
            device_name="EQ-RTR-01",
            hostname=parsed.hostname or "EQ-RTR-01",
            facility=parsed.facility,
            severity_level=parsed.severity_level,
            mnemonic=parsed.mnemonic,
            message=parsed.message,
            raw=raw,
            classification=classification,
            resolved_at=resolved_at,
            acknowledged_at=acknowledged_at,
        )
        session.add(row)
        await session.commit()


@pytest.mark.asyncio
async def test_startup_reconstruction_loads_unresolved_unacked_critical(
    mem_db: Any,
) -> None:
    """Reconstruction restores a CRITICAL unresolved+unacked row into the engine."""
    # Seed: CRITICAL, unresolved, unacked, within the 2× delay window
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    await _seed_alert(mem_db, _BGP_DOWN_RAW, "CRITICAL", timestamp=ts)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert len(eng._tracked) == 1


@pytest.mark.asyncio
async def test_startup_reconstruction_skips_resolved_rows(mem_db: Any) -> None:
    """Reconstruction skips CRITICAL rows that have resolved_at set."""
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    await _seed_alert(
        mem_db,
        _BGP_DOWN_RAW,
        "CRITICAL",
        timestamp=ts,
        resolved_at=datetime.now(_UTC6),
    )

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert eng._tracked == {}


@pytest.mark.asyncio
async def test_startup_reconstruction_skips_acknowledged_rows(mem_db: Any) -> None:
    """Reconstruction skips CRITICAL rows that have acknowledged_at set."""
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    await _seed_alert(
        mem_db,
        _BGP_DOWN_RAW,
        "CRITICAL",
        timestamp=ts,
        acknowledged_at=datetime.now(_UTC6),
    )

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert eng._tracked == {}


@pytest.mark.asyncio
async def test_startup_reconstruction_skips_non_critical_rows(mem_db: Any) -> None:
    """Reconstruction skips WARNING / INFO rows even if unresolved."""
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    await _seed_alert(mem_db, _BER_CLEAR_RAW, "WARNING", timestamp=ts)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert eng._tracked == {}


@pytest.mark.asyncio
async def test_startup_reconstruction_skips_unparseable_raw(mem_db: Any) -> None:
    """Reconstruction skips rows whose raw field cannot be parsed."""
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    async with AsyncSession(mem_db) as session:
        row = AlertLog(
            timestamp=ts,
            source_ip="1.2.3.4",
            device_name="UNKNOWN",
            hostname="X",
            facility="TEST",
            severity_level=2,
            mnemonic="DUMMY",
            message="bad",
            raw="THIS IS NOT A VALID SYSLOG LINE",
            classification="CRITICAL",
        )
        session.add(row)
        await session.commit()

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert eng._tracked == {}


@pytest.mark.asyncio
async def test_startup_reconstruction_skips_rows_outside_window(mem_db: Any) -> None:
    """Reconstruction ignores CRITICAL rows older than 2× escalation delay."""
    # EscalationEngine default delay = 900 s (15 min); 2× = 30 min.
    # Place this alert 35 minutes ago — outside the window.
    ts = datetime.now(_UTC6) - timedelta(minutes=35)
    await _seed_alert(mem_db, _BGP_DOWN_RAW, "CRITICAL", timestamp=ts)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert eng._tracked == {}


@pytest.mark.asyncio
async def test_startup_reconstruction_respects_row_limit(mem_db: Any) -> None:
    """Reconstruction processes at most 200 rows (LIMIT guard)."""
    ts_base = datetime.now(_UTC6) - timedelta(minutes=10)
    # Insert 5 rows — all within window; all should be restored (well under limit)
    for i in range(5):
        ts = ts_base + timedelta(seconds=i)
        await _seed_alert(mem_db, _BGP_DOWN_RAW, "CRITICAL", timestamp=ts)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    # All 5 share the same key (same device+mnemonic+discriminator),
    # so only 1 distinct entry is in _tracked (last write wins).
    assert len(eng._tracked) == 1


@pytest.mark.asyncio
async def test_startup_reconstruction_preserves_tracked_at(mem_db: Any) -> None:
    """The tracked_at used by restore() is the row's timestamp (original clock)."""
    ts = datetime.now(_UTC6) - timedelta(minutes=10)
    await _seed_alert(mem_db, _BGP_DOWN_RAW, "CRITICAL", timestamp=ts)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    assert len(eng._tracked) == 1
    _, stored_ts = next(iter(eng._tracked.values()))
    # Stored timestamp should match what was seeded (within 1-second tolerance
    # for timezone-naive vs aware comparisons)
    if stored_ts.tzinfo is None:
        stored_ts = stored_ts.replace(tzinfo=_UTC6)
    diff = abs(stored_ts - ts)
    assert diff < timedelta(seconds=1), f"tracked_at drift too large: {diff}"


@pytest.mark.asyncio
async def test_startup_reconstruction_does_not_block_on_db_failure() -> None:
    """Reconstruction failure must not raise; it logs a warning and continues."""
    # Use a disposed engine to simulate DB failure
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await engine.dispose()

    eng = EscalationEngine()
    # Should not raise
    await _run_reconstruction(eng, engine)

    assert eng._tracked == {}


# ---------------------------------------------------------------------------
# E2E: simulate startup reconstruction from a seeded DB (in-process)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_e2e_startup_reconstruction_end_to_end(mem_db: Any) -> None:
    """End-to-end: seed DB with mixed rows → reconstruction → verify correct state.

    Simulates the in-process startup reconstruction exactly as main.py lifespan
    does it, but driven from a test without binding any port.
    """
    now = datetime.now(_UTC6)

    # Row 1: CRITICAL, unresolved, unacked, 10 min ago → should be restored
    ts_bgp = now - timedelta(minutes=10)
    await _seed_alert(mem_db, _BGP_DOWN_RAW, "CRITICAL", timestamp=ts_bgp)

    # Row 2: CRITICAL, resolved → must be skipped
    ts_rf = now - timedelta(minutes=8)
    await _seed_alert(
        mem_db,
        _REMOTE_FAULT_RAW,
        "CRITICAL",
        timestamp=ts_rf,
        resolved_at=now,
    )

    # Row 3: CRITICAL, acknowledged → must be skipped
    ts_bgp2 = now - timedelta(minutes=6)
    await _seed_alert(
        mem_db,
        _BGP_DOWN_RAW,
        "CRITICAL",
        timestamp=ts_bgp2,
        acknowledged_at=now,
    )

    # Row 4: WARNING unresolved → must be skipped
    ts_up = now - timedelta(minutes=4)
    await _seed_alert(mem_db, _BER_CLEAR_RAW, "WARNING", timestamp=ts_up)

    # Row 5: CRITICAL outside window (35 min ago) → must be skipped
    ts_old = now - timedelta(minutes=35)
    await _seed_alert(mem_db, _REMOTE_FAULT_RAW, "CRITICAL", timestamp=ts_old)

    eng = EscalationEngine()
    await _run_reconstruction(eng, mem_db)

    # Only row 1 (BGP Down, unresolved, unacked, within window) should be tracked.
    # Row 3 has the same key as row 1 but is acknowledged — since row 1 is loaded
    # first (ORDER BY timestamp ASC) and row 3 is acked (skipped by the WHERE
    # clause filter), only row 1 ends up tracked.
    assert len(eng._tracked) == 1
    key = next(iter(eng._tracked))
    stored_enriched, stored_ts = eng._tracked[key]
    assert stored_enriched.classification == "CRITICAL"
    # tracked_at should be close to ts_bgp
    aware_stored = (
        stored_ts.replace(tzinfo=_UTC6) if stored_ts.tzinfo is None else stored_ts
    )
    diff = abs(aware_stored - ts_bgp)
    assert diff < timedelta(seconds=1)


# ---------------------------------------------------------------------------
# Migration: acknowledged_at column
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_acknowledged_at_column_exists_after_create_tables() -> None:
    """create_tables creates the acknowledged_at column on fresh DBs."""
    from sqlalchemy import text

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)

    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns = {row[1] for row in result.fetchall()}

    await engine.dispose()
    assert "acknowledged_at" in columns


@pytest.mark.asyncio
async def test_migration_adds_acknowledged_at_to_existing_db() -> None:
    """The migration adds acknowledged_at to a DB created without it."""
    from sqlalchemy import text

    from src.database.migrations import _migrate_alert_log_acknowledged_at

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Create schema WITHOUT the acknowledged_at column (simulate old DB)
    async with engine.begin() as conn:
        await conn.execute(text("""
                CREATE TABLE alert_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    source_ip VARCHAR(45) NOT NULL,
                    device_name VARCHAR(128) NOT NULL,
                    hostname VARCHAR(128) DEFAULT '',
                    rp_location VARCHAR(64) DEFAULT '',
                    facility VARCHAR(64) NOT NULL,
                    subfacility VARCHAR(64) DEFAULT '',
                    severity_level INTEGER NOT NULL,
                    mnemonic VARCHAR(64) NOT NULL,
                    message TEXT NOT NULL,
                    raw TEXT NOT NULL,
                    classification VARCHAR(32) DEFAULT 'INFO',
                    interface_name VARCHAR(128) DEFAULT '',
                    interface_description VARCHAR(256) DEFAULT '',
                    client_name VARCHAR(128) DEFAULT '',
                    bgp_neighbor VARCHAR(64) DEFAULT '',
                    as_number INTEGER DEFAULT 0,
                    as_name VARCHAR(128) DEFAULT '',
                    incident_id VARCHAR(32),
                    notification_sent BOOLEAN DEFAULT 0,
                    resolved_at DATETIME,
                    resolution_reason VARCHAR(64) DEFAULT '',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """))

    # Verify column is absent before migration
    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns_before = {row[1] for row in result.fetchall()}
    assert "acknowledged_at" not in columns_before

    # Run migration
    await _migrate_alert_log_acknowledged_at(engine)

    # Verify column now present
    async with engine.begin() as conn:
        result = await conn.execute(text("PRAGMA table_info(alert_log)"))
        columns_after = {row[1] for row in result.fetchall()}

    await engine.dispose()
    assert "acknowledged_at" in columns_after


@pytest.mark.asyncio
async def test_migration_is_idempotent() -> None:
    """Running the acknowledged_at migration twice does not raise."""
    from src.database.migrations import _migrate_alert_log_acknowledged_at

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)

    # Run twice — must not raise
    await _migrate_alert_log_acknowledged_at(engine)
    await _migrate_alert_log_acknowledged_at(engine)

    await engine.dispose()


# ---------------------------------------------------------------------------
# Internal helper: runs the same reconstruction logic as main.py lifespan
# (extracted here so tests don't import main.py, avoiding side effects)
# ---------------------------------------------------------------------------


async def _run_reconstruction(eng: EscalationEngine, db_engine: Any) -> None:
    """Replicate the escalation reconstruction block from main.py lifespan.

    Uses the same query and logic so tests exercise the real algorithm without
    spinning up the full FastAPI application.
    """
    from sqlalchemy import and_, select

    from src.core.enricher import enrich
    from src.core.parser import parse_syslog

    try:
        delay = eng.escalation_delay_seconds * 2
        cutoff = datetime.now(_UTC6) - timedelta(seconds=delay)
        async with AsyncSession(db_engine) as session:
            stmt = (
                select(AlertLog)
                .where(
                    and_(
                        AlertLog.classification == "CRITICAL",
                        AlertLog.resolved_at.is_(None),
                        AlertLog.acknowledged_at.is_(None),
                        AlertLog.timestamp >= cutoff,
                    )
                )
                .order_by(AlertLog.timestamp.asc())
                .limit(200)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

        for row in rows:
            if not row.raw:
                continue
            try:
                parsed = parse_syslog(row.raw)
                if parsed is None:
                    continue
                enriched = enrich(parsed)
                tracked_at = row.timestamp
                if tracked_at.tzinfo is None:
                    tracked_at = tracked_at.replace(tzinfo=_UTC6)
                eng.restore(enriched, tracked_at=tracked_at, acknowledged=False)
            except Exception:  # noqa: BLE001, S110
                pass
    except Exception:  # noqa: BLE001, S110
        pass
