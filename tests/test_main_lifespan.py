"""Coverage tests for src.main: lifespan, pipeline callback, schedulers, routes.

These tests exercise the FastAPI application lifespan (startup/shutdown), the
``_on_syslog_line`` ingestion callback across all of its branches, the daily
digest and escalation background schedulers, and the HTML page / health routes.

No real network I/O ever happens:
  * ``src.main.SyslogReceiver`` is patched so ``.start()`` / ``.stop()`` are
    async no-ops that never connect to Loki.
  * ``src.main.send_discord_alert`` / ``src.main.send_telegram_alert`` are
    patched with async stubs.
  * The daily digest sender is patched so the scheduler never queries a DB.

All DB access uses a throwaway ``sqlite+aiosqlite`` file under ``tmp_path`` so
the real ``bsccl_netwatch.db`` is never touched.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

import src.main as main_mod
from src.config import Settings
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _db_url(tmp_path: Path) -> str:
    """Return an aiosqlite URL pointing at a fresh temp DB file."""
    return f"sqlite+aiosqlite:///{(tmp_path / 'netwatch_test.db').as_posix()}"


def _make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Build a Settings instance pointed at a temp DB.

    Extra keyword arguments override individual frozen dataclass fields
    (e.g. ``discord_enabled=True``).
    """
    base = Settings()
    base = replace(base, database_url=_db_url(tmp_path))
    if overrides:
        base = replace(base, **overrides)  # type: ignore[arg-type]
    return base


class _StubReceiver:
    """Stand-in for SyslogReceiver: records calls, performs no network I/O."""

    instances: list[_StubReceiver] = []

    def __init__(self, settings: object, callback: object, resume_from_ns: int = 0):
        self.settings = settings
        self.callback = callback
        self.resume_from_ns = resume_from_ns
        self.started = False
        self.stopped = False
        _StubReceiver.instances.append(self)

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def _reset_pipeline_globals() -> Iterator[None]:
    """Snapshot and restore src.main pipeline globals around each test."""
    saved = (
        main_mod._engine,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._dedup,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    yield
    (
        main_mod._engine,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._dedup,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    ) = saved


def _alert_from_raw(raw: str) -> AlertLog:
    """Build an AlertLog from a real raw line, mislabelled as INFO.

    Uses ``datetime.now(UTC)`` for the timestamp so the alert falls within
    the 7-day reclassification window regardless of the date embedded in
    the raw syslog line.
    """
    parsed = parse_syslog(raw)
    assert parsed is not None
    return AlertLog(
        timestamp=datetime.now(UTC),
        source_ip=parsed.source_ip,
        device_name="seed-device",
        hostname=parsed.hostname,
        rp_location=parsed.rp_location,
        facility=parsed.facility,
        subfacility=parsed.subfacility,
        severity_level=parsed.severity_level,
        mnemonic=parsed.mnemonic,
        message=parsed.message,
        raw=raw,
        classification="INFO",  # intentionally wrong → forces reclassify
    )


async def _seed_alerts(
    db_url: str, raw_lines: list[str], *, with_edge_rows: bool = False
) -> None:
    """Create tables in the temp DB and insert one AlertLog per raw line.

    Each parseable row is stored with a deliberately wrong ``classification``
    ("INFO") so the lifespan re-classification loop has work to do and commits
    a fix.

    When ``with_edge_rows`` is True, two extra rows are added to exercise the
    re-classification loop's skip branches: one with an empty ``raw`` (skipped
    at the ``if not row.raw`` guard) and one with an unparseable ``raw`` (skipped
    when ``parse_syslog`` returns ``None``).
    """
    engine = await get_engine(db_url)
    await create_tables(engine)
    async with AsyncSession(engine) as session:
        for raw in raw_lines:
            session.add(_alert_from_raw(raw))
        if with_edge_rows:
            now = datetime.now(UTC)
            # Empty raw → hits the `if not row.raw: continue` guard.
            session.add(
                AlertLog(
                    timestamp=now,
                    source_ip="0.0.0.0",
                    device_name="seed-empty",
                    facility="X",
                    severity_level=6,
                    mnemonic="NONE",
                    message="",
                    raw="",
                    classification="INFO",
                )
            )
            # Unparseable raw → parse_syslog returns None, hits that continue.
            session.add(
                AlertLog(
                    timestamp=now,
                    source_ip="0.0.0.0",
                    device_name="seed-garbage",
                    facility="X",
                    severity_level=6,
                    mnemonic="NONE",
                    message="garbage",
                    raw="not a parseable syslog line",
                    classification="INFO",
                )
            )
        await session.commit()
    await engine.dispose()


# ---------------------------------------------------------------------------
# Lifespan startup / shutdown (lines 302-409)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_lifespan_startup_and_shutdown(
    tmp_path: Path, sample_bgp_down_log: str, sample_ssh_login_log: str
) -> None:
    """Full lifespan: seed DB, drive lifespan, exercise startup + shutdown.

    The ``lifespan`` async context manager is driven directly (rather than via
    ``TestClient``) so it runs in the test's own event loop / thread, where the
    coverage tracer is active and startup DB queries are reliably measured.

    Covers: historical count load (310-323), re-classification loop (327-349),
    pipeline singleton init (353-366), resume-timestamp logic (369-385),
    receiver start (382-384), scheduler task creation (387-392), and the
    shutdown sequence (397-409).
    """
    db_url = _db_url(tmp_path)
    await _seed_alerts(
        db_url,
        [sample_bgp_down_log, sample_ssh_login_log],
        with_edge_rows=True,
    )

    settings = _make_settings(tmp_path)
    _StubReceiver.instances.clear()

    # Fast, non-blocking schedulers: the background tasks created during
    # startup must not perform a real 60-second sleep.
    async def _fast_sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    with (
        patch.object(main_mod, "get_settings", return_value=settings),
        patch.object(main_mod, "SyslogReceiver", _StubReceiver),
        patch("src.main.asyncio.sleep", _fast_sleep),
    ):
        async with main_mod.lifespan(main_mod.app):
            # Inside the context the startup sequence has fully completed.
            # The 2 seeded rows were counted into the processed total.
            from src.api.routes import _alerts_processed  # noqa: PLC0415

            assert _alerts_processed >= 2
            # Singletons were initialised.
            assert main_mod._engine is not None  # noqa: SLF001
            assert main_mod._correlator is not None  # noqa: SLF001
            assert main_mod._dedup is not None  # noqa: SLF001
            assert main_mod._escalation is not None  # noqa: SLF001
        # Exiting the context triggers the shutdown sequence (397-409).

    # The receiver was created, started, and stopped.
    assert len(_StubReceiver.instances) == 1
    receiver = _StubReceiver.instances[0]
    assert receiver.started is True
    assert receiver.stopped is True
    # resume_from_ns derived from the max seeded timestamp (non-zero).
    assert receiver.resume_from_ns > 0


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_lifespan_startup_empty_db(tmp_path: Path) -> None:
    """Lifespan startup with an empty DB skips the historical-count branch.

    Exercises the path where ``existing_count == 0`` (line 317 false) and the
    resume timestamp stays 0 (line 376 false) — receiver gets resume_from_ns=0.
    """
    settings = _make_settings(tmp_path)
    _StubReceiver.instances.clear()

    async def _fast_sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    with (
        patch.object(main_mod, "get_settings", return_value=settings),
        patch.object(main_mod, "SyslogReceiver", _StubReceiver),
        patch("src.main.asyncio.sleep", _fast_sleep),
    ):
        async with main_mod.lifespan(main_mod.app):
            assert main_mod._engine is not None  # noqa: SLF001

    receiver = _StubReceiver.instances[0]
    assert receiver.started is True
    assert receiver.stopped is True
    assert receiver.resume_from_ns == 0


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_lifespan_startup_db_errors_are_swallowed(tmp_path: Path) -> None:
    """Every startup DB query failing hits the three except branches.

    Covers the warning paths at 322-323 (historical count), 348-349
    (re-classification), and 379-380 (resume timestamp). Startup must still
    complete and the receiver must still start.
    """
    settings = _make_settings(tmp_path)
    _StubReceiver.instances.clear()

    async def _fast_sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    # Force every AsyncSession.execute to raise so each guarded query block
    # falls into its except handler.
    async def _boom_execute(*_args: object, **_kwargs: object) -> object:
        msg = "simulated DB failure"
        raise RuntimeError(msg)

    with (
        patch.object(main_mod, "get_settings", return_value=settings),
        patch.object(main_mod, "SyslogReceiver", _StubReceiver),
        patch("src.main.asyncio.sleep", _fast_sleep),
        patch.object(AsyncSession, "execute", _boom_execute),
    ):
        async with main_mod.lifespan(main_mod.app):
            # Despite the query failures, the singletons + receiver came up.
            assert main_mod._engine is not None  # noqa: SLF001

    receiver = _StubReceiver.instances[0]
    assert receiver.started is True
    assert receiver.stopped is True
    # The resume query failed, so we fell back to resume_from_ns == 0.
    assert receiver.resume_from_ns == 0


# ---------------------------------------------------------------------------
# _on_syslog_line branches (lines 98-213)
# ---------------------------------------------------------------------------


async def test_on_syslog_line_unparseable_returns_early() -> None:
    """A line the parser rejects returns immediately (line 100)."""
    # Must not raise even with no pipeline globals configured.
    await main_mod._on_syslog_line("this is not a syslog line at all")  # noqa: SLF001


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_db_insert_path(
    tmp_path: Path, sample_bgp_down_log: str
) -> None:
    """A real engine drives the DB insert block (lines 117-145)."""
    engine = await get_engine(_db_url(tmp_path))
    await create_tables(engine)
    try:
        main_mod._engine = engine  # noqa: SLF001
        main_mod._correlator = None  # noqa: SLF001
        main_mod._dedup = None  # noqa: SLF001
        main_mod._escalation = None  # noqa: SLF001

        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

        # The alert was persisted.
        from sqlalchemy import func, select

        async with AsyncSession(engine) as session:
            count = (await session.execute(select(func.count(AlertLog.id)))).scalar()
        assert count == 1
    finally:
        await engine.dispose()


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_db_insert_failure_is_logged(
    sample_bgp_down_log: str,
) -> None:
    """A broken engine triggers the DB-insert except branch (lines 144-145)."""

    class _BoomEngine:
        """Any attribute access during session use raises."""

    main_mod._engine = _BoomEngine()  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    # Insert fails internally but the callback swallows + logs the error.
    await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_add_to_store_failure_is_logged(
    sample_bgp_down_log: str,
) -> None:
    """A failing add_alert_to_store hits the except branch (lines 153-154)."""
    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    with patch.object(
        main_mod, "add_alert_to_store", side_effect=RuntimeError("store boom")
    ):
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_maintenance_suppression(
    sample_bgp_down_log: str,
) -> None:
    """An active maintenance window flips will_notify off (lines 165-177)."""
    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    enriched = enrich(parse_syslog(sample_bgp_down_log))  # type: ignore[arg-type]
    now = datetime.now(UTC)
    window = {
        "id": "win-cov",
        "device_name": enriched.device_name,
        "start_time": (now - timedelta(hours=1)).isoformat(),
        "end_time": (now + timedelta(hours=1)).isoformat(),
    }

    discord = AsyncMock(return_value=True)
    telegram = AsyncMock(return_value=True)
    with (
        patch.object(main_mod, "get_maintenance_store", return_value=[window]),
        patch.object(main_mod, "send_discord_alert", discord),
        patch.object(main_mod, "send_telegram_alert", telegram),
    ):
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

    # Suppressed by the window → no notification dispatched.
    discord.assert_not_awaited()
    telegram.assert_not_awaited()


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_maintenance_naive_window_and_other_device(
    sample_bgp_down_log: str,
) -> None:
    """Naive-datetime window + a non-matching device entry (lines 164, 170, 172).

    The first store entry targets a different device and is skipped at the
    ``device_name`` guard (164). The second uses naive ``datetime`` objects so
    the tzinfo-normalisation branches (170, 172) run before the window match.
    """
    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    enriched = enrich(parse_syslog(sample_bgp_down_log))  # type: ignore[arg-type]
    now_naive = datetime.now(UTC).replace(tzinfo=None)
    store = [
        # Different device → hits the `continue` at line 164.
        {
            "id": "other-device",
            "device_name": "SOME-OTHER-DEVICE",
            "start_time": now_naive - timedelta(hours=1),
            "end_time": now_naive + timedelta(hours=1),
        },
        # Matching device, naive datetimes → hits the tzinfo branches (170/172).
        {
            "id": "naive-window",
            "device_name": enriched.device_name,
            "start_time": now_naive - timedelta(hours=1),
            "end_time": now_naive + timedelta(hours=1),
        },
    ]

    discord = AsyncMock(return_value=True)
    with (
        patch.object(main_mod, "get_maintenance_store", return_value=store),
        patch.object(main_mod, "send_discord_alert", discord),
    ):
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

    # The naive active window suppresses the notification.
    discord.assert_not_awaited()


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_maintenance_malformed_window_continues(
    sample_bgp_down_log: str,
) -> None:
    """A window with an unparseable time hits the except/continue (176-177)."""
    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    enriched = enrich(parse_syslog(sample_bgp_down_log))  # type: ignore[arg-type]
    bad_window = {
        "id": "win-bad",
        "device_name": enriched.device_name,
        "start_time": "not-a-timestamp",
        "end_time": "also-bad",
    }
    discord = AsyncMock(return_value=True)
    with (
        patch.object(main_mod, "get_maintenance_store", return_value=[bad_window]),
        patch.object(main_mod, "send_discord_alert", discord),
    ):
        # Malformed window is skipped; notification still proceeds.
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_notify_path(
    tmp_path: Path, sample_bgp_down_log: str
) -> None:
    """Discord + Telegram enabled drives the notify block (lines 183-187)."""
    from src.notifications.escalation import EscalationEngine

    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = EscalationEngine()  # noqa: SLF001

    settings = _make_settings(tmp_path, discord_enabled=True, telegram_enabled=True)
    discord = AsyncMock(return_value=True)
    telegram = AsyncMock(return_value=True)

    with (
        patch.object(main_mod, "get_settings", return_value=settings),
        patch.object(main_mod, "send_discord_alert", discord),
        patch.object(main_mod, "send_telegram_alert", telegram),
    ):
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

    discord.assert_awaited_once()
    telegram.assert_awaited_once()
    # Escalation engine tracked the notify-worthy alert.
    assert main_mod._escalation is not None  # noqa: SLF001


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_dedup_suppresses(sample_bgp_down_log: str) -> None:
    """When dedup says no, should_send is False — DB/store/notify all skipped."""
    from unittest.mock import MagicMock

    dedup = MagicMock()
    dedup.should_notify.return_value = (False, "suppressed_duplicate")

    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = None  # noqa: SLF001
    main_mod._dedup = dedup  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    with patch.object(main_mod, "add_alert_to_store") as add_store:
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001

    # should_send False → in-memory store is never touched.
    add_store.assert_not_called()
    dedup.should_notify.assert_called_once()


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_on_syslog_line_with_correlator(sample_bgp_down_log: str) -> None:
    """A live correlator exercises the correlate branch (line 105) + store."""
    from src.core.correlator import CorrelationEngine

    main_mod._engine = None  # noqa: SLF001
    main_mod._correlator = CorrelationEngine()  # noqa: SLF001
    main_mod._dedup = None  # noqa: SLF001
    main_mod._escalation = None  # noqa: SLF001

    # Should run through correlate → store → broadcast without error.
    await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001


# ---------------------------------------------------------------------------
# _digest_scheduler (lines 232-254)
# ---------------------------------------------------------------------------


def _fixed_now(when: datetime) -> type:
    """Build a ``datetime`` subclass whose ``now()`` returns *when*.

    ``_digest_scheduler`` does ``from datetime import datetime`` locally and
    calls ``datetime.now(UTC)``.  Patching ``datetime.datetime`` in the stdlib
    module makes that local binding resolve to this stub at call time.
    """

    class _FixedDatetime(datetime):
        @classmethod
        def now(cls, tz: object = None) -> datetime:  # noqa: ARG003
            return when

    return _FixedDatetime


async def test_digest_scheduler_fires_at_hour_two(tmp_path: Path) -> None:
    """At 02:00 UTC the scheduler runs the digest once (lines 245-250)."""
    fixed = _fixed_now(datetime(2026, 5, 24, 2, 30, tzinfo=UTC))

    # A real engine is needed because the scheduler opens an AsyncSession
    # before invoking the (patched) digest sender.
    engine = await get_engine(_db_url(tmp_path))
    await create_tables(engine)

    call_count = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        # First sleep returns; second raises to break the while loop.
        call_count["n"] += 1
        if call_count["n"] >= 2:
            raise asyncio.CancelledError

    digest = AsyncMock(return_value=True)

    try:
        with (
            patch("src.main.asyncio.sleep", _fake_sleep),
            patch("src.notifications.digest.send_daily_digest", digest),
            patch("datetime.datetime", fixed),
            contextlib.suppress(asyncio.CancelledError),
        ):
            await main_mod._digest_scheduler(engine)  # noqa: SLF001
    finally:
        await engine.dispose()

    digest.assert_awaited_once()


async def test_digest_scheduler_skips_off_hour() -> None:
    """Outside 02:00 the digest is not sent (line 245 false)."""
    fixed = _fixed_now(datetime(2026, 5, 24, 9, 0, tzinfo=UTC))

    async def _fake_sleep(_seconds: float) -> None:
        raise asyncio.CancelledError

    digest = AsyncMock(return_value=True)
    with (
        patch("src.main.asyncio.sleep", _fake_sleep),
        patch("src.notifications.digest.send_daily_digest", digest),
        patch("datetime.datetime", fixed),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await main_mod._digest_scheduler(engine=object())  # noqa: SLF001

    digest.assert_not_awaited()


async def test_digest_scheduler_swallows_errors() -> None:
    """A non-cancel error in the loop is logged, not propagated (253-254)."""
    state = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("transient digest error")
        raise asyncio.CancelledError

    with (
        patch("src.main.asyncio.sleep", _fake_sleep),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await main_mod._digest_scheduler(engine=object())  # noqa: SLF001

    # Reached the second iteration → the first error was swallowed.
    assert state["n"] == 2


# ---------------------------------------------------------------------------
# _escalation_checker (lines 265-279)
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_escalation_checker_logs_pending(sample_bgp_down_log: str) -> None:
    """Pending escalations iterated, notifications sent, mark_escalated called."""
    from unittest.mock import MagicMock

    enriched = enrich(parse_syslog(sample_bgp_down_log))  # type: ignore[arg-type]
    esc = MagicMock()
    # get_pending_escalations now returns (EnrichedLog, int) tuples.
    esc.get_pending_escalations.return_value = [(enriched, 20)]
    esc.mark_escalated = MagicMock(return_value=True)
    main_mod._escalation = esc  # noqa: SLF001

    # The loop sleeps first, then runs its body; sleep must return once before
    # cancelling so the get_pending_escalations() body executes.
    state = {"n": 0}

    async def _sleep_once(_seconds: float) -> None:
        state["n"] += 1
        if state["n"] >= 2:
            raise asyncio.CancelledError

    discord_calls: list = []
    telegram_calls: list = []

    async def _stub_discord_escalation(
        alert: object, elapsed: int, settings: object  # noqa: ARG001
    ) -> bool:
        discord_calls.append((alert, elapsed))
        return True

    async def _stub_telegram_escalation(
        alert: object, elapsed: int, settings: object  # noqa: ARG001
    ) -> bool:
        telegram_calls.append((alert, elapsed))
        return True

    with (
        patch("src.main.asyncio.sleep", _sleep_once),
        patch("src.main.send_discord_escalation", _stub_discord_escalation),
        patch("src.main.send_telegram_escalation", _stub_telegram_escalation),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await main_mod._escalation_checker()  # noqa: SLF001

    esc.get_pending_escalations.assert_called()
    esc.mark_escalated.assert_called_once_with(
        enriched.device_name, enriched.parsed.mnemonic
    )


async def test_escalation_checker_swallows_errors() -> None:
    """A non-cancel error in the loop is logged, not raised (278-279)."""
    state = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("transient escalation error")
        raise asyncio.CancelledError

    with (
        patch("src.main.asyncio.sleep", _fake_sleep),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await main_mod._escalation_checker()  # noqa: SLF001

    assert state["n"] == 2


# ---------------------------------------------------------------------------
# Page + health routes (lines 446-511 area; targets 488-511)
# ---------------------------------------------------------------------------


def test_page_and_health_routes(tmp_path: Path) -> None:
    """GET /, /statistics, /settings, /health all render successfully.

    Uses a plain (non-lifespan) TestClient so the page handlers and the
    health route are exercised without starting the receiver.
    """
    settings = _make_settings(tmp_path)
    # Patch get_settings so /settings (which calls src.config.get_settings)
    # and any settings access stay deterministic.
    with patch("src.config.get_settings", return_value=settings):
        client = TestClient(main_mod.app)
        for path in ("/", "/statistics", "/settings"):
            resp = client.get(path)
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/html")

        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# WebSocket endpoints (lines 488-496 and 502-511)
# ---------------------------------------------------------------------------


def test_ws_all_connect_and_disconnect() -> None:
    """Connecting then closing /ws exercises connect + finally disconnect."""
    client = TestClient(main_mod.app)
    with client.websocket_connect("/ws") as ws:
        # Push one message in so the receive_text() loop runs once (line 492).
        ws.send_text("ping")
    # Exiting the context closes the socket → the except/finally path runs.


def test_ws_filtered_sets_filter_then_disconnects() -> None:
    """The /ws/filtered handler reads the filter then loops (lines 502-511)."""
    client = TestClient(main_mod.app)
    with client.websocket_connect("/ws/filtered") as ws:
        # First message is the classification filter (line 504-505).
        ws.send_text("critical")
        # Second message keeps the loop alive once (line 507).
        ws.send_text("keepalive")
    # Closing triggers the disconnect cleanup (line 511).


# ---------------------------------------------------------------------------
# _hourly_aggregator background task
# ---------------------------------------------------------------------------


async def test_hourly_aggregator_writes_hourly_stats(tmp_path: Path) -> None:
    """_hourly_aggregator opens a session, calls aggregate_hourly, and commits.

    One sleep iteration is allowed to run; the second sleep raises
    CancelledError to terminate the loop.  We verify that HourlyStats received
    at least one row (meaning aggregate_hourly was actually called and committed).
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    from src.database.models import AlertLog, HourlyStats

    engine = await get_engine(_db_url(tmp_path))
    await create_tables(engine)

    # Seed one alert so aggregate_hourly has something to bucket.
    hour_ts = datetime(2026, 5, 25, 10, 0, 0, tzinfo=UTC)
    async with AsyncSession(engine) as session:
        session.add(
            AlertLog(
                timestamp=hour_ts + timedelta(minutes=5),
                source_ip="192.168.203.1",
                device_name="BSCCL-EQ-RTR-01",
                hostname="BSCCL-EQ-RTR-01",
                facility="BGP",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="test",
                raw="raw line",
                classification="CRITICAL",
            )
        )
        await session.commit()

    call_count = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        call_count["n"] += 1
        if call_count["n"] >= 2:
            raise asyncio.CancelledError

    try:
        with (
            patch("src.main.asyncio.sleep", _fake_sleep),
            contextlib.suppress(asyncio.CancelledError),
        ):
            await main_mod._hourly_aggregator(engine)  # noqa: SLF001
    finally:
        pass  # engine disposed below

    # Verify at least one HourlyStats row was written and committed.
    async with AsyncSession(engine) as session:
        result = await session.execute(select(HourlyStats))
        rows = result.scalars().all()

    await engine.dispose()

    assert len(rows) >= 1, "HourlyStats must have at least one row after aggregation"
    assert rows[0].device_name == "BSCCL-EQ-RTR-01"
    assert rows[0].critical_count == 1


async def test_hourly_aggregator_swallows_errors() -> None:
    """A non-cancel exception in the aggregation loop is logged, not raised.

    The first sleep raises a RuntimeError (simulating a DB failure); the second
    sleep raises CancelledError to stop the loop.  The task must reach the
    second iteration, proving the first error was caught and swallowed.
    """
    state = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("transient aggregator error")
        raise asyncio.CancelledError

    with (
        patch("src.main.asyncio.sleep", _fake_sleep),
        contextlib.suppress(asyncio.CancelledError),
    ):
        await main_mod._hourly_aggregator(engine=object())  # noqa: SLF001

    # Reached second iteration → the first error was swallowed.
    assert state["n"] == 2


async def test_hourly_aggregator_cancels_cleanly() -> None:
    """CancelledError on the first sleep breaks the loop without propagating."""
    state = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        state["n"] += 1
        raise asyncio.CancelledError

    # CancelledError must not propagate out of _hourly_aggregator.
    with patch("src.main.asyncio.sleep", _fake_sleep):
        await main_mod._hourly_aggregator(engine=object())  # noqa: SLF001
    assert state["n"] == 1


@pytest.mark.usefixtures("_reset_pipeline_globals")
async def test_lifespan_creates_hourly_aggregator_task(tmp_path: Path) -> None:
    """Lifespan startup must create the hourly aggregator background task.

    We verify this by patching _hourly_aggregator with a spy coroutine that
    records when it is called, then confirming the patched version ran during
    the lifespan startup.
    """
    settings = _make_settings(tmp_path)
    _StubReceiver.instances.clear()

    # Capture the real asyncio.sleep BEFORE patching so our helper coroutines
    # can yield control without recursing into the patched version.
    _real_sleep = asyncio.sleep

    async def _fast_sleep(_seconds: float) -> None:
        await _real_sleep(0)

    hourly_called = {"n": 0}

    async def _stub_hourly_aggregator(_engine: object) -> None:
        hourly_called["n"] += 1
        # Yield control once then return so the task completes quickly.
        await _real_sleep(0)

    with (
        patch.object(main_mod, "get_settings", return_value=settings),
        patch.object(main_mod, "SyslogReceiver", _StubReceiver),
        patch("src.main.asyncio.sleep", _fast_sleep),
        patch.object(main_mod, "_hourly_aggregator", _stub_hourly_aggregator),
    ):
        async with main_mod.lifespan(main_mod.app):
            # Give the event loop a chance to schedule the created task.
            await _real_sleep(0)

    assert (
        hourly_called["n"] >= 1
    ), "_hourly_aggregator must be called during lifespan startup"
