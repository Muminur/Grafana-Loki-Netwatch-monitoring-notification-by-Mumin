"""Tests for per-channel notification tracking and failure persistence.

Covers:
- AlertLog model has discord_sent, telegram_sent, discord_error, telegram_error columns.
- update_notification_status() correctly updates per-channel fields.
- get_failed_notifications() returns rows where one channel failed.
- Migration adds the 4 new columns to existing databases.

All tests use in-memory SQLite to avoid side effects.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from src.database.crud import (
    get_failed_notifications,
    insert_alert,
    update_notification_status,
)
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog

IN_MEMORY_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


def _make_alert(**kwargs) -> AlertLog:
    """Build a minimal AlertLog with sensible defaults."""
    defaults = {
        "timestamp": datetime(2026, 5, 22, 15, 0, 0, tzinfo=UTC),
        "source_ip": "192.168.203.1",
        "device_name": "BSCCL-EQ-RTR-01",
        "hostname": "BSCCL-EQ-RTR-01",
        "facility": "BGP",
        "severity_level": 5,
        "mnemonic": "ADJCHANGE",
        "message": "neighbor 2001:de8:4::39:9077:1 Down",
        "raw": "raw syslog line here",
        "classification": "CRITICAL",
    }
    defaults.update(kwargs)
    return AlertLog(**defaults)


# ---------------------------------------------------------------------------
# 1. Model columns exist with correct defaults
# ---------------------------------------------------------------------------


class TestAlertLogNotificationColumns:
    """AlertLog model has per-channel notification tracking columns."""

    @pytest.mark.asyncio
    async def test_new_columns_have_correct_defaults(
        self, session: AsyncSession
    ) -> None:
        """New AlertLog rows have discord_sent=False, telegram_sent=False,
        discord_error='', telegram_error='' by default."""
        alert = _make_alert(notification_sent=True)
        saved = await insert_alert(session, alert)
        await session.commit()

        assert saved.discord_sent is False
        assert saved.telegram_sent is False
        assert saved.discord_error == ""
        assert saved.telegram_error == ""

    @pytest.mark.asyncio
    async def test_columns_can_be_set_at_creation(self, session: AsyncSession) -> None:
        """Per-channel fields can be set at AlertLog creation time."""
        alert = _make_alert(
            notification_sent=True,
            discord_sent=True,
            telegram_sent=False,
            discord_error="",
            telegram_error="HTTP 500",
        )
        saved = await insert_alert(session, alert)
        await session.commit()

        assert saved.discord_sent is True
        assert saved.telegram_sent is False
        assert saved.telegram_error == "HTTP 500"


# ---------------------------------------------------------------------------
# 2. update_notification_status CRUD
# ---------------------------------------------------------------------------


class TestUpdateNotificationStatus:
    """update_notification_status() correctly updates per-channel fields."""

    @pytest.mark.asyncio
    async def test_update_discord_sent_only(self, session: AsyncSession) -> None:
        """Updating only discord_sent leaves telegram fields unchanged."""
        alert = _make_alert(notification_sent=True)
        saved = await insert_alert(session, alert)
        await session.commit()

        updated = await update_notification_status(session, saved.id, discord_sent=True)
        await session.commit()

        assert updated is True
        await session.refresh(saved)
        assert saved.discord_sent is True
        assert saved.telegram_sent is False  # unchanged
        assert saved.discord_error == ""  # unchanged
        assert saved.telegram_error == ""  # unchanged

    @pytest.mark.asyncio
    async def test_update_telegram_sent_with_error(self, session: AsyncSession) -> None:
        """Updating telegram_sent=False with an error message persists both."""
        alert = _make_alert(notification_sent=True)
        saved = await insert_alert(session, alert)
        await session.commit()

        updated = await update_notification_status(
            session,
            saved.id,
            discord_sent=True,
            telegram_sent=False,
            telegram_error="HTTP 429 (rate-limited)",
        )
        await session.commit()

        assert updated is True
        await session.refresh(saved)
        assert saved.discord_sent is True
        assert saved.telegram_sent is False
        assert saved.telegram_error == "HTTP 429 (rate-limited)"

    @pytest.mark.asyncio
    async def test_update_both_channels_success(self, session: AsyncSession) -> None:
        """Both channels marked as sent successfully."""
        alert = _make_alert(notification_sent=True)
        saved = await insert_alert(session, alert)
        await session.commit()

        updated = await update_notification_status(
            session, saved.id, discord_sent=True, telegram_sent=True
        )
        await session.commit()

        assert updated is True
        await session.refresh(saved)
        assert saved.discord_sent is True
        assert saved.telegram_sent is True

    @pytest.mark.asyncio
    async def test_update_nonexistent_alert_returns_false(
        self, session: AsyncSession
    ) -> None:
        """Updating a non-existent alert_id returns False."""
        result = await update_notification_status(session, 99999, discord_sent=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_update_discord_error_truncated(self, session: AsyncSession) -> None:
        """Error strings longer than 256 chars are truncated."""
        alert = _make_alert(notification_sent=True)
        saved = await insert_alert(session, alert)
        await session.commit()

        long_error = "X" * 300
        await update_notification_status(session, saved.id, discord_error=long_error)
        await session.commit()

        await session.refresh(saved)
        assert len(saved.discord_error) <= 256


# ---------------------------------------------------------------------------
# 3. get_failed_notifications CRUD
# ---------------------------------------------------------------------------


class TestGetFailedNotifications:
    """get_failed_notifications() returns alerts with partial delivery failure."""

    @pytest.mark.asyncio
    async def test_returns_discord_failure(self, session: AsyncSession) -> None:
        """Alert where discord_sent=False but telegram_sent=True is returned."""
        alert = _make_alert(
            notification_sent=True,
            discord_sent=False,
            telegram_sent=True,
            discord_error="HTTP 500",
        )
        await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 1
        assert results[0].discord_sent is False
        assert results[0].discord_error == "HTTP 500"

    @pytest.mark.asyncio
    async def test_returns_telegram_failure(self, session: AsyncSession) -> None:
        """Alert where telegram_sent=False but discord_sent=True is returned."""
        alert = _make_alert(
            notification_sent=True,
            discord_sent=True,
            telegram_sent=False,
            telegram_error="HTTP 429 (rate-limited)",
        )
        await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 1
        assert results[0].telegram_sent is False

    @pytest.mark.asyncio
    async def test_returns_both_failures(self, session: AsyncSession) -> None:
        """Alert where both channels failed is returned."""
        alert = _make_alert(
            notification_sent=True,
            discord_sent=False,
            telegram_sent=False,
            discord_error="timeout",
            telegram_error="timeout",
        )
        await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_excludes_fully_successful(self, session: AsyncSession) -> None:
        """Alert where both channels succeeded is NOT returned."""
        alert = _make_alert(
            notification_sent=True,
            discord_sent=True,
            telegram_sent=True,
        )
        await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_excludes_non_notified(self, session: AsyncSession) -> None:
        """Alert where notification_sent=False (never attempted) is NOT returned."""
        alert = _make_alert(
            notification_sent=False,
            discord_sent=False,
            telegram_sent=False,
        )
        await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_respects_limit(self, session: AsyncSession) -> None:
        """Only up to `limit` rows are returned."""
        for i in range(5):
            alert = _make_alert(
                notification_sent=True,
                discord_sent=False,
                telegram_sent=True,
                mnemonic=f"TEST{i:02d}",
            )
            await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=3)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_ordered_newest_first(self, session: AsyncSession) -> None:
        """Results are ordered by timestamp descending (newest first)."""
        for i in range(3):
            alert = _make_alert(
                notification_sent=True,
                discord_sent=False,
                telegram_sent=True,
                timestamp=datetime(2026, 5, 22, 10 + i, 0, 0, tzinfo=UTC),
                mnemonic=f"TS{i:02d}",
            )
            await insert_alert(session, alert)
        await session.commit()

        results = await get_failed_notifications(session, limit=100)
        assert len(results) == 3
        # Newest first
        assert results[0].timestamp > results[1].timestamp
        assert results[1].timestamp > results[2].timestamp


# ---------------------------------------------------------------------------
# 4. Migration adds columns to existing DB
# ---------------------------------------------------------------------------


class TestNotificationColumnsMigration:
    """Migration adds the 4 new columns to existing alert_log tables."""

    @pytest.mark.asyncio
    async def test_columns_present_after_migration(self) -> None:
        """All 4 per-channel columns exist in alert_log after create_tables."""
        _engine = await get_engine(IN_MEMORY_URL)
        await create_tables(_engine)

        async with AsyncSession(_engine) as session:
            result = await session.execute(text("PRAGMA table_info(alert_log)"))
            columns = {row[1] for row in result.fetchall()}

        await _engine.dispose()

        assert "discord_sent" in columns
        assert "telegram_sent" in columns
        assert "discord_error" in columns
        assert "telegram_error" in columns

    @pytest.mark.asyncio
    async def test_migration_idempotent(self) -> None:
        """Running create_tables twice does not fail for the new columns."""
        _engine = await get_engine(IN_MEMORY_URL)
        await create_tables(_engine)
        # Second call must not raise
        await create_tables(_engine)

        async with AsyncSession(_engine) as session:
            result = await session.execute(text("PRAGMA table_info(alert_log)"))
            columns = {row[1] for row in result.fetchall()}

        await _engine.dispose()

        assert "discord_sent" in columns
        assert "telegram_sent" in columns
        assert "discord_error" in columns
        assert "telegram_error" in columns
