"""Shift-panel counts must be DB-backed, not in-memory-only (audit C2).

After a restart the in-memory ``_alerts_store`` is empty, so the shift handoff
panel showed 0 CRITICAL / 0 WARNING regardless of the day's activity. The counts
must come from the database, anchored at the (naive BDT) shift start.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import src.main as main_mod
from src.api import routes as routes_mod
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog
from src.database.timeutils import now_bdt_naive

if TYPE_CHECKING:
    from datetime import datetime


def _alert(ts: datetime, classification: str) -> AlertLog:
    return AlertLog(
        timestamp=ts,
        source_ip="192.168.203.1",
        device_name="BSCCL-EQ-RTR-01",
        facility="BGP",
        severity_level=5,
        mnemonic="ADJCHANGE",
        message="m",
        raw="r",
        classification=classification,
    )


@pytest.mark.asyncio
async def test_shift_panel_counts_are_db_backed() -> None:
    """With an empty in-memory store, the shift panel counts from the DB."""
    engine = await get_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)
    # An alert "now" (naive BDT) is always within the current shift.
    async with AsyncSession(engine) as session:
        session.add(_alert(now_bdt_naive(), "CRITICAL"))
        await session.commit()

    orig_engine = routes_mod._db_engine  # noqa: SLF001
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod.set_db_engine(engine)
    routes_mod._alerts_store.clear()  # noqa: SLF001 — simulate a fresh restart
    try:
        transport = ASGITransport(app=main_mod.app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/shift/current")
        assert resp.status_code == 200
        assert resp.json()["critical_since_shift"] >= 1
    finally:
        routes_mod.set_db_engine(orig_engine)
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001
        await engine.dispose()
