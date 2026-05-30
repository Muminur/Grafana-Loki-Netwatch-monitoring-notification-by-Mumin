"""Monthly/yearly stats must be DB-backed, not in-memory-only (audit C1).

After a restart the in-memory ``_alerts_store`` is empty, so the monthly and
yearly stats tabs showed nothing until the store slowly refilled. These
endpoints must aggregate from the database like daily/weekly already do.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import src.main as main_mod
from src.api import routes as routes_mod
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog


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
async def test_monthly_and_yearly_stats_are_db_backed() -> None:
    """With an empty in-memory store, monthly/yearly aggregate from the DB."""
    engine = await get_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)
    async with AsyncSession(engine) as session:
        session.add(_alert(datetime(2026, 3, 10, 12, 0, 0), "CRITICAL"))  # noqa: DTZ001
        session.add(_alert(datetime(2026, 4, 10, 12, 0, 0), "WARNING"))  # noqa: DTZ001
        await session.commit()

    orig_engine = routes_mod._db_engine  # noqa: SLF001
    orig_alerts = list(routes_mod._alerts_store)  # noqa: SLF001
    routes_mod.set_db_engine(engine)
    routes_mod._alerts_store.clear()  # noqa: SLF001 — simulate a fresh restart
    try:
        transport = ASGITransport(app=main_mod.app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            monthly = await c.get("/api/stats/monthly")
            yearly = await c.get("/api/stats/yearly")

        assert monthly.status_code == 200
        mbody = monthly.json()
        assert mbody["total"] == 2
        assert {m["month"] for m in mbody["months"]} == {"2026-03", "2026-04"}

        assert yearly.status_code == 200
        ybody = yearly.json()
        assert ybody["total"] == 2
        assert {y["year"] for y in ybody["years"]} == {"2026"}
    finally:
        routes_mod.set_db_engine(orig_engine)
        routes_mod._alerts_store.clear()  # noqa: SLF001
        routes_mod._alerts_store.extend(orig_alerts)  # noqa: SLF001
        await engine.dispose()
