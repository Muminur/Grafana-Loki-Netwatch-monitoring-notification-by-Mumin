"""An acked INC- incident must stay acknowledged across a restart (audit C4).

The incident DB-synthesis assigns ``ALERT-{row.id}`` ids and restores acks from
the ``incident_ack`` table keyed by that id. A correlator incident is acked
under its ``INC-YYYYMMDD-NNN`` id, so the lookup never matched and the acked
incident reappeared as unacknowledged after a restart — re-alarming the
operator. The durable signal is ``AlertLog.acknowledged_at`` (set for both id
kinds by the ack endpoint).
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

import src.main as main_mod
from src.api import routes as routes_mod
from src.database.migrations import create_tables, get_engine
from src.database.models import AlertLog
from src.database.timeutils import now_bdt_naive


@pytest.mark.asyncio
async def test_acked_inc_incident_stays_acked_after_restart() -> None:
    """A synthesized incident whose alert row is acked comes back acknowledged."""
    engine = await get_engine("sqlite+aiosqlite:///:memory:")
    await create_tables(engine)
    async with AsyncSession(engine) as session:
        session.add(
            AlertLog(
                timestamp=now_bdt_naive(),
                source_ip="192.168.203.1",
                device_name="BSCCL-EQ-RTR-01",
                facility="BGP",
                severity_level=5,
                mnemonic="ADJCHANGE",
                message="backhaul down",
                raw="r",
                classification="CRITICAL",
                incident_id="INC-20260530-001",
                acknowledged_at=now_bdt_naive(),  # acked under the INC- id
            )
        )
        await session.commit()

    orig_engine = routes_mod._db_engine  # noqa: SLF001
    orig_inc = list(routes_mod._incidents_store)  # noqa: SLF001
    routes_mod.set_db_engine(engine)
    routes_mod._incidents_store.clear()  # noqa: SLF001 — force DB synthesis (restart)
    try:
        transport = ASGITransport(app=main_mod.app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/incidents")
        assert resp.status_code == 200
        incidents = resp.json()
        assert len(incidents) == 1
        assert incidents[0].get("acknowledged") is True
    finally:
        routes_mod.set_db_engine(orig_engine)
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_inc)  # noqa: SLF001
        await engine.dispose()
