"""Acknowledging an incident must cancel its pending escalation (audit D1).

Regression: ``EscalationEngine.acknowledge()`` had zero callers, so a CRITICAL
alert acknowledged by an operator in the dashboard still fired the 15-minute
escalation to the NOC channel. The ack endpoint must cancel the escalation.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

import src.main as main_mod
from src.api import routes as routes_mod
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.notifications.escalation import EscalationEngine


def test_acknowledge_incident_cancels_pending_escalation(
    sample_bgp_down_log: str,
) -> None:
    """POST /api/incidents/{id}/acknowledge cancels the tracked escalation."""
    parsed = parse_syslog(sample_bgp_down_log)
    assert parsed is not None
    enriched = enrich(parsed)
    assert enriched.classification == "CRITICAL"

    # delay=0 → the tracked CRITICAL alert is pending immediately.
    engine = EscalationEngine(escalation_delay=0)
    engine.track_alert(enriched)
    assert engine.get_pending_escalations(), "precondition: alert should be pending"

    incident_id = "INC-20260530-001"
    orig_engine = routes_mod._escalation_engine  # noqa: SLF001
    orig_inc = list(routes_mod._incidents_store)  # noqa: SLF001
    routes_mod.set_escalation_engine(engine)
    routes_mod._incidents_store.clear()  # noqa: SLF001
    routes_mod._incidents_store.append(  # noqa: SLF001
        {
            "id": incident_id,
            "device": enriched.device_name,
            "mnemonic": enriched.parsed.mnemonic,
            "interface": "",
            "neighbor": "",
            "as_number": 0,
            "message": "",
            "acknowledged": False,
        }
    )
    try:
        client = TestClient(main_mod.app)
        resp = client.post(f"/api/incidents/{incident_id}/acknowledge", json={})
        assert resp.status_code == 200
        # The human ACK must cancel the escalation — no longer pending.
        assert engine.get_pending_escalations() == []
    finally:
        routes_mod.set_escalation_engine(orig_engine)
        routes_mod._incidents_store.clear()  # noqa: SLF001
        routes_mod._incidents_store.extend(orig_inc)  # noqa: SLF001
