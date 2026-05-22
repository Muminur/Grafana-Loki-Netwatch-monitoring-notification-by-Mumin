"""Per-client SLA tracking for BSCCL NetWatch.

Calculates uptime percentage, MTBF, and MTTR from incident history stored
in the ``Incident`` table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import select

from src.database.models import Incident

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class ClientSLA:
    """SLA metrics for a single client over a measurement period.

    Attributes
    ----------
    client_name:
        The client identifier (matches the ``affected_clients`` JSON field
        in the ``Incident`` table).
    uptime_percent:
        Percentage of the measurement period during which the client's
        service was up.  Range: 0.0 – 100.0.
    mtbf_hours:
        Mean Time Between Failures in hours.  0.0 when there are fewer
        than 2 incidents (undefined for a single or no-incident period).
    mttr_minutes:
        Mean Time To Recover in minutes.  0.0 when no incidents were
        resolved in the period.
    incidents_count:
        Total number of incidents affecting this client in the period.
    """

    client_name: str
    uptime_percent: float
    mtbf_hours: float
    mttr_minutes: float
    incidents_count: int


async def calculate_client_sla(
    session: AsyncSession,
    client_name: str,
    days: int = 30,
) -> ClientSLA:
    """Calculate SLA metrics for a specific client over a lookback window.

    Incidents are matched by checking whether ``client_name`` appears in the
    JSON ``affected_clients`` list on each resolved ``Incident`` row.

    Parameters
    ----------
    session:
        An active async session.
    client_name:
        Client identifier to look up.
    days:
        Lookback window in days (default 30).

    Returns
    -------
    ClientSLA
        Frozen dataclass with all SLA metrics.  If no incidents exist the
        client is assumed to have 100 % uptime.
    """
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(days=days)
    total_window_minutes = days * 24 * 60.0

    # Fetch resolved incidents that overlap the window
    stmt = select(Incident).where(
        Incident.status == "resolved",
        Incident.created_at >= window_start,
    )
    result = await session.execute(stmt)
    all_incidents = result.scalars().all()

    # Filter to those affecting this client
    client_incidents = [
        inc
        for inc in all_incidents
        if _client_in_incident(client_name, inc.affected_clients)
    ]

    if not client_incidents:
        return ClientSLA(
            client_name=client_name,
            uptime_percent=100.0,
            mtbf_hours=0.0,
            mttr_minutes=0.0,
            incidents_count=0,
        )

    # Calculate total downtime (sum of incident durations)
    total_downtime_minutes = 0.0
    repair_times: list[float] = []

    for inc in client_incidents:
        if inc.resolved_at is not None:
            created = _ensure_utc(inc.created_at)
            resolved = _ensure_utc(inc.resolved_at)
            duration_minutes = (resolved - created).total_seconds() / 60.0
            total_downtime_minutes += duration_minutes
            repair_times.append(duration_minutes)

    uptime_minutes = max(0.0, total_window_minutes - total_downtime_minutes)
    uptime_percent = (uptime_minutes / total_window_minutes) * 100.0
    uptime_percent = max(0.0, min(100.0, uptime_percent))

    # MTTR: mean repair time
    mttr_minutes = sum(repair_times) / len(repair_times) if repair_times else 0.0

    # MTBF: mean time between failures
    # Defined as window_hours / incident_count when incidents > 1
    incident_count = len(client_incidents)
    mtbf_hours = days * 24.0 / incident_count if incident_count >= 2 else 0.0

    return ClientSLA(
        client_name=client_name,
        uptime_percent=uptime_percent,
        mtbf_hours=mtbf_hours,
        mttr_minutes=mttr_minutes,
        incidents_count=incident_count,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _client_in_incident(client_name: str, affected_clients_json: str) -> bool:
    """Check whether ``client_name`` appears in the JSON affected_clients list."""
    if not affected_clients_json:
        return False
    try:
        clients: list[str] = json.loads(affected_clients_json)
        return client_name in clients
    except (json.JSONDecodeError, TypeError):
        return False


def _ensure_utc(dt: datetime) -> datetime:
    """Return ``dt`` with UTC timezone attached if it is naive."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt
