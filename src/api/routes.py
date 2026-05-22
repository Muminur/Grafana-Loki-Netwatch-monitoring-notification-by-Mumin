"""REST API routes for BSCCL NetWatch.

Milestone 6: minimal health endpoint.
Milestone 7: expanded alert, incident, device, topology, stats, BGP endpoints.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from src.data.device_map import DEVICE_MAP
from src.data.topology import NETWORK_TOPOLOGY

router = APIRouter()

# Application start time (module-level; set when the module is first imported)
_APP_START: float = time.monotonic()

# Shared counters updated by the ingestion pipeline
_alerts_processed: int = 0
_active_connections: int = 0

# In-memory stores — will be replaced with DB in a later milestone
_alerts_store: list[dict[str, Any]] = []
_incidents_store: list[dict[str, Any]] = []


def increment_alerts_processed() -> None:
    """Increment the global alert counter (called by the ingestion pipeline)."""
    global _alerts_processed  # noqa: PLW0603
    _alerts_processed += 1


def set_active_connections(count: int) -> None:
    """Update the WebSocket connection count (called by WebSocketManager)."""
    global _active_connections  # noqa: PLW0603
    _active_connections = count


def add_alert(alert: dict[str, Any]) -> None:
    """Append an alert to the in-memory store (called by the ingestion pipeline)."""
    _alerts_store.append(alert)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check endpoint.

    Returns
    -------
    dict
        ``status``, ``version``, ``uptime_seconds``, ``alerts_processed``,
        and ``active_connections``.
    """
    uptime = time.monotonic() - _APP_START
    return {
        "status": "ok",
        "version": "0.1.0",
        "uptime_seconds": round(uptime, 1),
        "alerts_processed": _alerts_processed,
        "active_connections": _active_connections,
    }


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/api/alerts")
async def get_alerts(
    severity: str | None = Query(default=None, description="Filter by severity"),
    device: str | None = Query(default=None, description="Filter by device name"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    """Return a paginated list of alerts, optionally filtered by severity or device.

    Parameters
    ----------
    severity:
        Optional severity filter (CRITICAL, WARNING, INFO, NOISE, USER_LOGIN).
    device:
        Optional device name filter.
    limit:
        Maximum number of alerts to return (1-1000, default 100).
    offset:
        Number of alerts to skip (for pagination).

    Returns
    -------
    list[dict]
        List of alert dicts from the in-memory store.
    """
    results = list(_alerts_store)

    if severity is not None:
        sev_upper = severity.upper()
        results = [a for a in results if a.get("classification") == sev_upper]

    if device is not None:
        results = [a for a in results if a.get("device") == device]

    return results[offset : offset + limit]


@router.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str) -> dict[str, Any]:
    """Return a single alert by ID.

    Parameters
    ----------
    alert_id:
        Unique alert identifier.

    Raises
    ------
    HTTPException
        404 if the alert is not found.
    """
    for alert in _alerts_store:
        if str(alert.get("id")) == alert_id:
            return alert
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------


@router.get("/api/incidents")
async def get_incidents() -> list[dict[str, Any]]:
    """Return all active incidents.

    Returns
    -------
    list[dict]
        List of incident dicts from the in-memory store.
    """
    return list(_incidents_store)


@router.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str) -> dict[str, Any]:
    """Return a single incident by ID.

    Parameters
    ----------
    incident_id:
        Unique incident identifier.

    Raises
    ------
    HTTPException
        404 if the incident is not found.
    """
    for incident in _incidents_store:
        if str(incident.get("id")) == incident_id:
            return incident
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


@router.post("/api/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: str) -> dict[str, Any]:
    """Acknowledge an active incident.

    Parameters
    ----------
    incident_id:
        Unique incident identifier.

    Raises
    ------
    HTTPException
        404 if the incident is not found.
    """
    for incident in _incidents_store:
        if str(incident.get("id")) == incident_id:
            incident["acknowledged"] = True
            return {"status": "acknowledged", "incident_id": incident_id}
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


@router.get("/api/stats/daily")
async def get_stats_daily() -> dict[str, Any]:
    """Return daily aggregated statistics.

    Returns a dict with alert counts by classification for today.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    counts: dict[str, int] = dict.fromkeys(classifications, 0)
    for alert in _alerts_store:
        cls = alert.get("classification", "")
        if cls in counts:
            counts[cls] += 1
    return {
        "period": "daily",
        "counts": counts,
        "total": sum(counts.values()),
    }


@router.get("/api/stats/weekly")
async def get_stats_weekly() -> dict[str, Any]:
    """Return weekly aggregated statistics.

    Returns a dict with alert counts by classification for the past 7 days.
    """
    classifications = ["CRITICAL", "WARNING", "INFO", "NOISE", "USER_LOGIN"]
    counts: dict[str, int] = dict.fromkeys(classifications, 0)
    for alert in _alerts_store:
        cls = alert.get("classification", "")
        if cls in counts:
            counts[cls] += 1
    return {
        "period": "weekly",
        "counts": counts,
        "total": sum(counts.values()),
    }


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


@router.get("/api/devices")
async def get_devices() -> list[dict[str, Any]]:
    """Return all known network devices with their status.

    Returns
    -------
    list[dict]
        One entry per unique device (deduplicated — KKT aliases merged).
    """
    seen: set[str] = set()
    devices: list[dict[str, Any]] = []
    for ip, info in DEVICE_MAP.items():
        if info.name in seen:
            continue
        seen.add(info.name)
        devices.append(
            {
                "name": info.name,
                "hostname": info.hostname,
                "location": info.location,
                "platform": info.platform,
                "ip": ip,
                "status": "unknown",
            }
        )
    return devices


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


@router.get("/api/topology")
async def get_topology() -> dict[str, Any]:
    """Return network topology as nodes and links for SVG rendering.

    Returns
    -------
    dict
        ``nodes`` — list of device nodes with id, name, location, level.
        ``links`` — list of {source, target, bundle, description} dicts.
    """
    # Build node list from topology data (devices that have topology records)
    node_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []

    # Assign display levels: EQ=0, KKT=1, DHK/COX=2
    _level_map: dict[str, int] = {
        "Equinix-RTR-1": 0,
        "Equinix-RTR-2": 0,
        "KKT-Core-01": 1,
        "KKT-Core-02": 1,
        "KKT-Core-03": 1,
        "DHK-Core-03": 2,
        "COX-Core-01": 2,
        "COX-Core-03": 2,
        "DHK-Core-02": 2,
    }

    for ip, topo in NETWORK_TOPOLOGY.items():
        if topo.name not in node_ids:
            node_ids.add(topo.name)
            device_info = DEVICE_MAP.get(ip)
            nodes.append(
                {
                    "id": topo.name,
                    "name": topo.name,
                    "ip": ip,
                    "location": device_info.location if device_info else "",
                    "platform": device_info.platform if device_info else "",
                    "level": _level_map.get(topo.name, 2),
                    "status": "unknown",
                }
            )

    # Build link list from topology upstreams
    links: list[dict[str, Any]] = []
    seen_links: set[frozenset[str]] = set()
    for _ip, topo in NETWORK_TOPOLOGY.items():
        for bundle, link in topo.upstreams.items():
            remote_topo = NETWORK_TOPOLOGY.get(link.remote_device_ip)
            remote_name = remote_topo.name if remote_topo else link.remote_device_ip
            key = frozenset([topo.name, remote_name, bundle])
            if key in seen_links:
                continue
            seen_links.add(key)
            links.append(
                {
                    "source": topo.name,
                    "target": remote_name,
                    "bundle": bundle,
                    "description": link.description,
                    "members": len(link.members),
                    "status": "unknown",
                }
            )

    return {"nodes": nodes, "links": links}


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


@router.get("/api/bgp/peers")
async def get_bgp_peers() -> list[dict[str, Any]]:
    """Return BGP peer status list.

    Peers are derived from alerts in the store; returns empty list when no
    BGP events have been received yet.

    Returns
    -------
    list[dict]
        Each entry has neighbor, as_number, as_name, device, last_state.
    """
    seen: dict[str, dict[str, Any]] = {}
    for alert in _alerts_store:
        neighbor = alert.get("neighbor", "")
        if not neighbor:
            continue
        entry = {
            "neighbor": neighbor,
            "as_number": alert.get("as_number", 0),
            "as_name": alert.get("as_name", ""),
            "device": alert.get("device", ""),
            "last_state": alert.get("classification", "UNKNOWN"),
        }
        seen[neighbor] = entry
    return list(seen.values())
