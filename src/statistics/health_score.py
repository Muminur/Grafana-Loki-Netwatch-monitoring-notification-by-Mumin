"""Network health score calculator for BSCCL NetWatch.

Produces a 0-100 score reflecting the current health of the BSCCL backbone.
Pure function — no I/O, no database, no side effects.
"""

from __future__ import annotations


def calculate_health_score(
    critical_count: int,
    warning_count: int,
    active_incidents: int,
    flapping_peers: int,
    total_devices: int = 34,
) -> float:
    """Calculate network health score 0-100.

    Deductions (applied to a 100-point base):
    - Each active CRITICAL alert: -5 points
    - Each active WARNING alert: -1 point
    - Each active incident: -10 points
    - Each flapping BGP peer: -3 points

    Bonuses:
    - No CRITICALs present: +5 points
    - All devices reporting (total_devices > 0): +5 points

    The result is clamped to the [0, 100] range.

    Parameters
    ----------
    critical_count:
        Number of currently active CRITICAL alerts.
    warning_count:
        Number of currently active WARNING alerts.
    active_incidents:
        Number of active (unresolved) incidents.
    flapping_peers:
        Number of BGP peers currently in a FLAPPING state.
    total_devices:
        Total number of expected devices reporting syslog.
        When > 0, the "all devices reporting" bonus is applied.

    Returns
    -------
    float
        Health score in the range [0.0, 100.0].
    """
    score: float = 100.0

    # Deductions
    score -= critical_count * 5.0
    score -= warning_count * 1.0
    score -= active_incidents * 10.0
    score -= flapping_peers * 3.0

    # Bonuses
    if critical_count == 0:
        score += 5.0
    if total_devices > 0:
        score += 5.0

    # Clamp to [0, 100]
    return float(max(0.0, min(100.0, score)))
