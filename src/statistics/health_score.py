"""Network health score calculator for BSCCL NetWatch.

Produces a 0-100 score reflecting the current health of the BSCCL backbone,
following the PRD-SUPPLEMENT §E5.2 rubric.  Kept as a pure function — no I/O,
no database, no side effects; the caller supplies the counts.
"""

from __future__ import annotations


def calculate_health_score(
    critical_count: int,
    warning_count: int,
    bgp_down_count: int = 0,
    flapping_peers: int = 0,
    degraded_backhauls: int = 0,
    pni_healthy: bool = True,
) -> float:
    """Calculate the network health score (0-100) per PRD-SUPPLEMENT §E5.2.

    Base 100, with capped deductions and bonuses::

        - Active CRITICAL alerts:    -15 each (cap -60)
        - Active WARNING alerts:     -2 each  (cap -20)
        - BGP peers currently DOWN:  -3 each  (cap -30)
        - Flapping peers:            -5 each  (cap -25)
        - Degraded backhaul bundles: -10 each (cap -40)
        + All PNI links healthy:     +5
        + No CRITICAL alerts:        +5

    The result is clamped to [0, 100].

    Parameters
    ----------
    critical_count:
        Number of currently active CRITICAL alerts.
    warning_count:
        Number of currently active WARNING alerts.
    bgp_down_count:
        Number of BGP peers currently in the DOWN state.
    flapping_peers:
        Number of BGP peers currently flapping.
    degraded_backhauls:
        Number of backhaul bundles currently degraded (a member is down).
    pni_healthy:
        ``True`` when all PNI (private interconnect) links are healthy, which
        grants the +5 bonus.

    Returns
    -------
    float
        Health score in the range [0.0, 100.0].
    """
    score: float = 100.0

    # Capped deductions
    score -= min(critical_count * 15.0, 60.0)
    score -= min(warning_count * 2.0, 20.0)
    score -= min(bgp_down_count * 3.0, 30.0)
    score -= min(flapping_peers * 5.0, 25.0)
    score -= min(degraded_backhauls * 10.0, 40.0)

    # Bonuses
    if pni_healthy:
        score += 5.0
    if critical_count == 0:
        score += 5.0

    # Clamp to [0, 100]
    return float(max(0.0, min(100.0, score)))
