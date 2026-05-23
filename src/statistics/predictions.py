"""BGP prefix count trending and exhaustion predictions for BSCCL NetWatch.

Pure functions — no I/O, no database, no side effects.
"""

from __future__ import annotations


def predict_prefix_exhaustion(
    current_count: int,
    max_count: int,
    growth_rate: float,
) -> dict[str, object]:
    """Predict when a BGP prefix limit will be reached.

    Given the current prefix count, the configured maximum, and an observed
    daily growth rate, returns:
    - warning thresholds (80 % and 90 % of max)
    - estimated days until the maximum is reached
    - whether each warning threshold has already been crossed

    Parameters
    ----------
    current_count:
        Current number of prefixes received from the BGP peer.
    max_count:
        Configured maximum prefix limit (MAXPFX setting).
    growth_rate:
        Observed average prefix growth per day (floating point).  A value
        of 0 means the prefix count is stable and exhaustion will never
        occur.

    Returns
    -------
    dict
        Keys:
        - ``current_count`` (int)
        - ``max_count`` (int)
        - ``growth_rate`` (float)
        - ``warning_80_reached`` (bool) — current_count >= 80% of max
        - ``warning_90_reached`` (bool) — current_count >= 90% of max
        - ``days_until_max`` (int | None) — None if growth_rate == 0
        - ``days_until_80`` (int | None) — days until 80% threshold
        - ``days_until_90`` (int | None) — days until 90% threshold
    """
    threshold_80 = max_count * 0.80
    threshold_90 = max_count * 0.90

    warning_80_reached = current_count >= threshold_80
    warning_90_reached = current_count >= threshold_90

    if growth_rate <= 0.0:
        days_until_max: int | None = None
        days_until_80: int | None = None
        days_until_90: int | None = None
    else:
        remaining_to_max = max_count - current_count
        days_until_max = max(0, int(remaining_to_max / growth_rate))

        if current_count < threshold_80:
            days_until_80 = int((threshold_80 - current_count) / growth_rate)
        else:
            days_until_80 = 0

        if current_count < threshold_90:
            days_until_90 = int((threshold_90 - current_count) / growth_rate)
        else:
            days_until_90 = 0

    return {
        "current_count": current_count,
        "max_count": max_count,
        "growth_rate": growth_rate,
        "warning_80_reached": warning_80_reached,
        "warning_90_reached": warning_90_reached,
        "days_until_max": days_until_max,
        "days_until_80": days_until_80,
        "days_until_90": days_until_90,
    }
