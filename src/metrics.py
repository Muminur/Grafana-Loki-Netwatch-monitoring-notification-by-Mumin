"""Prometheus metrics for BSCCL NetWatch.

Exposes a dedicated ``CollectorRegistry`` so that the metrics defined here
are completely isolated from the default prometheus-client global registry.
This prevents double-registration errors on module re-import (e.g. during
test runs) and keeps the production server's default registry clean.

Exported metrics
----------------
netwatch_alerts_processed_total{classification}
    Counter — each call to :func:`record_alert` increments the counter for
    the given *classification* label.

netwatch_dedup_suppressed_total
    Counter — each call to :func:`record_dedup_suppressed` increments this.

netwatch_notifications_sent_total{channel}
    Counter — each call to :func:`record_notification` increments the
    counter for the given *channel* label (``"discord"`` / ``"telegram"``).

netwatch_websocket_connections
    Gauge — :func:`set_ws_connections` replaces the current value.

Usage
-----
Import the helper functions where behaviour happens:

    from src.metrics import record_alert, record_dedup_suppressed, render

Then expose ``/metrics`` via the route added in ``src/api/routes.py``.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    generate_latest,
)

# ---------------------------------------------------------------------------
# Module-level singleton registry — isolated from the prometheus-client global
# ---------------------------------------------------------------------------

_REGISTRY = CollectorRegistry(auto_describe=True)

# ---------------------------------------------------------------------------
# Metric definitions
# ---------------------------------------------------------------------------

_alerts_processed = Counter(
    "netwatch_alerts_processed_total",
    "Total syslog alerts processed by the pipeline, labelled by classification.",
    labelnames=["classification"],
    registry=_REGISTRY,
)

_dedup_suppressed = Counter(
    "netwatch_dedup_suppressed_total",
    "Total number of notifications suppressed by the deduplication engine.",
    registry=_REGISTRY,
)

_notifications_sent = Counter(
    "netwatch_notifications_sent_total",
    "Total number of notifications successfully dispatched, labelled by channel.",
    labelnames=["channel"],
    registry=_REGISTRY,
)

_ws_connections = Gauge(
    "netwatch_websocket_connections",
    "Current number of active WebSocket connections.",
    registry=_REGISTRY,
)

# ---------------------------------------------------------------------------
# Helper functions — thin wrappers kept separate so call-sites stay readable
# ---------------------------------------------------------------------------


def record_alert(classification: str = "UNKNOWN") -> None:
    """Increment the alerts-processed counter for *classification*.

    Parameters
    ----------
    classification:
        The classification label, e.g. ``"CRITICAL"``, ``"WARNING"``, etc.
        Defaults to ``"UNKNOWN"`` when not provided.
    """
    _alerts_processed.labels(classification=classification).inc()


def record_dedup_suppressed() -> None:
    """Increment the deduplication-suppressed counter by one."""
    _dedup_suppressed.inc()


def record_notification(channel: str) -> None:
    """Increment the notifications-sent counter for *channel*.

    Parameters
    ----------
    channel:
        The notification channel label, e.g. ``"discord"`` or ``"telegram"``.
    """
    _notifications_sent.labels(channel=channel).inc()


def set_ws_connections(n: int) -> None:
    """Set the WebSocket connection gauge to *n*.

    Parameters
    ----------
    n:
        The current number of active WebSocket connections.
    """
    _ws_connections.set(n)


def render() -> tuple[bytes, str]:
    """Render the current metrics in Prometheus exposition format.

    Returns
    -------
    tuple[bytes, str]
        ``(exposition_bytes, content_type)`` — suitable for building a
        :class:`fastapi.Response` directly::

            content, media_type = render()
            return Response(content=content, media_type=media_type)
    """
    return generate_latest(_REGISTRY), CONTENT_TYPE_LATEST
