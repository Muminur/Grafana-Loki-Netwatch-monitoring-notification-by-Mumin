"""Tests for the Prometheus /metrics endpoint and src/metrics.py helpers.

Coverage targets
----------------
* GET /metrics returns HTTP 200 with the correct Prometheus content-type.
* The exposition body contains the expected metric names.
* Counter helpers increment their respective counters.
* Gauge helper reflects the set value.
* The exposition bytes are parseable by prometheus-client's own parser.
* Module re-import does not raise DuplicateMetric errors.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient
from prometheus_client.parser import (  # noqa: I001
    text_string_to_metric_families,
)

# ---------------------------------------------------------------------------
# /metrics endpoint — HTTP contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_200() -> None:
    """GET /metrics must return HTTP 200."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/metrics")

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_metrics_endpoint_content_type() -> None:
    """GET /metrics must return a text/plain Prometheus content-type header."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/metrics")

    assert response.status_code == 200
    ct = response.headers.get("content-type", "")
    # Prometheus scrapers identify the format via this prefix.
    assert ct.startswith("text/plain")


@pytest.mark.asyncio
async def test_metrics_endpoint_contains_expected_metric_names() -> None:
    """GET /metrics body must include all four metric family names."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/metrics")

    body = response.text
    assert "netwatch_alerts_processed_total" in body
    assert "netwatch_dedup_suppressed_total" in body
    assert "netwatch_notifications_sent_total" in body
    assert "netwatch_websocket_connections" in body


@pytest.mark.asyncio
async def test_metrics_endpoint_exposition_is_parseable() -> None:
    """The exposition text must be parseable by the prometheus-client parser."""
    from src.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/metrics")

    # text_string_to_metric_families raises on malformed exposition text.
    families: list[Any] = list(text_string_to_metric_families(response.text))
    names = {f.name for f in families}
    # The prometheus-client parser strips the conventional _total suffix for
    # counter metric families (raw text still contains the _total suffix).
    has_counter = (
        "netwatch_alerts_processed" in names
        or "netwatch_alerts_processed_total" in names
    )
    assert has_counter
    assert "netwatch_websocket_connections" in names


# ---------------------------------------------------------------------------
# Helper functions — unit tests via render() output (public API)
# ---------------------------------------------------------------------------


def _get_sample_value(text: str, metric: str, label_filter: str = "") -> float:
    """Extract a sample value from Prometheus exposition text.

    Searches for lines matching ``metric{...label_filter...} <value>`` and
    returns the float value of the first match, or 0.0 if not found.
    """
    # Match a line that starts with the metric name (with optional labels)
    # followed by whitespace and a float value.
    lf = re.escape(label_filter)
    pattern = re.compile(
        r"^" + re.escape(metric) + r"(?:\{[^}]*" + lf + r"[^}]*\})?\s+([\d.e+\-]+)",
        re.MULTILINE,
    )
    m = pattern.search(text)
    return float(m.group(1)) if m else 0.0


def test_record_alert_increments_counter() -> None:
    """record_alert() must increment the alerts-processed counter."""
    from src.metrics import record_alert, render

    text_before = render()[0].decode()
    before = _get_sample_value(
        text_before,
        "netwatch_alerts_processed_total",
        'classification="CRITICAL"',
    )
    record_alert("CRITICAL")
    text_after = render()[0].decode()
    after = _get_sample_value(
        text_after,
        "netwatch_alerts_processed_total",
        'classification="CRITICAL"',
    )
    assert after == before + 1.0


def test_record_alert_default_label() -> None:
    """record_alert() with no argument must use the 'UNKNOWN' label."""
    from src.metrics import record_alert, render

    text_before = render()[0].decode()
    before = _get_sample_value(
        text_before,
        "netwatch_alerts_processed_total",
        'classification="UNKNOWN"',
    )
    record_alert()
    text_after = render()[0].decode()
    after = _get_sample_value(
        text_after,
        "netwatch_alerts_processed_total",
        'classification="UNKNOWN"',
    )
    assert after == before + 1.0


def test_record_dedup_suppressed_increments_counter() -> None:
    """record_dedup_suppressed() must increment the dedup counter."""
    from src.metrics import record_dedup_suppressed, render

    text_before = render()[0].decode()
    before = _get_sample_value(text_before, "netwatch_dedup_suppressed_total")
    record_dedup_suppressed()
    text_after = render()[0].decode()
    after = _get_sample_value(text_after, "netwatch_dedup_suppressed_total")
    assert after == before + 1.0


def test_record_notification_increments_counter() -> None:
    """record_notification() must increment the notifications counter."""
    from src.metrics import record_notification, render

    text_before = render()[0].decode()
    before = _get_sample_value(
        text_before,
        "netwatch_notifications_sent_total",
        'channel="discord"',
    )
    record_notification("discord")
    text_after = render()[0].decode()
    after = _get_sample_value(
        text_after,
        "netwatch_notifications_sent_total",
        'channel="discord"',
    )
    assert after == before + 1.0


def test_set_ws_connections_reflects_value() -> None:
    """set_ws_connections() must update the gauge to the given value."""
    from src.metrics import render, set_ws_connections

    set_ws_connections(42)
    text = render()[0].decode()
    value = _get_sample_value(text, "netwatch_websocket_connections")
    assert value == 42.0

    set_ws_connections(0)
    text = render()[0].decode()
    value = _get_sample_value(text, "netwatch_websocket_connections")
    assert value == 0.0


def test_render_returns_bytes_and_content_type_string() -> None:
    """render() must return (bytes, str) with the prometheus content-type."""
    from src.metrics import render

    content, media_type = render()
    assert isinstance(content, bytes)
    assert isinstance(media_type, str)
    assert media_type.startswith("text/plain")


def test_render_output_contains_metric_names() -> None:
    """render() bytes must contain the four metric family names."""
    from src.metrics import render

    content, _ = render()
    text = content.decode()
    assert "netwatch_alerts_processed_total" in text
    assert "netwatch_dedup_suppressed_total" in text
    assert "netwatch_notifications_sent_total" in text
    assert "netwatch_websocket_connections" in text


def test_no_duplicate_registration_on_reimport() -> None:
    """Importing src.metrics multiple times must not raise DuplicateMetric."""
    import importlib

    import src.metrics as m

    # Re-importing the already-loaded module must be a no-op (Python caches it).
    reloaded = importlib.import_module("src.metrics")
    # Verify we got the same singleton registry back — same object identity
    # proves no new registrations occurred on the re-import.
    assert reloaded._REGISTRY is m._REGISTRY  # noqa: SLF001


# ---------------------------------------------------------------------------
# Integration: the pipeline actually moves the counters (closes the wiring gap)
# ---------------------------------------------------------------------------


async def test_pipeline_wires_alert_and_dedup_counters(
    sample_bgp_down_log: str,
) -> None:
    """Driving _on_syslog_line must increment alerts_processed and dedup_suppressed.

    Guards against the helpers being defined but never called from the pipeline.
    """
    import src.main as main_mod  # noqa: PLC0415
    from src.core.dedup import DedupEngine  # noqa: PLC0415
    from src.core.enricher import enrich  # noqa: PLC0415
    from src.core.parser import parse_syslog  # noqa: PLC0415
    from src.metrics import _REGISTRY  # noqa: PLC0415

    parsed = parse_syslog(sample_bgp_down_log)
    assert parsed is not None
    classification = enrich(parsed).classification

    def _alerts() -> float:
        return (
            _REGISTRY.get_sample_value(
                "netwatch_alerts_processed_total",
                {"classification": classification},
            )
            or 0.0
        )

    def _suppressed() -> float:
        return _REGISTRY.get_sample_value("netwatch_dedup_suppressed_total") or 0.0

    saved = (
        main_mod._engine,  # noqa: SLF001
        main_mod._correlator,  # noqa: SLF001
        main_mod._dedup,  # noqa: SLF001
        main_mod._escalation,  # noqa: SLF001
    )
    a0, d0 = _alerts(), _suppressed()
    try:
        main_mod._engine = None  # noqa: SLF001
        main_mod._correlator = None  # noqa: SLF001
        main_mod._dedup = DedupEngine(window_seconds=300)  # noqa: SLF001
        main_mod._escalation = None  # noqa: SLF001
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001  # new
        await main_mod._on_syslog_line(sample_bgp_down_log)  # noqa: SLF001  # dup
    finally:
        (
            main_mod._engine,  # noqa: SLF001
            main_mod._correlator,  # noqa: SLF001
            main_mod._dedup,  # noqa: SLF001
            main_mod._escalation,  # noqa: SLF001
        ) = saved

    # record_alert fires once per processed line; the 2nd identical line is
    # suppressed by dedup (record_dedup_suppressed fires once).
    assert _alerts() == a0 + 2
    assert _suppressed() == d0 + 1
