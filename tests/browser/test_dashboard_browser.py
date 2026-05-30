"""Browser e2e tests — verify the JS layer the httpx tests can't reach.

Run via the dedicated CI job (Playwright browsers installed) or locally with
``pytest -m browser``. Excluded from the default/matrix run.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.browser

_READ_KPI = """() => {
    const t = (id) => {
        const el = document.getElementById(id);
        return el ? (parseInt(el.textContent.trim(), 10) || 0) : 0;
    };
    const sev = ['tabCountCritical', 'tabCountWarning', 'tabCountInfo',
                 'tabCountNoise', 'tabCountLogin'].map(t);
    return {
        all: t('tabCountAll'),
        total: t('countTotal'),
        sumSev: sev.reduce((a, b) => a + (b || 0), 0),
    };
}"""

_CHART_SUM = """(id) => {
    const c = document.getElementById(id);
    const getChart = window.Chart && window.Chart.getChart;
    const inst = getChart ? window.Chart.getChart(c) : null;
    if (!inst) return -1;
    return inst.data.datasets.reduce(
        (a, ds) => a + (ds.data || []).reduce((x, y) => x + (y || 0), 0), 0);
}"""


def test_kpi_all_badge_equals_total(live_server: dict[str, Any], page: Any) -> None:
    """Regression for the ALL-badge bug: ALL must equal countTotal and the sum
    of the per-severity badges (it previously read the empty live array)."""
    expected_total = live_server["expected"]["total"]
    page.goto(f"{live_server['url']}/", wait_until="domcontentloaded")
    # 'all' period makes the count independent of wall-clock time.
    page.select_option("#periodFilter", "all")
    page.wait_for_function(
        "(n) => { const e = document.getElementById('countTotal');"
        " return e && parseInt(e.textContent.trim(), 10) === n; }",
        arg=expected_total,
        timeout=15000,
    )

    kpi = page.evaluate(_READ_KPI)
    assert kpi["all"] == kpi["total"], kpi
    assert kpi["all"] == kpi["sumSev"], kpi
    assert kpi["all"] == expected_total, kpi


def test_statistics_charts_have_data(live_server: dict[str, Any], page: Any) -> None:
    """Timeline and Top-Devices charts must populate from the API (bugs #2/#3)."""
    page.goto(f"{live_server['url']}/statistics", wait_until="domcontentloaded")
    # 'Week' (7d) always includes the recently-seeded alerts.
    page.click('[data-period="week"]')
    page.wait_for_selector('[data-period="week"].active', timeout=5000)
    page.wait_for_function(
        f"() => {{ const f = {_CHART_SUM};"
        f" return f('statsTimelineChart') > 0 && f('statsTopDevicesChart') > 0; }}",
        timeout=15000,
    )

    timeline = page.evaluate(f"() => ({_CHART_SUM})('statsTimelineChart')")
    devices = page.evaluate(f"() => ({_CHART_SUM})('statsTopDevicesChart')")
    assert timeline > 0, f"timeline empty: {timeline}"
    assert devices > 0, f"top-devices empty: {devices}"


def test_health_gauge_is_height_bounded(live_server: dict[str, Any], page: Any) -> None:
    """The stats health gauge must not overflow its panel (bug #1 — was 842px)."""
    page.goto(f"{live_server['url']}/statistics", wait_until="domcontentloaded")
    page.wait_for_function(
        "() => { const c = document.getElementById('statsHealthGauge');"
        " return c && c.getBoundingClientRect().height > 0; }",
        timeout=15000,
    )
    height = page.evaluate(
        "() => Math.round("
        "document.getElementById('statsHealthGauge').getBoundingClientRect().height)"
    )
    assert 0 < height <= 260, f"gauge height {height}px is not bounded"
