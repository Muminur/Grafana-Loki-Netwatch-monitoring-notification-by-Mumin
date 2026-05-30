/**
 * BSCCL NETWATCH — Chart.js chart initialisation and updates.
 *
 * Manages four mini-charts on the dashboard:
 *   1. Health gauge (doughnut)
 *   2. Alert timeline stacked area
 *   3. Category donut
 *   4. Top devices bar
 *
 * Plus larger versions on the statistics page.
 */

(function () {
    'use strict';

    // Colour palette (matches neon-theme.css)
    var COLORS = {
        CRITICAL:   '#ff0040',
        WARNING:    '#ffdd00',
        INFO:       '#00f0ff',
        NOISE:      '#446688',
        USER_LOGIN: '#00ff88',
        muted:      '#555570',
        grid:       'rgba(80,80,120,0.2)',
        text:       '#8888a0',
    };

    var _isLargeDisplay = window.innerWidth >= 2000;

    function _evaluateDisplaySize() {
        return window.innerWidth >= 2000;
    }

    function _buildChartDefaults() {
        return {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: COLORS.text,
                        font: { family: 'JetBrains Mono', size: _isLargeDisplay ? 16 : 10 },
                        boxWidth: _isLargeDisplay ? 14 : 10,
                        padding: _isLargeDisplay ? 12 : 8,
                    },
                },
                tooltip: {
                    backgroundColor: '#0d0d1a',
                    borderColor: 'rgba(0,240,255,0.3)',
                    borderWidth: 1,
                    titleColor: '#00f0ff',
                    bodyColor: '#e8e8f0',
                    titleFont: { family: 'Orbitron', size: _isLargeDisplay ? 16 : 10 },
                    bodyFont: { family: 'JetBrains Mono', size: _isLargeDisplay ? 17 : 11 },
                },
            },
        };
    }

    // Chart default options shared across all charts
    var CHART_DEFAULTS = _buildChartDefaults();

    // ── Shared state ──────────────────────────────────────────────────────────
    var _charts = {};             // chart instance registry by canvas id
    var _timelineBuckets = [];    // 60 × 1-min buckets
    var _deviceCounts = {};       // device → count
    var _resizeObserver = null;   // ResizeObserver (if used) — cleaned up on unload

    // ── Timeline buckets (rolling 60-min window) ──────────────────────────────
    function _currentMinute() {
        return Math.floor(Date.now() / 60000);
    }

    function _ensureBuckets() {
        var now = _currentMinute();
        if (_timelineBuckets.length === 0) {
            for (var i = 59; i >= 0; i--) {
                _timelineBuckets.push({
                    minute: now - i,
                    CRITICAL: 0, WARNING: 0, INFO: 0, NOISE: 0, USER_LOGIN: 0,
                });
            }
        }
        // Advance to current minute
        var last = _timelineBuckets[_timelineBuckets.length - 1];
        while (last.minute < now) {
            _timelineBuckets.push({
                minute: last.minute + 1,
                CRITICAL: 0, WARNING: 0, INFO: 0, NOISE: 0, USER_LOGIN: 0,
            });
            last = _timelineBuckets[_timelineBuckets.length - 1];
        }
        // Keep only last 60
        while (_timelineBuckets.length > 60) {
            _timelineBuckets.shift();
        }
    }

    // ── Health gauge chart ────────────────────────────────────────────────────
    function _initHealthGauge(canvasId, small) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        if (_charts[canvasId]) { _charts[canvasId].destroy(); }

        var score = 100;
        var chart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [_healthColor(score), 'rgba(255,255,255,0.05)'],
                    borderWidth: 0,
                    circumference: 180,
                    rotation: 270,
                }],
            },
            options: Object.assign({}, CHART_DEFAULTS, {
                // Stats-page gauge fills a height-bounded wrapper instead of
                // forcing a 1:1 square that overflows the panel.
                maintainAspectRatio: !small,
                plugins: Object.assign({}, CHART_DEFAULTS.plugins, {
                    legend: { display: false },
                    tooltip: { enabled: false },
                }),
            }),
        });
        _charts[canvasId] = chart;
        return chart;
    }

    function _healthColor(score) {
        if (score >= 90) return COLORS.USER_LOGIN;   // green
        if (score >= 70) return COLORS.INFO;          // cyan
        if (score >= 50) return COLORS.WARNING;       // yellow
        return COLORS.CRITICAL;                        // red
    }

    function _updateHealthGauge(canvasId, score, displayId) {
        var chart = _charts[canvasId];
        if (!chart) return;
        chart.data.datasets[0].data = [score, 100 - score];
        chart.data.datasets[0].backgroundColor[0] = _healthColor(score);
        chart.update('none');
        var disp = document.getElementById(displayId);
        if (disp) disp.textContent = score;
    }

    // ── Timeline chart ────────────────────────────────────────────────────────
    function _initTimelineChart(canvasId) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        if (_charts[canvasId]) { _charts[canvasId].destroy(); }

        _ensureBuckets();
        var labels = _timelineBuckets.map(function (b) {
            var d = new Date(b.minute * 60000);
            return String((d.getUTCHours() + 6) % 24).padStart(2, '0')
                 + ':' + String(d.getUTCMinutes()).padStart(2, '0');
        });

        var classifications = ['CRITICAL', 'WARNING', 'INFO', 'NOISE', 'USER_LOGIN'];
        var datasets = classifications.map(function (cls) {
            return {
                label: cls,
                data: _timelineBuckets.map(function (b) { return b[cls] || 0; }),
                backgroundColor: COLORS[cls] + '55',
                borderColor: COLORS[cls],
                borderWidth: 1.5,
                fill: true,
                tension: 0.3,
                pointRadius: 0,
            };
        });

        var chart = new Chart(canvas, {
            type: 'line',
            data: { labels: labels, datasets: datasets },
            options: Object.assign({}, CHART_DEFAULTS, {
                scales: {
                    x: {
                        ticks: { color: COLORS.text, font: { family: 'JetBrains Mono', size: 9 }, maxTicksLimit: 8 },
                        grid: { color: COLORS.grid },
                    },
                    y: {
                        stacked: true,
                        beginAtZero: true,
                        ticks: { color: COLORS.text, font: { family: 'JetBrains Mono', size: 9 } },
                        grid: { color: COLORS.grid },
                    },
                },
                plugins: Object.assign({}, CHART_DEFAULTS.plugins, {
                    legend: { display: false },
                }),
            }),
        });
        _charts[canvasId] = chart;
        return chart;
    }

    // ── Category donut ────────────────────────────────────────────────────────
    function _initCategoryDonut(canvasId) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        if (_charts[canvasId]) { _charts[canvasId].destroy(); }

        var isStats = canvasId.indexOf('stats') === 0;
        var chart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: ['CRITICAL', 'WARNING', 'INFO', 'NOISE', 'LOGIN'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        COLORS.CRITICAL + 'cc',
                        COLORS.WARNING + 'cc',
                        COLORS.INFO + 'cc',
                        COLORS.NOISE + 'cc',
                        COLORS.USER_LOGIN + 'cc',
                    ],
                    borderColor: [
                        COLORS.CRITICAL,
                        COLORS.WARNING,
                        COLORS.INFO,
                        COLORS.NOISE,
                        COLORS.USER_LOGIN,
                    ],
                    borderWidth: 1,
                }],
            },
            options: Object.assign({}, CHART_DEFAULTS, {
                // Stats-page donut fills a height-bounded wrapper instead of
                // forcing a 1:1 square that overflows the panel.
                maintainAspectRatio: !isStats,
                plugins: Object.assign({}, CHART_DEFAULTS.plugins, {
                    legend: { position: 'right' },
                }),
            }),
        });
        _charts[canvasId] = chart;
        return chart;
    }

    // ── Top devices bar ───────────────────────────────────────────────────────
    function _initTopDevicesBar(canvasId) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        if (_charts[canvasId]) { _charts[canvasId].destroy(); }

        var chart = new Chart(canvas, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Alerts',
                    data: [],
                    backgroundColor: COLORS.INFO + '88',
                    borderColor: COLORS.INFO,
                    borderWidth: 1,
                }],
            },
            options: Object.assign({}, CHART_DEFAULTS, {
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { color: COLORS.text, font: { family: 'JetBrains Mono', size: 9 } },
                        grid: { color: COLORS.grid },
                    },
                    y: {
                        ticks: { color: COLORS.text, font: { family: 'JetBrains Mono', size: 9 } },
                        grid: { color: COLORS.grid },
                    },
                },
                plugins: Object.assign({}, CHART_DEFAULTS.plugins, {
                    legend: { display: false },
                }),
            }),
        });
        _charts[canvasId] = chart;
        return chart;
    }

    // ── Updaters called on each new alert ─────────────────────────────────────
    function _setDonutData(id, counters) {
        var chart = _charts[id];
        if (!chart) return;
        chart.data.datasets[0].data = [
            counters.CRITICAL || 0,
            counters.WARNING  || 0,
            counters.INFO     || 0,
            counters.NOISE    || 0,
            counters.USER_LOGIN || 0,
        ];
        chart.update('none');
    }

    // Live (dashboard) donut — driven by onAlert counters.
    function _updateCategoryDonut(counters) {
        _setDonutData('categoryDonutChart', counters);
    }

    // Statistics-page donut — driven by the API for the selected period, so it
    // stays consistent with the timeline/top-devices charts (not live alerts).
    function _updateStatsCategoryDonut(counts) {
        _setDonutData('statsCategoryDonut', counts);
    }

    function _updateTopDevices() {
        var sorted = Object.keys(_deviceCounts)
            .map(function (k) { return { name: k, count: _deviceCounts[k] }; })
            .sort(function (a, b) { return b.count - a.count; })
            .slice(0, 8);

        // Live updates target only the dashboard chart; the statistics-page
        // chart is historical and driven by the API (per_device).
        var ids = ['topDevicesChart'];
        ids.forEach(function (id) {
            var chart = _charts[id];
            if (!chart) return;
            chart.data.labels = sorted.map(function (d) { return d.name; });
            chart.data.datasets[0].data = sorted.map(function (d) { return d.count; });
            chart.update('none');
        });
    }

    function _updateTimeline() {
        _ensureBuckets();
        var classifications = ['CRITICAL', 'WARNING', 'INFO', 'NOISE', 'USER_LOGIN'];
        // Live updates target only the dashboard chart; the statistics-page
        // chart is historical and driven by the API (hourly_buckets).
        var ids = ['timelineChart'];
        ids.forEach(function (id) {
            var chart = _charts[id];
            if (!chart) return;
            chart.data.datasets.forEach(function (ds, i) {
                ds.data = _timelineBuckets.map(function (b) { return b[classifications[i]] || 0; });
            });
            chart.update('none');
        });
    }

    // ── Statistics page: historical charts driven by the stats API ───────────
    function _updateStatsTimeline(hourlyBuckets) {
        var chart = _charts['statsTimelineChart'];
        if (!chart || !Array.isArray(hourlyBuckets)) return;
        var classifications = ['CRITICAL', 'WARNING', 'INFO', 'NOISE', 'USER_LOGIN'];
        // b.hour is already BDT — the API buckets on strftime('%H', timestamp)
        // and timestamps are stored as naive BDT face values, so no UTC offset
        // is applied here (unlike the live dashboard window which uses Date.now).
        chart.data.labels = hourlyBuckets.map(function (b) {
            return String(b.hour).padStart(2, '0') + ':00';
        });
        chart.data.datasets.forEach(function (ds, i) {
            var cls = classifications[i];
            ds.data = hourlyBuckets.map(function (b) { return b[cls] || 0; });
        });
        chart.update('none');
    }

    function _updateStatsTopDevices(perDevice) {
        var chart = _charts['statsTopDevicesChart'];
        if (!chart || !Array.isArray(perDevice)) return;
        // The API (_finalize_per_device) already caps this at the top 10.
        chart.data.labels = perDevice.map(function (d) { return d.device; });
        chart.data.datasets[0].data = perDevice.map(function (d) { return d.count; });
        chart.update('none');
    }

    // ── Public: called when new alert arrives ─────────────────────────────────
    function onAlert(alert) {
        var cls = alert.classification;
        var now = _currentMinute();
        _ensureBuckets();
        var bucket = _timelineBuckets[_timelineBuckets.length - 1];
        if (bucket.minute === now && bucket.hasOwnProperty(cls)) {
            bucket[cls]++;
        }

        if (alert.device) {
            _deviceCounts[alert.device] = (_deviceCounts[alert.device] || 0) + 1;
        }

        _updateTimeline();
        _updateTopDevices();

        // Update donut using dashboard counters
        if (window.NetwatchDashboard) {
            var counters = window.NetwatchDashboard.getCounters();
            _updateCategoryDonut(counters);
            // Recalculate health score from live counters and update gauge
            var total = Object.values(counters).reduce(function (a, b) { return a + b; }, 0);
            var score = total === 0 ? 100 : Math.max(0, Math.min(100,
                100 - Math.floor((counters.CRITICAL || 0) * 5 + (counters.WARNING || 0) * 1)));
            _updateHealthGauge('healthGaugeChart', score, 'healthScoreValue');
        }
    }

    // ── Accessibility: set role and aria-label on chart canvases ─────────────
    var _chartTitles = {
        healthGaugeChart:     'Network Health Gauge',
        timelineChart:        'Alert Timeline (60 minutes)',
        categoryDonutChart:   'Alert Category Distribution',
        topDevicesChart:      'Top Devices by Alert Count',
        statsHealthGauge:     'Statistics Health Gauge',
        statsTimelineChart:   'Statistics Alert Timeline',
        statsCategoryDonut:   'Statistics Category Distribution',
        statsTopDevicesChart: 'Statistics Top Devices by Alert Count',
    };

    function _setChartAccessibility(canvasId) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        var title = _chartTitles[canvasId] || canvasId;
        canvas.setAttribute('role', 'img');
        canvas.setAttribute('aria-label', 'Chart: ' + title);
    }

    // ── Init dashboard mini-charts ────────────────────────────────────────────
    function initDashboard() {
        _isLargeDisplay = _evaluateDisplaySize();
        CHART_DEFAULTS = _buildChartDefaults();
        _initHealthGauge('healthGaugeChart');
        _initTimelineChart('timelineChart');
        _initCategoryDonut('categoryDonutChart');
        _initTopDevicesBar('topDevicesChart');

        // Set accessibility attributes on dashboard canvases
        _setChartAccessibility('healthGaugeChart');
        _setChartAccessibility('timelineChart');
        _setChartAccessibility('categoryDonutChart');
        _setChartAccessibility('topDevicesChart');
    }

    // ── Heatmap renderer ────────────────────────────────────────────────────
    var DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

    function _heatmapColor(count, maxCount) {
        if (maxCount === 0 || count === 0) return 'rgba(255,255,255,0.03)';
        var ratio = count / maxCount;
        // green → yellow → red
        if (ratio < 0.5) {
            // green to yellow
            var t = ratio / 0.5;
            var r = Math.round(0 + t * 255);
            var g = Math.round(255 - t * 34);  // 255 → 221
            var b = Math.round(136 - t * 136);  // 136 → 0
            return 'rgb(' + r + ',' + g + ',' + b + ')';
        }
        // yellow to red
        var t2 = (ratio - 0.5) / 0.5;
        var r2 = 255;
        var g2 = Math.round(221 - t2 * 221);  // 221 → 0
        var b2 = Math.round(t2 * 64);          // 0 → 64
        return 'rgb(' + r2 + ',' + g2 + ',' + b2 + ')';
    }

    function renderHeatmap(data, maxCount) {
        var body = document.getElementById('heatmapBody');
        if (!body) return;
        body.innerHTML = '';
        for (var day = 0; day < 7; day++) {
            var row = document.createElement('div');
            row.className = 'heatmap-row';
            var label = document.createElement('span');
            label.className = 'heatmap-day-label';
            label.textContent = DAY_LABELS[day];
            row.appendChild(label);
            for (var hour = 0; hour < 24; hour++) {
                var count = (data[day] && data[day][hour]) || 0;
                var cell = document.createElement('span');
                cell.className = 'heatmap-cell';
                cell.style.backgroundColor = _heatmapColor(count, maxCount);
                if (count > 0) {
                    cell.style.boxShadow = '0 0 4px ' + _heatmapColor(count, maxCount);
                }
                cell.setAttribute('data-day', DAY_LABELS[day]);
                cell.setAttribute('data-hour', String(hour).padStart(2, '0') + ':00');
                cell.setAttribute('data-count', String(count));
                cell.title = DAY_LABELS[day] + ' ' + String(hour).padStart(2, '0') + ':00 — ' + count + ' alerts';
                row.appendChild(cell);
            }
            body.appendChild(row);
        }
    }

    function fetchAndRenderHeatmap(period) {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        var p = period || '30d';
        fetch(apiBase + '/stats/heatmap?period=' + encodeURIComponent(p))
            .then(function (r) { return r.json(); })
            .then(function (resp) {
                if (resp && resp.data) {
                    renderHeatmap(resp.data, resp.max_count || 0);
                }
            })
            .catch(function () { /* non-fatal */ });
    }

    // ── Init statistics page charts ───────────────────────────────────────────
    function initStats() {
        _isLargeDisplay = _evaluateDisplaySize();
        CHART_DEFAULTS = _buildChartDefaults();
        _initHealthGauge('statsHealthGauge', true);
        _initTimelineChart('statsTimelineChart');
        _initCategoryDonut('statsCategoryDonut');
        _initTopDevicesBar('statsTopDevicesChart');

        // Set accessibility attributes on statistics canvases
        _setChartAccessibility('statsHealthGauge');
        _setChartAccessibility('statsTimelineChart');
        _setChartAccessibility('statsCategoryDonut');
        _setChartAccessibility('statsTopDevicesChart');

        // Load initial stats from API
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';

        // Populate incident and device count cells
        _fetchIncidentAndDeviceCounts(apiBase);

        // Render alert heatmap
        fetchAndRenderHeatmap('30d');

        fetch(apiBase + '/stats/daily')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.counts) {
                    _updateStatsCategoryDonut(data.counts);
                    _updateStatsTimeline(data.hourly_buckets);
                    _updateStatsTopDevices(data.per_device);
                    var healthEl = document.getElementById('statsHealthNumber');
                    if (healthEl) {
                        var total = data.total || 0;
                        var score = total === 0 ? 100 : Math.max(0, 100 - Math.floor(data.counts.CRITICAL * 5 + data.counts.WARNING * 1));
                        healthEl.textContent = Math.min(100, score);
                        _updateHealthGauge('statsHealthGauge', Math.min(100, score), 'statsHealthNumber');
                    }
                    // Update summary cells
                    var map = {
                        statsTotalAlerts: data.total || 0,
                        statsCriticalCount: (data.counts && data.counts.CRITICAL) || 0,
                        statsWarningCount:  (data.counts && data.counts.WARNING)  || 0,
                        statsInfoCount:     (data.counts && data.counts.INFO)     || 0,
                    };
                    Object.keys(map).forEach(function (id) {
                        var el = document.getElementById(id);
                        if (el) el.textContent = map[id];
                    });
                }
            })
            .catch(function () { /* non-fatal */ });
    }

    var PERIOD_ENDPOINTS = {
        today: '/stats/daily',
        week:  '/stats/weekly',
        month: '/stats/monthly',
        year:  '/stats/yearly',
    };

    // Map sub-tab periods to heatmap API periods
    var HEATMAP_PERIODS = {
        today: '7d',
        week:  '7d',
        month: '30d',
        year:  '1y',
    };

    function loadPeriod(period) {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        var endpoint = PERIOD_ENDPOINTS[period] || '/stats/daily';
        fetch(apiBase + endpoint)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                // monthly/yearly endpoints return {months|years,...} with no
                // top-level counts/hourly_buckets/per_device, so this guard
                // skips them and the charts retain the prior period's data.
                if (data && data.counts) {
                    _updateStatsCategoryDonut(data.counts);
                    _updateStatsTimeline(data.hourly_buckets);
                    _updateStatsTopDevices(data.per_device);
                }
            })
            .catch(function () { /* non-fatal */ });

        // Refresh heatmap for the selected period
        fetchAndRenderHeatmap(HEATMAP_PERIODS[period] || '30d');

        // Populate incident and device count cells
        _fetchIncidentAndDeviceCounts(apiBase);
    }

    function _fetchIncidentAndDeviceCounts(apiBase) {
        fetch(apiBase + '/incidents')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var el = document.getElementById('statsIncidentCount');
                if (el) {
                    el.textContent = Array.isArray(data) ? data.length : 0;
                }
            })
            .catch(function () { /* non-fatal */ });

        fetch(apiBase + '/devices')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var el = document.getElementById('statsDeviceCount');
                if (el) {
                    el.textContent = Array.isArray(data) ? data.length : 0;
                }
            })
            .catch(function () { /* non-fatal */ });
    }

    // ── Debounced resize handler for breakpoint changes ─────────────────────
    var _resizeTimer = null;
    function _onResize() {
        clearTimeout(_resizeTimer);
        _resizeTimer = setTimeout(function () {
            var newLarge = _evaluateDisplaySize();
            if (newLarge !== _isLargeDisplay) {
                _isLargeDisplay = newLarge;
                CHART_DEFAULTS = _buildChartDefaults();
                if (document.getElementById('healthGaugeChart')) {
                    initDashboard();
                }
                if (document.getElementById('statsHealthGauge')) {
                    initStats();
                }
            }
        }, 300);
    }

    // Auto-init on DOMContentLoaded
    document.addEventListener('DOMContentLoaded', function () {
        if (document.getElementById('healthGaugeChart')) {
            initDashboard();
        }
        if (document.getElementById('statsHealthGauge')) {
            initStats();
        }
        window.addEventListener('resize', _onResize);
    });

    // ── Cleanup on page unload to prevent memory leaks ───────────────────────
    window.addEventListener('beforeunload', function () {
        if (_resizeObserver) {
            _resizeObserver.disconnect();
            _resizeObserver = null;
        }
        // Destroy all Chart.js instances to release canvas memory
        Object.keys(_charts).forEach(function (id) {
            if (_charts[id]) {
                _charts[id].destroy();
            }
        });
        _charts = {};
    });

    // Public API
    window.NetwatchCharts = {
        onAlert: onAlert,
        initDashboard: initDashboard,
        initStats: initStats,
        loadPeriod: loadPeriod,
        updateHealthGauge: _updateHealthGauge,
        renderHeatmap: renderHeatmap,
        fetchAndRenderHeatmap: fetchAndRenderHeatmap,
    };
})();
