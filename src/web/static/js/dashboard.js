/**
 * BSCCL NETWATCH — Dashboard JS
 *
 * Handles: tab switching, alert card rendering, severity counters,
 * filter/search, acknowledge button, incident display.
 */

(function () {
    'use strict';

    // ── State ────────────────────────────────────────────────────────────────
    var _alerts = [];        // all received alerts, newest-first
    var _activeTab = 'all'; // current tab filter
    var _searchQuery = '';  // current search text
    var _counters = {
        CRITICAL: 0,
        WARNING: 0,
        INFO: 0,
        NOISE: 0,
        USER_LOGIN: 0,
    };

    // ── Severity display map ──────────────────────────────────────────────────
    var SEV_LABEL = {
        CRITICAL:   'CRITICAL',
        WARNING:    'WARNING',
        INFO:       'INFO',
        NOISE:      'NOISE',
        USER_LOGIN: 'LOGIN',
    };

    // ── DOM helpers ──────────────────────────────────────────────────────────
    function _el(id) { return document.getElementById(id); }

    function _updateCounters() {
        _el('countCritical') && (_el('countCritical').textContent = _counters.CRITICAL);
        _el('countWarning')  && (_el('countWarning').textContent  = _counters.WARNING);
        _el('countInfo')     && (_el('countInfo').textContent     = _counters.INFO);
        _el('countNoise')    && (_el('countNoise').textContent    = _counters.NOISE);
        _el('countLogin')    && (_el('countLogin').textContent    = _counters.USER_LOGIN);
        var total = Object.values(_counters).reduce(function (a, b) { return a + b; }, 0);
        _el('countTotal') && (_el('countTotal').textContent = total);

        // Tab badges
        _el('tabCountAll')      && (_el('tabCountAll').textContent      = _alerts.length);
        _el('tabCountCritical') && (_el('tabCountCritical').textContent = _counters.CRITICAL);
        _el('tabCountWarning')  && (_el('tabCountWarning').textContent  = _counters.WARNING);
        _el('tabCountInfo')     && (_el('tabCountInfo').textContent     = _counters.INFO);
        _el('tabCountNoise')    && (_el('tabCountNoise').textContent    = _counters.NOISE);
        _el('tabCountLogin')    && (_el('tabCountLogin').textContent    = _counters.USER_LOGIN);

        // Pulse critical card when there are critical alerts
        var critCard = _el('sevCardCritical');
        if (critCard) {
            if (_counters.CRITICAL > 0) {
                critCard.classList.add('has-alerts');
            } else {
                critCard.classList.remove('has-alerts');
            }
        }
    }

    // ── Alert rendering ──────────────────────────────────────────────────────
    function _buildAlertCard(alert) {
        var card = document.createElement('div');
        card.className = 'alert-card sev-' + (alert.classification || 'INFO');
        card.dataset.id = alert.id || '';
        card.dataset.classification = alert.classification || '';

        var sevLabel = SEV_LABEL[alert.classification] || alert.classification || 'INFO';
        var ts = alert.timestamp ? _formatTimestamp(alert.timestamp) : '';
        var mnemonic = alert.mnemonic || '';
        var device = alert.device || '';
        var message = alert.message || '';

        // Build meta tags
        var metaItems = [];
        if (alert.interface_name) {
            metaItems.push('<span class="alert-meta-item">'
                + '<span class="meta-key">iface</span>'
                + '<span class="meta-val">' + _esc(alert.interface_name) + '</span>'
                + '</span>');
        }
        if (alert.bgp_neighbor) {
            metaItems.push('<span class="alert-meta-item">'
                + '<span class="meta-key">nbr</span>'
                + '<span class="meta-val">' + _esc(alert.bgp_neighbor) + '</span>'
                + '</span>');
        }
        if (alert.as_name) {
            metaItems.push('<span class="alert-meta-item">'
                + '<span class="meta-key">AS</span>'
                + '<span class="meta-val">' + _esc(alert.as_name) + '</span>'
                + '</span>');
        }
        if (alert.client_name) {
            metaItems.push('<span class="alert-meta-item">'
                + '<span class="meta-key">client</span>'
                + '<span class="meta-val">' + _esc(alert.client_name) + '</span>'
                + '</span>');
        }
        if (alert.device_location) {
            metaItems.push('<span class="alert-meta-item">'
                + '<span class="meta-key">loc</span>'
                + '<span class="meta-val">' + _esc(alert.device_location) + '</span>'
                + '</span>');
        }

        card.innerHTML = '<div class="alert-header">'
            + '<span class="alert-severity ' + _esc(alert.classification) + '">' + _esc(sevLabel) + '</span>'
            + (device ? '<span class="alert-device">' + _esc(device) + '</span>' : '')
            + (mnemonic ? '<span class="alert-mnemonic">' + _esc(mnemonic) + '</span>' : '')
            + (ts ? '<span class="alert-timestamp">' + _esc(ts) + '</span>' : '')
            + '</div>'
            + '<div class="alert-message">' + _esc(message) + '</div>'
            + (metaItems.length ? '<div class="alert-meta">' + metaItems.join('') + '</div>' : '')
            + '<div class="alert-actions">'
            + '<button class="btn-ack" data-alert-id="' + _esc(alert.id || '') + '">ACK</button>'
            + '</div>';

        // Acknowledge handler
        var ackBtn = card.querySelector('.btn-ack');
        if (ackBtn) {
            ackBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                card.classList.add('acknowledged');
            });
        }

        return card;
    }

    function _esc(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function _formatTimestamp(iso) {
        try {
            var d = new Date(iso);
            var pad = function (n) { return String(n).padStart(2, '0'); };
            return pad((d.getUTCHours() + 6) % 24) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds());
        } catch (e) {
            return iso;
        }
    }

    // ── Filter + render ──────────────────────────────────────────────────────
    function _filteredAlerts() {
        return _alerts.filter(function (a) {
            if (_activeTab !== 'all' && a.classification !== _activeTab) return false;
            if (_searchQuery) {
                var q = _searchQuery.toLowerCase();
                var haystack = [a.device, a.mnemonic, a.message, a.as_name, a.client_name]
                    .filter(Boolean)
                    .join(' ')
                    .toLowerCase();
                if (haystack.indexOf(q) === -1) return false;
            }
            return true;
        });
    }

    function _renderAlerts() {
        var container = _el('alertsContainer');
        var emptyEl = _el('alertsEmpty');
        if (!container) return;

        var filtered = _filteredAlerts();

        // Remove old cards (keep empty-state element)
        var cards = container.querySelectorAll('.alert-card');
        cards.forEach(function (c) { c.remove(); });

        if (filtered.length === 0) {
            if (emptyEl) emptyEl.style.display = '';
            return;
        }

        if (emptyEl) emptyEl.style.display = 'none';

        // Render newest 200 to avoid DOM bloat
        var slice = filtered.slice(0, 200);
        var frag = document.createDocumentFragment();
        slice.forEach(function (alert) {
            frag.appendChild(_buildAlertCard(alert));
        });
        container.insertBefore(frag, container.firstChild);
    }

    // ── Tabs ──────────────────────────────────────────────────────────────────
    function _initTabs() {
        var tabBar = document.querySelector('.tab-bar');
        if (!tabBar) return;

        tabBar.addEventListener('click', function (e) {
            var tab = e.target.closest('[data-tab]');
            if (!tab) return;

            tabBar.querySelectorAll('.tab').forEach(function (t) {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
            });
            tab.classList.add('active');
            tab.setAttribute('aria-selected', 'true');

            _activeTab = tab.dataset.tab;
            _renderAlerts();
        });
    }

    // ── Search ────────────────────────────────────────────────────────────────
    function _initSearch() {
        var searchInput = _el('alertSearch');
        if (!searchInput) return;

        var timer = null;
        searchInput.addEventListener('input', function () {
            clearTimeout(timer);
            timer = setTimeout(function () {
                _searchQuery = searchInput.value.trim();
                _renderAlerts();
            }, 200);
        });
    }

    // ── Clear button ──────────────────────────────────────────────────────────
    function _initClearButton() {
        var btn = _el('clearAlertsBtn');
        if (!btn) return;
        btn.addEventListener('click', function () {
            _alerts = [];
            _counters = { CRITICAL: 0, WARNING: 0, INFO: 0, NOISE: 0, USER_LOGIN: 0 };
            _updateCounters();
            _renderAlerts();
        });
    }

    // ── WebSocket alert events ────────────────────────────────────────────────
    document.addEventListener('netwatch:alert', function (e) {
        var alert = e.detail;
        alert.id = alert.id || ('a-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7));

        _alerts.unshift(alert);
        if (_alerts.length > 2000) _alerts.length = 2000; // cap memory

        var cls = alert.classification;
        if (_counters.hasOwnProperty(cls)) {
            _counters[cls]++;
        }

        _updateCounters();
        _renderAlerts();

        // Notify charts module
        if (window.NetwatchCharts) {
            window.NetwatchCharts.onAlert(alert);
        }

        // Notify sounds module
        if (window.NetwatchSounds) {
            window.NetwatchSounds.play(cls);
        }
    });

    // ── Incidents ─────────────────────────────────────────────────────────────
    function _loadIncidents() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        fetch(apiBase + '/incidents')
            .then(function (r) { return r.json(); })
            .then(function (incidents) {
                _renderIncidents(incidents);
            })
            .catch(function () { /* non-fatal */ });
    }

    function _renderIncidents(incidents) {
        var list = _el('incidentsList');
        var count = _el('incidentCount');
        if (!list) return;

        if (count) count.textContent = incidents.length;

        if (incidents.length === 0) {
            list.innerHTML = '<div class="empty-state">No active incidents</div>';
            return;
        }

        list.innerHTML = incidents.map(function (inc) {
            return '<div class="incident-card">'
                + '<div class="incident-title">' + _esc(inc.title || 'Incident ' + inc.id) + '</div>'
                + '<div class="incident-meta">'
                + (inc.device ? inc.device + ' · ' : '')
                + (inc.started_at ? _formatTimestamp(inc.started_at) : '')
                + '</div>'
                + '</div>';
        }).join('');
    }

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {
        _initTabs();
        _initSearch();
        _initClearButton();
        _updateCounters();
        _renderAlerts();
        _loadIncidents();

        // Refresh incidents every 30 s
        setInterval(_loadIncidents, 30000);
    });

    // Public API for testing and shortcuts
    window.NetwatchDashboard = {
        getAlerts: function () { return _alerts.slice(); },
        getCounters: function () { return Object.assign({}, _counters); },
        setTab: function (tab) {
            var tabEl = document.querySelector('[data-tab="' + tab + '"]');
            if (tabEl) tabEl.click();
        },
        focusSearch: function () {
            var s = _el('alertSearch');
            if (s) s.focus();
        },
        acknowledgeSelected: function () {
            var sel = document.querySelector('.alert-card:not(.acknowledged)');
            if (sel) {
                sel.classList.add('acknowledged');
            }
        },
    };
})();
