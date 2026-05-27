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
    var _ackedIds = {};      // persists ACK state across array replacements
    var _activeTab = 'CRITICAL'; // current tab filter
    var _searchQuery = '';  // current search text
    var _counters = {
        CRITICAL: 0,
        WARNING: 0,
        INFO: 0,
        NOISE: 0,
        USER_LOGIN: 0,
    };

    // Race-condition guard: queue WebSocket alerts while a fetch is in-flight
    var _isFetching = false;
    var _alertQueue = [];

    // Debounce timer for applyFilters
    var _filterTimer = null;

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
        if (alert._acked || _ackedIds[alert.id]) card.classList.add('acknowledged');
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

        // data-severity attribute drives the CSS critical pulse animation
        card.dataset.severity = alert.classification || 'INFO';

        card.innerHTML = '<div class="alert-row">'
            + '<span class="alert-sev-dot"></span>'
            + (ts ? '<span class="alert-timestamp">' + _esc(ts) + '</span>' : '')
            + (device ? '<span class="alert-device">' + _esc(device) + '</span>' : '')
            + (mnemonic ? '<span class="alert-mnemonic">' + _esc(mnemonic) + '</span>' : '')
            + '<span class="alert-message">' + _esc(message) + '</span>'
            + '</div>'
            + '<div class="alert-detail">'
            + '<div class="alert-message-full">' + _esc(message) + '</div>'
            + (metaItems.length ? '<div class="alert-meta">' + metaItems.join('') + '</div>' : '')
            + '</div>'
            + '<div class="alert-actions">'
            + '<button class="btn-ack" data-alert-id="' + _esc(alert.id || '') + '">ACK</button>'
            + '</div>';

        // Expand/collapse on row click
        var row = card.querySelector('.alert-row');
        if (row) {
            row.addEventListener('click', function () {
                card.classList.toggle('expanded');
            });
        }

        // Acknowledge handler — persist in alert data so tab switches preserve state
        var ackBtn = card.querySelector('.btn-ack');
        if (ackBtn) {
            ackBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                alert._acked = true;
                _ackedIds[alert.id] = true;
                card.classList.add('acknowledged');
                card.classList.remove('expanded');
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
            if (isNaN(d.getTime())) { return String(iso); }
            var pad = function (n) { return String(n).padStart(2, '0'); };
            // Convert UTC to BDT (UTC+6)
            var bdtMs = d.getTime() + 6 * 3600 * 1000;
            var b = new Date(bdtMs);
            var year  = b.getUTCFullYear();
            var month = pad(b.getUTCMonth() + 1);
            var day   = pad(b.getUTCDate());
            var hh    = pad(b.getUTCHours());
            var mm    = pad(b.getUTCMinutes());
            var ss    = pad(b.getUTCSeconds());
            return year + '-' + month + '-' + day + ' ' + hh + ':' + mm + ':' + ss + ' BDT';
        } catch (e) {
            return String(iso);
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

        // Remove old cards AND transient loading/error indicators
        var stale = container.querySelectorAll('.alert-card, .loading-state, .error-state');
        stale.forEach(function (c) { c.remove(); });

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

    // ── Clear button (with confirmation + undo) ────────────────────────────────
    var _clearedBackup = null;
    var _undoTimer = null;
    var _undoCountdown = null;

    function _initClearButton() {
        var btn = _el('clearAlertsBtn');
        if (!btn) return;
        btn.addEventListener('click', function () {
            var total = _alerts.length;
            if (total === 0) return;

            if (!confirm('Clear all alerts? This can be undone within 5 seconds.')) return;

            // Stash current state for undo
            _clearedBackup = {
                alerts: _alerts.slice(),
                ackedIds: Object.assign({}, _ackedIds),
                counters: Object.assign({}, _counters),
            };

            // Clear alerts and counters
            _alerts = [];
            _ackedIds = {};
            _counters = { CRITICAL: 0, WARNING: 0, INFO: 0, NOISE: 0, USER_LOGIN: 0 };
            _updateCounters();
            _renderAlerts();

            // Show undo bar
            _showUndoBar(total);
        });
    }

    function _showUndoBar(count) {
        _dismissUndoBar();

        var UNDO_SECONDS = 5;
        var remaining = UNDO_SECONDS;

        var bar = document.createElement('div');
        bar.id = 'clearUndoBar';
        bar.className = 'clear-undo-bar';

        var msgSpan = document.createElement('span');
        msgSpan.className = 'undo-message';
        msgSpan.textContent = 'Cleared ' + count + ' alert' + (count !== 1 ? 's' : '');

        var undoBtn = document.createElement('button');
        undoBtn.className = 'btn-undo';
        undoBtn.textContent = 'UNDO';

        var timerSpan = document.createElement('span');
        timerSpan.className = 'undo-timer';
        timerSpan.textContent = '(' + remaining + 's)';

        bar.appendChild(msgSpan);
        bar.appendChild(undoBtn);
        bar.appendChild(timerSpan);

        // Insert at the top of the alert stream container
        var container = _el('alertsContainer');
        if (container) {
            container.insertBefore(bar, container.firstChild);
        } else {
            document.body.appendChild(bar);
        }

        // Countdown timer
        _undoCountdown = setInterval(function () {
            remaining--;
            if (remaining <= 0) {
                _expireUndo();
            } else {
                timerSpan.textContent = '(' + remaining + 's)';
            }
        }, 1000);

        // Expiry timeout (authoritative — ensures cleanup even if interval drifts)
        _undoTimer = setTimeout(function () {
            _expireUndo();
        }, UNDO_SECONDS * 1000 + 100);

        // UNDO click handler
        undoBtn.addEventListener('click', function () {
            if (!_clearedBackup) return;
            _alerts = _clearedBackup.alerts;
            _ackedIds = _clearedBackup.ackedIds;
            _counters = _clearedBackup.counters;
            _clearedBackup = null;
            _updateCounters();
            _renderAlerts();
            _dismissUndoBar();
            _showToast('Alerts restored');
        });
    }

    function _expireUndo() {
        _clearedBackup = null;
        _dismissUndoBar();
    }

    function _dismissUndoBar() {
        clearTimeout(_undoTimer);
        _undoTimer = null;
        clearInterval(_undoCountdown);
        _undoCountdown = null;
        var bar = document.getElementById('clearUndoBar');
        if (bar) bar.remove();
    }

    // ── Client-side dedup (safety net) ──────────────────────────────────────
    var _recentKeys = {};
    var _DEDUP_WINDOW_MS = 300000; // 5 minutes

    // Prune expired dedup entries every 60 s to prevent unbounded growth
    setInterval(function () {
        var now = Date.now();
        Object.keys(_recentKeys).forEach(function (k) {
            if (now - _recentKeys[k] > _DEDUP_WINDOW_MS) {
                delete _recentKeys[k];
            }
        });
    }, 60000);

    function _isDuplicate(alert) {
        var key = (alert.device || '') + ':' + (alert.mnemonic || '') + ':'
                + (alert.neighbor || alert.interface || '');
        var now = Date.now();
        if (_recentKeys[key] && (now - _recentKeys[key]) < _DEDUP_WINDOW_MS) {
            return true;
        }
        _recentKeys[key] = now;
        return false;
    }

    // ── WebSocket alert events ────────────────────────────────────────────────
    document.addEventListener('netwatch:alert', function (e) {
        var alert = e.detail;
        if (_isDuplicate(alert)) return;

        alert.id = alert.id || ('a-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7));

        // If a fetch is in-flight, queue the alert to avoid race conditions
        // where the fetch response would overwrite this live alert.
        if (_isFetching) {
            _alertQueue.push(alert);
        } else {
            _alerts.unshift(alert);
            if (_alerts.length > 2000) _alerts.length = 2000; // cap memory
        }

        var cls = alert.classification;
        if (_counters.hasOwnProperty(cls)) {
            _counters[cls]++;
        }

        _updateCounters();

        // Only re-render if we actually inserted into _alerts (not queued)
        if (!_isFetching) {
            _renderAlerts();
        }

        // Notify charts module
        if (window.NetwatchCharts) {
            window.NetwatchCharts.onAlert(alert);
        }

        // Notify sounds module
        if (window.NetwatchSounds) {
            window.NetwatchSounds.play(cls);
        }
    });

    // ── Time filter / DB fetch ────────────────────────────────────────────────

    /**
     * Drain queued WebSocket alerts into the main _alerts array.
     * Called after a fetch completes (success or failure) to ensure
     * live alerts that arrived during the fetch are not lost.
     */
    function _drainAlertQueue() {
        while (_alertQueue.length) {
            _alerts.unshift(_alertQueue.shift());
        }
        if (_alerts.length > 2000) _alerts.length = 2000;
    }

    /**
     * Internal implementation: fetch historical alerts from the DB for the
     * selected period and render them.  Also refreshes severity counters
     * via /api/alerts/count.
     *
     * Called on page load and whenever the period selector changes.
     * New real-time alerts from the WebSocket are prepended on top.
     */
    function _applyFiltersImpl() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        var periodEl = document.getElementById('periodFilter');
        var period = periodEl ? periodEl.value : 'today';

        var container = _el('alertsContainer');

        // Show loading indicator (preserves #alertsEmpty element)
        if (container) {
            var _old = container.querySelectorAll('.alert-card, .loading-state, .error-state');
            _old.forEach(function (c) { c.remove(); });
            var _ld = document.createElement('div');
            _ld.className = 'loading-state';
            _ld.style.cssText = 'display:flex;align-items:center;justify-content:center;'
                + 'padding:1.25rem 1rem;color:#b0b0c8;'
                + 'font-family:var(--font-mono,monospace);font-size:0.78rem;';
            _ld.textContent = 'Loading...';
            container.insertBefore(_ld, container.firstChild);
        }

        _isFetching = true;

        // Fetch paginated alerts
        fetch(apiBase + '/alerts?period=' + encodeURIComponent(period) + '&limit=500')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                // Merge DB results with any live WebSocket alerts received
                // during the fetch.  Keep live alerts whose id is not already
                // in the DB result set, then prepend them.
                var dbAlerts = Array.isArray(data) ? data : [];
                var dbIds = {};
                dbAlerts.forEach(function (a) { if (a.id) dbIds[a.id] = true; });
                var liveOnly = _alerts.filter(function (a) {
                    return a.id && !dbIds[a.id];
                });
                _alerts = liveOnly.concat(dbAlerts);

                // Drain any WebSocket alerts that arrived during the fetch
                _drainAlertQueue();
                _isFetching = false;

                _renderAlerts();
            })
            .catch(function (err) {
                console.error('[NetWatch] Failed to fetch alerts:', err);
                _drainAlertQueue();
                _isFetching = false;

                _renderAlerts();

                // Append error indicator after render (preserves #alertsEmpty)
                if (container) {
                    var _err = document.createElement('div');
                    _err.className = 'error-state';
                    _err.style.cssText = 'display:flex;align-items:center;justify-content:center;'
                        + 'padding:1.25rem 1rem;color:#ff0040;'
                        + 'font-family:var(--font-mono,monospace);font-size:0.78rem;';
                    _err.textContent = 'Failed to load. Retrying...';
                    container.appendChild(_err);
                }
            });

        // Also refresh counts badge via dedicated endpoint
        fetch(apiBase + '/alerts/count?period=' + encodeURIComponent(period))
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data && data.counts) {
                    Object.keys(data.counts).forEach(function (cls) {
                        if (_counters.hasOwnProperty(cls)) {
                            _counters[cls] = data.counts[cls];
                        }
                    });
                    _updateCounters();
                }
            })
            .catch(function (err) {
                console.error('[NetWatch] Failed to fetch alert counts:', err);
            });
    }

    /**
     * Debounced public entry point for applyFilters.
     * Prevents rapid clicks on period filter from flooding the server.
     */
    function applyFilters() {
        clearTimeout(_filterTimer);
        _filterTimer = setTimeout(function () {
            _applyFiltersImpl();
        }, 300);
    }

    // Expose for the inline onchange attribute on the <select>
    window.applyFilters = applyFilters;

    // ── Incidents ─────────────────────────────────────────────────────────────
    function _loadIncidents() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        var list = _el('incidentsList');

        // Show loading indicator while fetching
        if (list) {
            list.innerHTML = '<div class="loading-state" style="'
                + 'display:flex;align-items:center;justify-content:center;'
                + 'padding:1.25rem 1rem;color:#b0b0c8;'
                + 'font-family:var(--font-mono,monospace);font-size:0.78rem;'
                + '">Loading...</div>';
        }

        fetch(apiBase + '/incidents')
            .then(function (r) { return r.json(); })
            .then(function (incidents) {
                _renderIncidents(incidents);
            })
            .catch(function (err) {
                console.error('[NetWatch] Failed to fetch incidents:', err);
                if (list) {
                    list.innerHTML = '<div class="error-state" style="'
                        + 'display:flex;align-items:center;justify-content:center;'
                        + 'padding:1.25rem 1rem;color:#ff0040;'
                        + 'font-family:var(--font-mono,monospace);font-size:0.78rem;'
                        + '">Failed to load. Retrying...</div>';
                }
            });
    }

    // ── Incident Alarm System (only for unacked active incidents) ─────────
    var _incidentAlarmInterval = null;
    var _incidentAlarmActive = false;
    var _repeatAlarmEnabled = localStorage.getItem('netwatch_repeat_alarm') !== 'false';

    function _startIncidentAlarm() {
        if (_incidentAlarmActive) return;
        _incidentAlarmActive = true;
        document.body.classList.add('has-active-incidents');
        // Play immediately on first detection (always)
        if (window.NetwatchSounds && window.NetwatchSounds.isEnabled()) {
            window.NetwatchSounds.play('CRITICAL');
        }
        // Repeat every 30 seconds only if repeat is enabled
        if (_repeatAlarmEnabled) {
            _incidentAlarmInterval = setInterval(function () {
                if (window.NetwatchSounds && window.NetwatchSounds.isEnabled()) {
                    window.NetwatchSounds.play('CRITICAL');
                }
            }, 30000);
        }
    }

    function _stopIncidentAlarm() {
        if (!_incidentAlarmActive) return;
        _incidentAlarmActive = false;
        document.body.classList.remove('has-active-incidents');
        if (_incidentAlarmInterval) {
            clearInterval(_incidentAlarmInterval);
            _incidentAlarmInterval = null;
        }
    }

    function _setRepeatAlarm(enabled) {
        _repeatAlarmEnabled = enabled;
        localStorage.setItem('netwatch_repeat_alarm', enabled ? 'true' : 'false');
        if (_incidentAlarmActive) {
            if (enabled && !_incidentAlarmInterval) {
                _incidentAlarmInterval = setInterval(function () {
                    if (window.NetwatchSounds && window.NetwatchSounds.isEnabled()) {
                        window.NetwatchSounds.play('CRITICAL');
                    }
                }, 30000);
            } else if (!enabled && _incidentAlarmInterval) {
                clearInterval(_incidentAlarmInterval);
                _incidentAlarmInterval = null;
            }
        }
    }

    // ── ACK Modal ────────────────────────────────────────────────────────
    function _showAckModal(incidentId) {
        // Remove existing modal if any
        var old = document.getElementById('ackModal');
        if (old) old.remove();

        var modal = document.createElement('div');
        modal.id = 'ackModal';
        modal.className = 'modal-overlay';
        modal.innerHTML = '<div class="modal-content">'
            + '<div class="modal-header">Acknowledge Incident</div>'
            + '<div class="modal-body">'
            + '<label class="modal-label" for="ackOperator">Operator Name *</label>'
            + '<input type="text" id="ackOperator" class="modal-input" placeholder="Your name" maxlength="64">'
            + '<label class="modal-label" for="ackComment">Comment *</label>'
            + '<textarea id="ackComment" class="modal-textarea" placeholder="investigating / vendor ticket #XYZ / false positive" maxlength="1000" rows="3"></textarea>'
            + '</div>'
            + '<div class="modal-footer">'
            + '<button class="btn-cancel" id="ackCancel">Cancel</button>'
            + '<button class="btn-confirm" id="ackConfirm">Acknowledge</button>'
            + '</div>'
            + '</div>';
        document.body.appendChild(modal);

        var operatorInput = document.getElementById('ackOperator');
        var commentInput = document.getElementById('ackComment');
        operatorInput.focus();

        document.getElementById('ackCancel').addEventListener('click', function () {
            modal.remove();
        });
        modal.addEventListener('click', function (e) {
            if (e.target === modal) modal.remove();
        });
        document.getElementById('ackConfirm').addEventListener('click', function () {
            var name = operatorInput.value.trim();
            var comment = commentInput.value.trim();
            if (!name || !comment) {
                operatorInput.style.borderColor = name ? '' : 'var(--neon-red)';
                commentInput.style.borderColor = comment ? '' : 'var(--neon-red)';
                return;
            }
            _doAcknowledge(incidentId, name, comment);
            modal.remove();
        });
        // Enter key submits
        commentInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' && e.ctrlKey) {
                document.getElementById('ackConfirm').click();
            }
        });
    }

    function _doAcknowledge(incidentId, operatorName, comment) {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';

        // Optimistic UI update: immediately mark as acknowledged locally
        var card = document.querySelector('[data-incident-id="' + incidentId + '"]');
        if (card) {
            card.classList.remove('incident-unacked');
            card.classList.add('incident-acked');
            var ackBtn = card.querySelector('.btn-ack-incident');
            if (ackBtn) ackBtn.remove();
        }

        // Check if all incidents are now acked → stop alarm
        var remaining = document.querySelectorAll('.incident-card.incident-unacked');
        if (remaining.length === 0) {
            _stopIncidentAlarm();
        }

        fetch(apiBase + '/incidents/' + encodeURIComponent(incidentId) + '/acknowledge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ operator_name: operatorName, comment: comment }),
        })
            .then(function (r) {
                if (!r.ok) {
                    throw new Error('Server returned ' + r.status);
                }
                return r.json();
            })
            .then(function () {
                _loadIncidents();
            })
            .catch(function (err) {
                console.error('[NetWatch] ACK failed:', err);
                // Revert optimistic update on failure
                _loadIncidents();
            });
    }

    function _showBulkAckModal(cards) {
        var ids = [];
        cards.forEach(function (c) { ids.push(c.dataset.incidentId); });

        var old = document.getElementById('ackModal');
        if (old) old.remove();

        var modal = document.createElement('div');
        modal.id = 'ackModal';
        modal.className = 'modal-overlay';
        modal.innerHTML = '<div class="modal-content">'
            + '<div class="modal-header">Bulk Acknowledge (' + ids.length + ' incidents)</div>'
            + '<div class="modal-body">'
            + '<label class="modal-label" for="ackOperator">Operator Name *</label>'
            + '<input type="text" id="ackOperator" class="modal-input" placeholder="Your name" maxlength="64">'
            + '<label class="modal-label" for="ackComment">Comment *</label>'
            + '<textarea id="ackComment" class="modal-textarea" placeholder="investigating / vendor ticket #XYZ / false positive" maxlength="1000" rows="3"></textarea>'
            + '</div>'
            + '<div class="modal-footer">'
            + '<button class="btn-cancel" id="ackCancel">Cancel</button>'
            + '<button class="btn-confirm" id="ackConfirm">Acknowledge All</button>'
            + '</div>'
            + '</div>';
        document.body.appendChild(modal);

        document.getElementById('ackOperator').focus();

        document.getElementById('ackCancel').addEventListener('click', function () {
            modal.remove();
        });
        modal.addEventListener('click', function (e) {
            if (e.target === modal) modal.remove();
        });
        document.getElementById('ackConfirm').addEventListener('click', function () {
            var name = document.getElementById('ackOperator').value.trim();
            var comment = document.getElementById('ackComment').value.trim();
            if (!name || !comment) return;
            ids.forEach(function (id) { _doAcknowledge(id, name, comment); });
            modal.remove();
        });
    }

    function _renderIncidents(incidents) {
        var list = _el('incidentsList');
        var count = _el('incidentCount');
        if (!list) return;

        if (count) count.textContent = incidents.length;

        if (incidents.length === 0) {
            list.innerHTML = '<div class="empty-state">No active incidents</div>';
            // Stop incident alarm when no active unacked incidents
            _stopIncidentAlarm();
            return;
        }

        var hasUnacked = false;
        list.innerHTML = incidents.map(function (inc) {
            var isAcked = inc.acknowledged;
            if (!isAcked) hasUnacked = true;
            var ackInfo = '';
            if (isAcked) {
                ackInfo = '<div class="incident-ack-info">'
                    + '<span class="ack-badge">ACK</span> '
                    + '<span class="ack-by">' + _esc(inc.acknowledged_by || '') + '</span>'
                    + (inc.ack_comment ? ' — ' + _esc(inc.ack_comment) : '')
                    + (inc.acknowledged_at ? '<br><span class="ack-time">' + _esc(_formatTimestamp(inc.acknowledged_at)) + '</span>' : '')
                    + '</div>';
            }
            return '<div class="incident-card' + (isAcked ? ' incident-acked' : ' incident-unacked') + '" data-incident-id="' + _esc(inc.id || '') + '">'
                + '<div class="incident-header">'
                + '<div class="incident-title">' + _esc(inc.title || 'Incident ' + inc.id) + '</div>'
                + (!isAcked ? '<button class="btn-ack-incident" data-incident-id="' + _esc(inc.id || '') + '" title="Acknowledge this incident">ACK</button>' : '')
                + '</div>'
                + '<div class="incident-meta">'
                + (inc.device ? _esc(inc.device) + ' · ' : '')
                + (inc.started_at ? _esc(_formatTimestamp(inc.started_at)) : '')
                + '</div>'
                + (inc.client ? '<div class="incident-client">' + _esc(inc.client) + '</div>' : '')
                + ackInfo
                + '</div>';
        }).join('');

        // Handle incident alarm sound
        if (hasUnacked) {
            _startIncidentAlarm();
        } else {
            _stopIncidentAlarm();
        }

        // Bind ACK buttons
        list.querySelectorAll('.btn-ack-incident').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var incId = btn.dataset.incidentId;
                _showAckModal(incId);
            });
        });
    }

    function _loadShiftInfo() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        fetch(apiBase + '/shift/current')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                var nameEl = _el('shiftName');
                var timeEl = _el('shiftTime');
                var critEl = _el('shiftCritical');
                var warnEl = _el('shiftWarning');
                var incEl = _el('shiftIncidents');
                if (nameEl) nameEl.textContent = (data.shift_name || '').toUpperCase() + ' SHIFT';
                if (timeEl) timeEl.textContent = 'Since ' + _formatTimestamp(data.shift_start);
                if (critEl) critEl.textContent = (data.critical_since_shift || 0) + ' CRITICAL';
                if (warnEl) warnEl.textContent = (data.warning_since_shift || 0) + ' WARNING';
                if (incEl) incEl.textContent = (data.open_incidents || 0) + ' OPEN';
            })
            .catch(function () {});
    }

    // ── Handoff Display + Modal ─────────────────────────────────────────────
    function _loadHandoffNotes() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        var panel = _el('handoffPanel');
        var display = _el('handoffDisplay');
        if (!panel || !display) return;

        fetch(apiBase + '/shift/handoffs?limit=3')
            .then(function (r) { return r.json(); })
            .then(function (handoffs) {
                if (!handoffs || handoffs.length === 0) {
                    panel.style.display = 'none';
                    return;
                }
                panel.style.display = '';
                display.innerHTML = handoffs.map(function (h) {
                    return '<div class="handoff-note">'
                        + '<div class="handoff-meta">'
                        + '<span class="handoff-operator">' + _esc(h.operator_name || '') + '</span>'
                        + '<span class="handoff-shift">' + _esc(h.shift_name || '').toUpperCase() + '</span>'
                        + '<span class="handoff-date">' + _esc(h.shift_date || '') + '</span>'
                        + (h.critical_count ? '<span class="handoff-stat critical">' + h.critical_count + ' CRIT</span>' : '')
                        + (h.open_incidents ? '<span class="handoff-stat incidents">' + h.open_incidents + ' OPEN</span>' : '')
                        + '</div>'
                        + (h.notes ? '<div class="handoff-text">' + _esc(h.notes) + '</div>' : '')
                        + '</div>';
                }).join('');
            })
            .catch(function () { panel.style.display = 'none'; });
    }

    function _showHandoffModal() {
        var old = document.getElementById('ackModal');
        if (old) old.remove();

        var today = new Date();
        var bdtMs = today.getTime() + 6 * 3600 * 1000;
        var bdt = new Date(bdtMs);
        var dateStr = bdt.getUTCFullYear() + '-'
            + String(bdt.getUTCMonth() + 1).padStart(2, '0') + '-'
            + String(bdt.getUTCDate()).padStart(2, '0');

        var shiftName = (_el('shiftName') || {}).textContent || '';
        shiftName = shiftName.replace(' SHIFT', '').toLowerCase() || 'morning';

        var modal = document.createElement('div');
        modal.id = 'ackModal';
        modal.className = 'modal-overlay';
        modal.innerHTML = '<div class="modal-content">'
            + '<div class="modal-header">Shift Handoff Note</div>'
            + '<div class="modal-body">'
            + '<label class="modal-label" for="handoffOperator">Operator Name *</label>'
            + '<input type="text" id="handoffOperator" class="modal-input" placeholder="Your name" maxlength="64">'
            + '<label class="modal-label" for="handoffNotes">Notes for next shift</label>'
            + '<textarea id="handoffNotes" class="modal-textarea" placeholder="Ongoing issues, pending actions..." maxlength="2000" rows="5"></textarea>'
            + '</div>'
            + '<div class="modal-footer">'
            + '<button class="btn-cancel" id="handoffCancel">Cancel</button>'
            + '<button class="btn-confirm" id="handoffConfirm">Submit Handoff</button>'
            + '</div>'
            + '</div>';
        document.body.appendChild(modal);

        document.getElementById('handoffOperator').focus();

        document.getElementById('handoffCancel').addEventListener('click', function () {
            modal.remove();
        });
        modal.addEventListener('click', function (e) {
            if (e.target === modal) modal.remove();
        });
        document.getElementById('handoffConfirm').addEventListener('click', function () {
            var name = document.getElementById('handoffOperator').value.trim();
            if (!name) {
                document.getElementById('handoffOperator').style.borderColor = 'var(--neon-red)';
                return;
            }
            var notes = document.getElementById('handoffNotes').value.trim();
            var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
            var confirmBtn = document.getElementById('handoffConfirm');
            confirmBtn.textContent = 'Saving...';
            confirmBtn.disabled = true;

            fetch(apiBase + '/shift/handoff', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    shift_name: shiftName,
                    shift_date: dateStr,
                    operator_name: name,
                    notes: notes,
                    open_incidents: parseInt((_el('shiftIncidents') || {}).textContent) || 0,
                    critical_count: parseInt((_el('shiftCritical') || {}).textContent) || 0,
                    warning_count: parseInt((_el('shiftWarning') || {}).textContent) || 0,
                }),
            })
                .then(function (r) {
                    if (!r.ok) throw new Error('Server returned ' + r.status);
                    return r.json();
                })
                .then(function () {
                    modal.remove();
                    _loadHandoffNotes();
                    _showToast('Handoff note saved successfully');
                })
                .catch(function (err) {
                    console.error('[NetWatch] Handoff failed:', err);
                    confirmBtn.textContent = 'Submit Handoff';
                    confirmBtn.disabled = false;
                    _showToast('Handoff save failed — check connection', true);
                });
        });
    }

    function _showToast(message, isError) {
        var existing = document.querySelector('.netwatch-toast');
        if (existing) existing.remove();
        var toast = document.createElement('div');
        toast.className = 'netwatch-toast' + (isError ? ' toast-error' : '');
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(function () { toast.remove(); }, 3000);
    }

    // ── Topology node click → populate search ──────────────────────────────
    document.addEventListener('netwatch:filter-device', function (e) {
        var device = e.detail && e.detail.device;
        if (!device) return;
        var searchInput = _el('alertSearch');
        if (searchInput) {
            searchInput.value = device;
            _searchQuery = device;
            _renderAlerts();
            searchInput.focus();
        }
    });

    // ── Init ──────────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {
        _initTabs();
        _initSearch();
        _initClearButton();
        _updateCounters();
        _renderAlerts();
        _loadIncidents();

        // Load historical alerts from DB for today on initial page load
        applyFilters();

        // Refresh incidents every 30 s
        setInterval(_loadIncidents, 30000);

        _loadShiftInfo();
        _loadHandoffNotes();
        setInterval(_loadShiftInfo, 60000);

        var handoffBtn = _el('btnHandoff');
        if (handoffBtn) {
            handoffBtn.addEventListener('click', function () {
                _showHandoffModal();
            });
        }
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
                var alertId = sel.dataset.id;
                if (alertId) {
                    _ackedIds[alertId] = true;
                    // Also set _acked on the in-memory alert object
                    for (var i = 0; i < _alerts.length; i++) {
                        if (_alerts[i].id === alertId) {
                            _alerts[i]._acked = true;
                            break;
                        }
                    }
                }
            }
        },
        bulkAcknowledgeIncidents: function () {
            var unacked = document.querySelectorAll('.incident-card.incident-unacked');
            if (unacked.length === 0) return;
            var count = unacked.length;
            if (!confirm('Acknowledge all ' + count + ' active incidents?')) return;
            _showBulkAckModal(unacked);
        },
        setRepeatAlarm: function (enabled) { _setRepeatAlarm(enabled); },
        isRepeatAlarmEnabled: function () { return _repeatAlarmEnabled; },
    };
})();
