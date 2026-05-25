/**
 * BSCCL NETWATCH — Auto-reconnecting WebSocket client
 *
 * Connects to /ws, exponential back-off on disconnect,
 * fires custom DOM events for dashboard.js to consume.
 */

(function () {
    'use strict';

    var RECONNECT_INITIAL_MS = 1000;
    var RECONNECT_MAX_MS = 30000;
    var RECONNECT_MULTIPLIER = 1.5;
    var HEARTBEAT_CHECK_INTERVAL_MS = 15000;
    var STALE_THRESHOLD_MS = 30000;

    var _ws = null;
    var _reconnectDelay = RECONNECT_INITIAL_MS;
    var _reconnectTimer = null;
    var _intentionalClose = false;
    var _lastMessageTime = Date.now();
    var _heartbeatInterval = null;
    var _reconnectAttempts = 0;

    function _getWsUrl() {
        var cfg = window.NETWATCH_CONFIG || {};
        if (cfg.wsUrl) return cfg.wsUrl;
        var proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        return proto + '//' + window.location.host + '/ws';
    }

    function _setLiveState(connected, statusText) {
        var indicator = document.getElementById('liveIndicator');
        if (!indicator) return;
        var label = indicator.querySelector('.live-label');
        if (connected) {
            indicator.classList.remove('disconnected');
            if (label) label.textContent = 'LIVE';
        } else {
            indicator.classList.add('disconnected');
            if (label && statusText) {
                label.textContent = statusText;
            }
        }
    }

    function _dispatch(type, detail) {
        var evt = new CustomEvent('netwatch:' + type, {
            detail: detail,
            bubbles: true,
        });
        document.dispatchEvent(evt);
    }

    function _startHeartbeatCheck() {
        _stopHeartbeatCheck();
        _heartbeatInterval = setInterval(function () {
            if (
                _ws &&
                _ws.readyState === WebSocket.OPEN &&
                Date.now() - _lastMessageTime > STALE_THRESHOLD_MS
            ) {
                console.warn(
                    '[NetwatchWS] Stale connection detected (' +
                        Math.round((Date.now() - _lastMessageTime) / 1000) +
                        's silence). Forcing reconnect.'
                );
                _ws.close();
            }
        }, HEARTBEAT_CHECK_INTERVAL_MS);
    }

    function _stopHeartbeatCheck() {
        if (_heartbeatInterval) {
            clearInterval(_heartbeatInterval);
            _heartbeatInterval = null;
        }
    }

    function connect() {
        // Connection guard: do not open a duplicate connection
        if (
            _ws &&
            (_ws.readyState === WebSocket.CONNECTING ||
                _ws.readyState === WebSocket.OPEN)
        ) {
            return;
        }

        if (_reconnectTimer) {
            clearTimeout(_reconnectTimer);
            _reconnectTimer = null;
        }

        try {
            _ws = new WebSocket(_getWsUrl());
        } catch (e) {
            console.warn('[NetwatchWS] WebSocket construction failed:', e);
            _reconnectAttempts++;
            var statusText = _reconnectAttempts >= 10
                ? 'Connection lost — check server'
                : _reconnectAttempts >= 3
                    ? 'Disconnected (retrying…)'
                    : 'Reconnecting…';
            _setLiveState(false, statusText);
            _scheduleReconnect();
            return;
        }

        _ws.onopen = function () {
            _reconnectDelay = RECONNECT_INITIAL_MS;
            _reconnectAttempts = 0;
            _lastMessageTime = Date.now();
            _setLiveState(true);
            _startHeartbeatCheck();
            _dispatch('connected', {});
            console.log('[NetwatchWS] Connected');
        };

        _ws.onmessage = function (evt) {
            _lastMessageTime = Date.now();
            var data;
            try {
                data = JSON.parse(evt.data);
            } catch (e) {
                return;
            }
            if (data && data.type === 'alert') {
                _dispatch('alert', data);
            } else if (data && data.type === 'incident') {
                _dispatch('incident', data);
            } else {
                _dispatch('message', data);
            }
        };

        _ws.onclose = function (evt) {
            _stopHeartbeatCheck();
            if (!_intentionalClose) {
                _reconnectAttempts++;
                var statusText = 'Disconnected';
                if (_reconnectAttempts >= 10) {
                    statusText = 'Connection lost — check server';
                } else if (_reconnectAttempts >= 3) {
                    statusText = 'Disconnected (retrying…)';
                } else {
                    statusText = 'Reconnecting…';
                }
                _setLiveState(false, statusText);
                _dispatch('disconnected', {
                    code: evt.code,
                    attempts: _reconnectAttempts,
                });
                _scheduleReconnect();
            } else {
                _setLiveState(false);
                _dispatch('disconnected', { code: evt.code });
            }
        };

        _ws.onerror = function (err) {
            console.warn('[NetwatchWS] WebSocket error', err);
            _dispatch('error', {});
        };
    }

    function _scheduleReconnect() {
        _reconnectTimer = setTimeout(function () {
            console.log('[NetwatchWS] Reconnecting…');
            connect();
        }, _reconnectDelay);
        _reconnectDelay = Math.min(_reconnectDelay * RECONNECT_MULTIPLIER, RECONNECT_MAX_MS);
    }

    function disconnect() {
        _intentionalClose = true;
        _stopHeartbeatCheck();
        if (_ws) {
            _ws.close();
            _ws = null;
        }
    }

    function send(data) {
        if (_ws && _ws.readyState === WebSocket.OPEN) {
            _ws.send(typeof data === 'string' ? data : JSON.stringify(data));
        }
    }

    // Auto-connect on page load
    document.addEventListener('DOMContentLoaded', connect);

    // Public API
    window.NetwatchWS = {
        connect: connect,
        disconnect: disconnect,
        send: send,
    };
})();
