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

    var _ws = null;
    var _reconnectDelay = RECONNECT_INITIAL_MS;
    var _reconnectTimer = null;
    var _intentionalClose = false;

    function _getWsUrl() {
        var cfg = window.NETWATCH_CONFIG || {};
        if (cfg.wsUrl) return cfg.wsUrl;
        var proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        return proto + '//' + window.location.host + '/ws';
    }

    function _setLiveState(connected) {
        var indicator = document.getElementById('liveIndicator');
        if (!indicator) return;
        if (connected) {
            indicator.classList.remove('disconnected');
        } else {
            indicator.classList.add('disconnected');
        }
    }

    function _dispatch(type, detail) {
        var evt = new CustomEvent('netwatch:' + type, {
            detail: detail,
            bubbles: true,
        });
        document.dispatchEvent(evt);
    }

    function connect() {
        if (_reconnectTimer) {
            clearTimeout(_reconnectTimer);
            _reconnectTimer = null;
        }

        try {
            _ws = new WebSocket(_getWsUrl());
        } catch (e) {
            console.warn('[NetwatchWS] WebSocket construction failed:', e);
            _scheduleReconnect();
            return;
        }

        _ws.onopen = function () {
            _reconnectDelay = RECONNECT_INITIAL_MS;
            _setLiveState(true);
            _dispatch('connected', {});
            console.log('[NetwatchWS] Connected');
        };

        _ws.onmessage = function (evt) {
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
            _setLiveState(false);
            _dispatch('disconnected', { code: evt.code });
            if (!_intentionalClose) {
                _scheduleReconnect();
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
