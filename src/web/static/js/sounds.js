/**
 * BSCCL NETWATCH — Alert Sound System (Web Audio API)
 *
 * Three alert sounds:
 *   critical  — urgent pulsing alarm (two descending tones)
 *   warning   — short chime (single tone)
 *   recovery  — ascending arpeggio (three rising tones)
 *
 * All tones are synthesised — no audio file downloads required.
 */

(function () {
    'use strict';

    var _ctx = null;          // AudioContext (lazy init)
    var _enabled = true;      // global mute flag
    var _prefs = {
        critical: true,
        warning:  true,
        recovery: true,
    };

    // ── AudioContext init (must be triggered by a user gesture first) ─────────
    function _getCtx() {
        if (_ctx) return _ctx;
        try {
            _ctx = new (window.AudioContext || window.webkitAudioContext)();
        } catch (e) {
            console.warn('[NetwatchSounds] Web Audio API not available');
            _ctx = null;
        }
        return _ctx;
    }

    // ── Low-level tone player ─────────────────────────────────────────────────
    /**
     * Play a tone burst.
     * @param {number} freq   Frequency in Hz
     * @param {number} start  Start time (AudioContext.currentTime offset)
     * @param {number} dur    Duration in seconds
     * @param {string} type   OscillatorType: sine|square|sawtooth|triangle
     * @param {number} gain   Peak gain (0-1)
     */
    function _tone(freq, start, dur, type, gain) {
        var ctx = _getCtx();
        if (!ctx) return;

        var osc = ctx.createOscillator();
        var gainNode = ctx.createGain();

        osc.connect(gainNode);
        gainNode.connect(ctx.destination);

        osc.type = type || 'sine';
        osc.frequency.value = freq;

        var now = ctx.currentTime;
        gainNode.gain.setValueAtTime(0, now + start);
        gainNode.gain.linearRampToValueAtTime(gain || 0.3, now + start + 0.01);
        gainNode.gain.linearRampToValueAtTime(0, now + start + dur);

        osc.start(now + start);
        osc.stop(now + start + dur + 0.05);
    }

    // ── Sound presets ─────────────────────────────────────────────────────────

    /** Critical alarm — two harsh descending tones, repeating twice */
    function _playCritical() {
        // 880 Hz → 660 Hz, two pulses
        _tone(880, 0.00, 0.18, 'sawtooth', 0.35);
        _tone(660, 0.22, 0.18, 'sawtooth', 0.35);
        _tone(880, 0.55, 0.18, 'sawtooth', 0.30);
        _tone(660, 0.77, 0.18, 'sawtooth', 0.30);
    }

    /** Warning chime — single mid-tone sine */
    function _playWarning() {
        _tone(587, 0.00, 0.25, 'sine', 0.25);
        _tone(493, 0.28, 0.15, 'sine', 0.15);
    }

    /** Recovery arpeggio — three rising notes */
    function _playRecovery() {
        _tone(523, 0.00, 0.12, 'sine', 0.20);  // C5
        _tone(659, 0.14, 0.12, 'sine', 0.20);  // E5
        _tone(784, 0.28, 0.20, 'sine', 0.25);  // G5
    }

    // ── Public play dispatcher ────────────────────────────────────────────────
    function play(classification) {
        if (!_enabled) return;
        if (!_getCtx()) return;

        if (_ctx && _ctx.state === 'suspended') {
            _ctx.resume();
        }

        switch (classification) {
            case 'CRITICAL':
                if (_prefs.critical) _playCritical();
                break;
            case 'WARNING':
                if (_prefs.warning) _playWarning();
                break;
            case 'RECOVERY':
                if (_prefs.recovery) _playRecovery();
                break;
            default:
                break;
        }
    }

    // ── Sound toggle button in nav ─────────────────────────────────────────────
    function _initToggleButton() {
        var btn = document.getElementById('soundToggle');
        var icon = document.getElementById('soundIcon');
        if (!btn) return;

        btn.addEventListener('click', function () {
            // Unlock AudioContext on first click (browser policy)
            _getCtx();
            if (_ctx && _ctx.state === 'suspended') {
                _ctx.resume();
            }
            _enabled = !_enabled;
            if (icon) icon.textContent = _enabled ? '🔊' : '🔇';
            btn.title = _enabled ? 'Mute sounds (N)' : 'Unmute sounds (N)';
        });
    }

    // ── Public API ────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', _initToggleButton);

    window.NetwatchSounds = {
        play: play,
        setEnabled: function (val) {
            _enabled = !!val;
            var icon = document.getElementById('soundIcon');
            if (icon) icon.textContent = _enabled ? '🔊' : '🔇';
        },
        isEnabled: function () { return _enabled; },
        testCritical:  function () { _enabled = true; _playCritical(); },
        testWarning:   function () { _enabled = true; _playWarning(); },
        testRecovery:  function () { _enabled = true; _playRecovery(); },
        setPrefs: function (prefs) {
            Object.assign(_prefs, prefs);
        },
    };
})();
