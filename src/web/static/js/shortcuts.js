/**
 * BSCCL NETWATCH — Keyboard Shortcuts
 *
 * Global keyboard shortcuts for NOC operator efficiency.
 *
 * Shortcuts:
 *   1  → CRITICAL tab
 *   2  → WARNING tab
 *   3  → INFO tab
 *   4  → NOISE tab
 *   5  → LOGIN tab
 *   0  → ALL tab
 *   a  → Acknowledge selected/top alert
 *   n  → Toggle mute
 *   /  → Focus search input
 *   Esc → Blur search
 */

(function () {
    'use strict';

    var TAB_KEYS = {
        '0': 'all',
        '1': 'CRITICAL',
        '2': 'WARNING',
        '3': 'INFO',
        '4': 'NOISE',
        '5': 'USER_LOGIN',
    };

    function _isTyping() {
        var active = document.activeElement;
        if (!active) return false;
        var tag = active.tagName.toLowerCase();
        return tag === 'input' || tag === 'textarea' || tag === 'select' || active.isContentEditable;
    }

    document.addEventListener('keydown', function (e) {
        // Don't hijack when user is typing in a form field
        if (_isTyping() && e.key !== 'Escape') return;

        // Tab switching: 0-5
        if (TAB_KEYS[e.key] !== undefined) {
            e.preventDefault();
            if (window.NetwatchDashboard) {
                window.NetwatchDashboard.setTab(TAB_KEYS[e.key]);
            }
            return;
        }

        switch (e.key.toLowerCase()) {
            case 'a':
                e.preventDefault();
                if (e.shiftKey) {
                    // Shift+A: Bulk acknowledge all active incidents
                    if (window.NetwatchDashboard) {
                        window.NetwatchDashboard.bulkAcknowledgeIncidents();
                    }
                } else {
                    // a: Acknowledge top non-acknowledged alert
                    if (window.NetwatchDashboard) {
                        window.NetwatchDashboard.acknowledgeSelected();
                    }
                }
                break;

            case 'n':
                // Toggle sound mute
                e.preventDefault();
                if (window.NetwatchSounds) {
                    var enabled = window.NetwatchSounds.isEnabled();
                    window.NetwatchSounds.setEnabled(!enabled);
                }
                break;

            case '/':
                // Focus search input
                e.preventDefault();
                if (window.NetwatchDashboard) {
                    window.NetwatchDashboard.focusSearch();
                }
                break;

            case 'escape':
                // Blur active element (exit search)
                if (document.activeElement) {
                    document.activeElement.blur();
                }
                break;

            default:
                break;
        }
    });

    // Public API
    window.NetwatchShortcuts = {
        TAB_KEYS: TAB_KEYS,
    };
})();
