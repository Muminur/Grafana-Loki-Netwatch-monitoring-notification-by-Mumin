/**
 * BSCCL NETWATCH — SVG Network Topology Renderer
 *
 * Fetches /api/topology and renders an interactive SVG showing:
 *   Level 0: Singapore Equinix (EQ-RTR)
 *   Level 1: Kuakata (KKT-Core)
 *   Level 2: Dhaka (DHK-Core) + Cox's Bazar (COX-Core)
 */

(function () {
    'use strict';

    // Neon colours matching CSS theme
    var STATUS_COLORS = {
        ok:      '#00ff88',
        warning: '#ffdd00',
        critical:'#ff0040',
        unknown: '#446688',
    };

    var NODE_RADIUS = 22;
    var SVG_NS = 'http://www.w3.org/2000/svg';
    var _resizeObserver = null;   // ResizeObserver — cleaned up on unload
    var _lastClickTime = 0;       // Debounce guard for node click handler

    // Level x-position presets (0=top, 1=mid, 2=bottom in vertical layout)
    var LEVEL_Y = { 0: 50, 1: 140, 2: 230 };

    // ── SVG helpers ───────────────────────────────────────────────────────────
    function _svgEl(tag, attrs) {
        var el = document.createElementNS(SVG_NS, tag);
        Object.keys(attrs).forEach(function (k) { el.setAttribute(k, attrs[k]); });
        return el;
    }

    // ── Layout calculation ────────────────────────────────────────────────────
    function _layoutNodes(nodes) {
        var byLevel = { 0: [], 1: [], 2: [] };
        nodes.forEach(function (n) {
            var lvl = n.level != null ? n.level : 2;
            if (!byLevel[lvl]) byLevel[lvl] = [];
            byLevel[lvl].push(n);
        });

        var svgEl = document.getElementById('topologySvg');
        var svgWidth = svgEl ? (svgEl.viewBox.baseVal.width || 900) : 900;
        var positions = {};

        [0, 1, 2].forEach(function (lvl) {
            var group = byLevel[lvl] || [];
            var count = group.length;
            group.forEach(function (node, i) {
                var x = count === 1
                    ? svgWidth / 2
                    : 60 + (i * (svgWidth - 120) / Math.max(count - 1, 1));
                positions[node.id] = { x: Math.round(x), y: LEVEL_Y[lvl] || 200 };
            });
        });

        return positions;
    }

    // ── Render ────────────────────────────────────────────────────────────────
    function render(topology) {
        var svg = document.getElementById('topologySvg');
        if (!svg) return;

        // Clear existing content
        while (svg.firstChild) svg.removeChild(svg.firstChild);

        var nodes = topology.nodes || [];
        var links = topology.links || [];

        if (nodes.length === 0) {
            var msg = _svgEl('text', {
                x: 300, y: 140, 'text-anchor': 'middle',
                fill: '#8888a0', 'font-family': 'JetBrains Mono', 'font-size': 12,
            });
            msg.textContent = 'No topology data';
            svg.appendChild(msg);
            return;
        }

        var positions = _layoutNodes(nodes);

        // ── Draw links first (below nodes) ────────────────────────────────────
        var linkGroup = _svgEl('g', { class: 'topo-links' });
        links.forEach(function (link) {
            var src = positions[link.source];
            var tgt = positions[link.target];
            if (!src || !tgt) return;

            var g = _svgEl('g', { class: 'topo-link' });

            var line = _svgEl('line', {
                x1: src.x, y1: src.y,
                x2: tgt.x, y2: tgt.y,
                stroke: STATUS_COLORS[link.status] || STATUS_COLORS.unknown,
                'stroke-width': 2,
                'stroke-dasharray': link.status === 'critical' ? '6,3' : 'none',
                opacity: 0.7,
            });
            g.appendChild(line);

            // Bundle label mid-link
            if (link.bundle) {
                var midX = Math.round((src.x + tgt.x) / 2);
                var midY = Math.round((src.y + tgt.y) / 2) - 6;
                var lbl = _svgEl('text', {
                    x: midX, y: midY,
                    'text-anchor': 'middle',
                    fill: '#555570',
                    'font-family': 'JetBrains Mono',
                    'font-size': 8,
                });
                lbl.textContent = link.bundle;
                g.appendChild(lbl);
            }

            linkGroup.appendChild(g);
        });
        svg.appendChild(linkGroup);

        // ── Draw nodes ────────────────────────────────────────────────────────
        var nodeGroup = _svgEl('g', { class: 'topo-nodes' });
        nodes.forEach(function (node) {
            var pos = positions[node.id];
            if (!pos) return;

            var color = STATUS_COLORS[node.status] || STATUS_COLORS.unknown;
            var g = _svgEl('g', {
                class: 'topo-node',
                transform: 'translate(' + pos.x + ',' + pos.y + ')',
                'data-id': node.id,
            });

            // Outer glow ring
            var glow = _svgEl('circle', {
                r: NODE_RADIUS + 4,
                fill: 'none',
                stroke: color,
                'stroke-width': 1,
                opacity: 0.25,
            });
            g.appendChild(glow);

            // Main circle
            var circle = _svgEl('circle', {
                r: NODE_RADIUS,
                fill: 'rgba(13,13,26,0.9)',
                stroke: color,
                'stroke-width': 2,
            });
            g.appendChild(circle);

            // Node name (split on dash to keep compact)
            var parts = node.name.split('-');
            if (parts.length > 2) {
                var line1 = _svgEl('text', {
                    y: -5,
                    'text-anchor': 'middle',
                    fill: '#e8e8f0',
                    'font-family': 'Orbitron, sans-serif',
                    'font-size': 7,
                    'font-weight': '600',
                });
                line1.textContent = parts.slice(0, -1).join('-');
                g.appendChild(line1);

                var line2 = _svgEl('text', {
                    y: 7,
                    'text-anchor': 'middle',
                    fill: color,
                    'font-family': 'Orbitron, sans-serif',
                    'font-size': 7,
                    'font-weight': '400',
                });
                line2.textContent = parts[parts.length - 1];
                g.appendChild(line2);
            } else {
                var lbl = _svgEl('text', {
                    y: 4,
                    'text-anchor': 'middle',
                    fill: '#e8e8f0',
                    'font-family': 'Orbitron, sans-serif',
                    'font-size': 8,
                    'font-weight': '600',
                });
                lbl.textContent = node.name;
                g.appendChild(lbl);
            }

            // Location below node
            var loc = _svgEl('text', {
                y: NODE_RADIUS + 14,
                'text-anchor': 'middle',
                fill: '#555570',
                'font-family': 'JetBrains Mono',
                'font-size': 7,
            });
            loc.textContent = node.location || '';
            g.appendChild(loc);

            // Status dot
            var dot = _svgEl('circle', {
                cx: NODE_RADIUS - 4, cy: -(NODE_RADIUS - 4),
                r: 4,
                fill: color,
            });
            g.appendChild(dot);

            // Tooltip title
            var title = _svgEl('title', {});
            title.textContent = node.name + ' (' + (node.location || '') + ') — ' + (node.status || 'unknown');
            g.appendChild(title);

            // Click handler — dispatch detail + filter events (debounced)
            g.style.cursor = 'pointer';
            g.addEventListener('click', (function (nodeData) {
                return function () {
                    var now = Date.now();
                    if (now - _lastClickTime < 500) return; // Debounce 500ms
                    _lastClickTime = now;

                    // Dispatch device-detail event with full node metadata
                    try {
                        document.dispatchEvent(new CustomEvent('netwatch:device-detail', {
                            detail: {
                                device: nodeData.name,
                                location: nodeData.location || '',
                                platform: nodeData.platform || '',
                                ip: nodeData.ip || '',
                                status: nodeData.status || 'unknown',
                            },
                        }));
                    } catch (e) {
                        // CustomEvent not supported — fall through to filter
                    }

                    try {
                        document.dispatchEvent(new CustomEvent('netwatch:filter-device', {
                            detail: { device: nodeData.name },
                        }));
                    } catch (e) {
                        // IE fallback — not expected but safe
                    }
                    window.location.hash = '#device=' + encodeURIComponent(nodeData.name);
                };
            })(node));

            nodeGroup.appendChild(g);
        });
        svg.appendChild(nodeGroup);
    }

    // ── Load from API and render ──────────────────────────────────────────────
    function load() {
        var apiBase = (window.NETWATCH_CONFIG || {}).apiBase || '/api';
        fetch(apiBase + '/topology')
            .then(function (r) { return r.json(); })
            .then(function (data) { render(data); })
            .catch(function (err) {
                console.warn('[NetwatchTopology] Failed to load topology:', err);
            });
    }

    // ── ResizeObserver (debounced) ───────────────────────────────────────────
    var _resizeTimer = null;
    function _onContainerResize() {
        clearTimeout(_resizeTimer);
        _resizeTimer = setTimeout(function () { load(); }, 300);
    }

    // Auto-init
    document.addEventListener('DOMContentLoaded', function () {
        var svgContainer = document.getElementById('topologySvg');
        if (svgContainer) {
            load();
            // Refresh every 60 seconds
            setInterval(load, 60000);

            // Re-render on container resize
            if (typeof ResizeObserver !== 'undefined') {
                _resizeObserver = new ResizeObserver(_onContainerResize);
                _resizeObserver.observe(svgContainer.parentElement || svgContainer);
            }
        }
    });

    // ── Cleanup on page unload to prevent memory leaks ───────────────────────
    window.addEventListener('beforeunload', function () {
        if (_resizeObserver) {
            _resizeObserver.disconnect();
            _resizeObserver = null;
        }
    });

    // Public API
    window.NetwatchTopology = {
        load: load,
        render: render,
    };
})();
