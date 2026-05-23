"""Static mapping of backbone BGP peer IPs to their underlying bundle.

When a BGP session comes UP on a point-to-point backbone link, we can infer
that all physical member interfaces of that bundle are operational. This map
enables auto-resolution of silent hardware faults (RX_FAULT, SIGNAL, RFI)
that IOS-XR never generates clear messages for.

Source: docs/INTERFACE-IP-MAP.txt — bundle sub-interface IP assignments.
Only backbone point-to-point peers are included. IX/PNI peers are excluded.
"""

from __future__ import annotations

_BGP_BUNDLE_MAP: dict[tuple[str, str], str] = {
    # ── EQ-RTR-01 (192.168.203.1) ─────────────────────────────────────────
    ("192.168.203.1", "103.16.153.22"): "Bundle-Ether500",
    ("192.168.203.1", "2406:4b00:a:2:1::6"): "Bundle-Ether500",
    ("192.168.203.1", "103.16.153.46"): "Bundle-Ether200",
    ("192.168.203.1", "2406:4b00:0:3::2"): "Bundle-Ether200",
    ("192.168.203.1", "103.16.153.18"): "Bundle-Ether600",
    ("192.168.203.1", "2406:4b00:a:2:1::2"): "Bundle-Ether600",
    ("192.168.203.1", "103.16.153.38"): "Bundle-Ether300",
    # ── EQ-RTR-02 (192.168.203.3) ─────────────────────────────────────────
    ("192.168.203.3", "103.16.153.34"): "Bundle-Ether500",
    ("192.168.203.3", "2406:4b00:a:2:1::12"): "Bundle-Ether500",
    ("192.168.203.3", "103.16.153.17"): "Bundle-Ether600",
    ("192.168.203.3", "2406:4b00:a:2:1::1"): "Bundle-Ether600",
    ("192.168.203.3", "103.16.153.26"): "Bundle-Ether505",
    ("192.168.203.3", "2406:4b00:a:2:1::16"): "Bundle-Ether505",
    # ── KKT-Core-01 (192.168.202.2) ───────────────────────────────────────
    ("192.168.202.2", "103.16.153.21"): "Bundle-Ether500",
    ("192.168.202.2", "2406:4b00:a:2:1::5"): "Bundle-Ether500",
    ("192.168.202.2", "103.16.153.26"): "Bundle-Ether505",
    ("192.168.202.2", "2406:4b00:a:2:1::16"): "Bundle-Ether505",
    ("192.168.202.2", "103.16.152.81"): "Bundle-Ether400",
    ("192.168.202.2", "2406:4b00:0:b::1"): "Bundle-Ether400",
    # ── COX-Core-02 (192.168.200.6) ───────────────────────────────────────
    ("192.168.200.6", "103.16.153.33"): "Bundle-Ether500",
    ("192.168.200.6", "2406:4b00:a:2:1::11"): "Bundle-Ether500",
    # ── COX-Core-03 (192.168.200.26) ──────────────────────────────────────
    ("192.168.200.26", "103.16.153.45"): "Bundle-Ether200",
    ("192.168.200.26", "2406:4b00:0:3::1"): "Bundle-Ether200",
    # ── DHK-Core-03 (192.168.200.11) ──────────────────────────────────────
    ("192.168.200.11", "103.16.152.82"): "Bundle-Ether400",
    ("192.168.200.11", "2406:4b00:0:b::2"): "Bundle-Ether400",
    # ── KKT-Core-03 (192.168.202.153) ─────────────────────────────────────
    ("192.168.202.153", "103.16.153.37"): "Bundle-Ether300",
}


def lookup_bundle_for_bgp_peer(device_ip: str, neighbor_ip: str) -> str | None:
    """Look up the backbone bundle for a BGP peer on a given device.

    Returns the bundle name if the peer is a backbone point-to-point neighbor,
    or None if it's an IX/PNI/unknown peer.
    """
    return _BGP_BUNDLE_MAP.get((device_ip, neighbor_ip))
