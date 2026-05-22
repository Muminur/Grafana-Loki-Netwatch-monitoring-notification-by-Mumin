"""Static device map: syslog source IP → DeviceInfo.

Source of truth: docs/INTERFACE-MAP.txt lines 11-43.

KKT IP quirks
-------------
KKT-Core-1 sends syslogs from 192.168.202.2 (its loopback/syslog source),
but its real management IP is 192.168.202.150.
KKT-Core-2 sends syslogs from 192.168.202.130 but its real mgmt IP is
192.168.202.151.
Both the syslog IP and the mgmt IP are mapped to the same DeviceInfo so that
lookups succeed regardless of which IP appears in a given context.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DeviceInfo:
    """Immutable record describing a single network device."""

    name: str  # friendly name, e.g. "DHK-Core-3"
    hostname: str  # config hostname, e.g. "BSCPLC-DHK-RTR-03"; "" if unknown
    location: str  # site location, e.g. "Dhaka Tejgaon"
    platform: str  # IOS-XR, NX-OS, IOS, D-Link, DPI, or "" if unknown


# ---------------------------------------------------------------------------
# Internal helpers — define canonical DeviceInfo objects once, reuse below
# ---------------------------------------------------------------------------

_KKT_CORE1 = DeviceInfo(
    name="KKT-Core-1",
    hostname="BSCCL-KKT-CORE-RTR-01",
    location="Kuakata CLS",
    platform="IOS-XR",
)

_KKT_CORE2 = DeviceInfo(
    name="KKT-Core-2",
    hostname="BSCCL-KKT-CORE-RTR-02",
    location="Kuakata CLS",
    platform="IOS-XR",
)

# ---------------------------------------------------------------------------
# DEVICE_MAP — 36 entries:
#   34 canonical syslog-source IPs  +
#    2 real mgmt-IP aliases for KKT-Core-1 / KKT-Core-2
# ---------------------------------------------------------------------------

DEVICE_MAP: dict[str, DeviceInfo] = {
    # ── Dhaka Tejgaon ────────────────────────────────────────────────────
    "192.168.200.2": DeviceInfo(
        name="DHK-Core-1",
        hostname="",
        location="Dhaka Tejgaon",
        platform="IOS-XR",
    ),
    "192.168.200.4": DeviceInfo(
        name="DHK-Core-2-Agg",
        hostname="",
        location="Dhaka Tejgaon",
        platform="IOS-XR",
    ),
    "192.168.200.11": DeviceInfo(
        name="DHK-Core-3",
        hostname="BSCPLC-DHK-RTR-03",
        location="Dhaka Tejgaon",
        platform="IOS-XR",
    ),
    "192.168.200.18": DeviceInfo(
        name="TEJ-NEXUS",
        hostname="",
        location="Dhaka Tejgaon",
        platform="NX-OS",
    ),
    "192.168.200.19": DeviceInfo(
        name="TEJ-CGS-01",
        hostname="BSCCL-CGS-TEJ-01",
        location="Dhaka Tejgaon",
        platform="NX-OS",
    ),
    # ── Cox's Bazar ──────────────────────────────────────────────────────
    "192.168.200.6": DeviceInfo(
        name="COX-Core-2",
        hostname="BSCCL-COX-CORE-02",
        location="Cox Bazar",
        platform="IOS-XR",
    ),
    "192.168.200.8": DeviceInfo(
        name="COX-Core-1",
        hostname="BSCCL-COX-CORE-01",
        location="Cox Bazar",
        platform="IOS-XR",
    ),
    "192.168.200.26": DeviceInfo(
        name="COX-Core-3",
        hostname="BSCPLC-COX-RTR-03",
        location="Cox Bazar",
        platform="IOS-XR",
    ),
    "192.168.200.27": DeviceInfo(
        name="COX-Core-4",
        hostname="BSCPLC-COX-RTR-04",
        location="Cox Bazar",
        platform="IOS-XR",
    ),
    "192.168.200.20": DeviceInfo(
        name="COX-SW",
        hostname="",
        location="Cox Bazar",
        platform="",
    ),
    "192.168.200.22": DeviceInfo(
        name="COX-NEXUS",
        hostname="BSCCL-COX-NEXUS-01",
        location="Cox Bazar",
        platform="NX-OS",
    ),
    "192.168.200.30": DeviceInfo(
        name="COX-CGS-SW",
        hostname="BSCPLC-COX-CGS-SW-01",
        location="Cox Bazar",
        platform="NX-OS",
    ),
    # ── Kuakata CLS ──────────────────────────────────────────────────────
    # KKT-Core-1: syslog source IP is 192.168.202.2; real mgmt is .150
    "192.168.202.2": _KKT_CORE1,
    "192.168.202.150": _KKT_CORE1,  # real mgmt IP alias
    # KKT-Core-2: syslog source IP is 192.168.202.130; real mgmt is .151
    "192.168.202.130": _KKT_CORE2,
    "192.168.202.151": _KKT_CORE2,  # real mgmt IP alias
    "192.168.202.153": DeviceInfo(
        name="KKT-Core-3",
        hostname="BSCCL-KKT-CORE-RTR-03",
        location="Kuakata CLS",
        platform="IOS-XR",
    ),
    "192.168.202.11": DeviceInfo(
        name="KKT-MGMT-SW",
        hostname="",
        location="Kuakata",
        platform="",
    ),
    "192.168.202.12": DeviceInfo(
        name="KKT-10G-SW",
        hostname="",
        location="Kuakata",
        platform="",
    ),
    # ── Singapore Equinix ────────────────────────────────────────────────
    "192.168.203.1": DeviceInfo(
        name="Equinix-RTR-1",
        hostname="BSCCL-EQ-RTR-01",
        location="Singapore Equinix",
        platform="IOS-XR",
    ),
    "192.168.203.3": DeviceInfo(
        name="Equinix-RTR-2",
        hostname="BSCCL-EQ-RTR-02",
        location="Singapore Equinix",
        platform="IOS-XR",
    ),
    # ── Dhaka DC ─────────────────────────────────────────────────────────
    "192.168.200.16": DeviceInfo(
        name="LAN-DC-SW-1",
        hostname="BSCCL-LAN-SW-01",
        location="Dhaka DC",
        platform="IOS",
    ),
    "192.168.200.17": DeviceInfo(
        name="LAN-DC-SW-2",
        hostname="BSCCL-LAN-SW-02",
        location="Dhaka DC",
        platform="IOS",
    ),
    "192.168.200.25": DeviceInfo(
        name="LAN-DC-SW-3",
        hostname="DC-Switch-3",
        location="Dhaka DC",
        platform="IOS",
    ),
    # ── Dhaka Colo ───────────────────────────────────────────────────────
    "192.168.200.23": DeviceInfo(
        name="DHAKACOLO-CGS",
        hostname="BSCCL-DHKCOLO-CGS-01",
        location="Dhaka Colo",
        platform="NX-OS",
    ),
    # ── Dhaka Mogbazar ───────────────────────────────────────────────────
    "192.168.200.21": DeviceInfo(
        name="MOGBAZAR-NEXUS",
        hostname="BSCCL-MOGBAZAR-NEXUS",
        location="Dhaka Mogbazar",
        platform="NX-OS",
    ),
    # ── Dhaka (various) ──────────────────────────────────────────────────
    "192.168.200.66": DeviceInfo(
        name="D-LINK-SW",
        hostname="DES-3200-26",
        location="Dhaka",
        platform="D-Link",
    ),
    "192.168.200.14": DeviceInfo(
        name="ACC-SW-1",
        hostname="",
        location="Dhaka",
        platform="IOS",
    ),
    "192.168.200.24": DeviceInfo(
        name="L7-CISCO-SW",
        hostname="",
        location="Dhaka",
        platform="IOS",
    ),
    "192.168.209.2": DeviceInfo(
        name="L6-CISCO-SW",
        hostname="",
        location="Dhaka",
        platform="IOS",
    ),
    "192.168.200.10": DeviceInfo(
        name="DPI-1",
        hostname="",
        location="Dhaka",
        platform="DPI",
    ),
    "192.168.200.12": DeviceInfo(
        name="DPI-2",
        hostname="",
        location="Dhaka",
        platform="DPI",
    ),
    "192.168.200.35": DeviceInfo(
        name="ICT-TOWER",
        hostname="",
        location="Dhaka ICT Tower",
        platform="",
    ),
    # ── Chittagong ───────────────────────────────────────────────────────
    "192.168.200.15": DeviceInfo(
        name="CTG-SW-01",
        hostname="",
        location="Chittagong",
        platform="IOS",
    ),
    "192.168.200.34": DeviceInfo(
        name="CTG-SW-02",
        hostname="",
        location="Chittagong",
        platform="NX-OS",
    ),
}


def lookup_device(ip: str) -> DeviceInfo | None:
    """Resolve a syslog source IP to its DeviceInfo.

    Handles both the syslog-source IPs and the real mgmt IPs for KKT devices.
    Returns None for any IP not present in the device map.
    """
    return DEVICE_MAP.get(ip)
