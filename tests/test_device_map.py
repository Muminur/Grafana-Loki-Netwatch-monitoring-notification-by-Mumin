"""Tests for src/data/device_map.py — device IP → DeviceInfo resolution."""

from src.data.device_map import DeviceInfo, lookup_device

# ---------------------------------------------------------------------------
# Individual device lookups
# ---------------------------------------------------------------------------


def test_equinix_rtr1() -> None:
    """192.168.203.1 resolves to Equinix-RTR-1 in Singapore Equinix."""
    result = lookup_device("192.168.203.1")
    assert result is not None
    assert result.name == "Equinix-RTR-1"
    assert result.location == "Singapore Equinix"
    assert result.platform == "IOS-XR"
    assert result.hostname == "BSCCL-EQ-RTR-01"


def test_dhk_core3() -> None:
    """192.168.200.11 resolves to DHK-Core-3 in Dhaka Tejgaon."""
    result = lookup_device("192.168.200.11")
    assert result is not None
    assert result.name == "DHK-Core-3"
    assert result.location == "Dhaka Tejgaon"
    assert result.platform == "IOS-XR"
    assert result.hostname == "BSCPLC-DHK-RTR-03"


def test_kkt_core1_syslog_ip() -> None:
    """192.168.202.2 (syslog source IP) resolves to KKT-Core-1, Kuakata CLS."""
    result = lookup_device("192.168.202.2")
    assert result is not None
    assert result.name == "KKT-Core-1"
    assert result.location == "Kuakata CLS"
    assert result.platform == "IOS-XR"
    assert result.hostname == "BSCCL-KKT-CORE-RTR-01"


def test_kkt_core1_mgmt_ip() -> None:
    """192.168.202.150 (real mgmt IP) also resolves to KKT-Core-1."""
    result = lookup_device("192.168.202.150")
    assert result is not None
    assert result.name == "KKT-Core-1"
    assert result.location == "Kuakata CLS"


def test_kkt_core2_syslog_ip() -> None:
    """192.168.202.130 (syslog source IP) resolves to KKT-Core-2."""
    result = lookup_device("192.168.202.130")
    assert result is not None
    assert result.name == "KKT-Core-2"
    assert result.location == "Kuakata CLS"
    assert result.platform == "IOS-XR"
    assert result.hostname == "BSCCL-KKT-CORE-RTR-02"


def test_kkt_core2_mgmt_ip() -> None:
    """192.168.202.151 (real mgmt IP) also resolves to KKT-Core-2."""
    result = lookup_device("192.168.202.151")
    assert result is not None
    assert result.name == "KKT-Core-2"
    assert result.location == "Kuakata CLS"


def test_cox_core1() -> None:
    """192.168.200.8 resolves to COX-Core-1, Cox Bazar, IOS-XR."""
    result = lookup_device("192.168.200.8")
    assert result is not None
    assert result.name == "COX-Core-1"
    assert result.location == "Cox Bazar"
    assert result.platform == "IOS-XR"
    assert result.hostname == "BSCCL-COX-CORE-01"


def test_unknown_ip() -> None:
    """An IP not in the device map returns None."""
    assert lookup_device("10.0.0.1") is None
    assert lookup_device("0.0.0.0") is None
    assert lookup_device("255.255.255.255") is None


def test_dlink_sw() -> None:
    """192.168.200.66 resolves to D-LINK-SW in Dhaka with D-Link platform."""
    result = lookup_device("192.168.200.66")
    assert result is not None
    assert result.name == "D-LINK-SW"
    assert result.location == "Dhaka"
    assert result.platform == "D-Link"


# ---------------------------------------------------------------------------
# Completeness — all 34 primary device IPs must resolve
# ---------------------------------------------------------------------------

# Canonical syslog-source IPs for all 33 devices listed in
# APPENDIX-A-COMPLETE-INTERFACE-MAP.txt lines 11-43.
# KKT-Core-1 and KKT-Core-2 use their syslog IPs here; the real mgmt-IP
# aliases are tested separately above.
_ALL_33_IPS = [
    "192.168.200.2",  # DHK-Core-1
    "192.168.200.4",  # DHK-Core-2-Agg
    "192.168.200.11",  # DHK-Core-3
    "192.168.200.8",  # COX-Core-1
    "192.168.200.6",  # COX-Core-2
    "192.168.200.26",  # COX-Core-3
    "192.168.200.27",  # COX-Core-4
    "192.168.202.2",  # KKT-Core-1  (syslog IP)
    "192.168.202.130",  # KKT-Core-2  (syslog IP)
    "192.168.202.153",  # KKT-Core-3
    "192.168.203.1",  # Equinix-RTR-1
    "192.168.203.3",  # Equinix-RTR-2
    "192.168.200.16",  # LAN-DC-SW-1
    "192.168.200.17",  # LAN-DC-SW-2
    "192.168.200.25",  # LAN-DC-SW-3
    "192.168.200.23",  # DHAKACOLO-CGS
    "192.168.200.19",  # TEJ-CGS-01
    "192.168.200.21",  # MOGBAZAR-NEXUS
    "192.168.200.22",  # COX-NEXUS
    "192.168.200.30",  # COX-CGS-SW
    "192.168.200.18",  # TEJ-NEXUS
    "192.168.200.66",  # D-LINK-SW
    "192.168.200.14",  # ACC-SW-1
    "192.168.200.15",  # CTG-SW-01
    "192.168.200.34",  # CTG-SW-02
    "192.168.200.10",  # DPI-1
    "192.168.200.12",  # DPI-2
    "192.168.200.35",  # ICT-TOWER
    "192.168.200.24",  # L7-CISCO-SW
    "192.168.209.2",  # L6-CISCO-SW
    "192.168.200.20",  # COX-SW
    "192.168.202.11",  # KKT-MGMT-SW
    "192.168.202.12",  # KKT-10G-SW
]


def test_all_33_devices_exist() -> None:
    """Every primary syslog-source IP for all 33 devices must resolve."""
    missing = [ip for ip in _ALL_33_IPS if lookup_device(ip) is None]
    assert missing == [], f"These IPs are missing from device_map: {missing}"


def test_device_info_is_frozen_dataclass() -> None:
    """DeviceInfo must be a frozen dataclass (immutable)."""
    import dataclasses

    assert dataclasses.is_dataclass(DeviceInfo)
    fields = {f.name for f in dataclasses.fields(DeviceInfo)}
    assert fields == {"name", "hostname", "location", "platform"}


def test_equinix_rtr2() -> None:
    """192.168.203.3 resolves to Equinix-RTR-2."""
    result = lookup_device("192.168.203.3")
    assert result is not None
    assert result.name == "Equinix-RTR-2"
    assert result.hostname == "BSCCL-EQ-RTR-02"
    assert result.location == "Singapore Equinix"


def test_kkt_core3() -> None:
    """192.168.202.153 resolves to KKT-Core-3, Kuakata CLS, IOS-XR."""
    result = lookup_device("192.168.202.153")
    assert result is not None
    assert result.name == "KKT-Core-3"
    assert result.location == "Kuakata CLS"
    assert result.platform == "IOS-XR"


def test_dhakacolo_cgs_nxos() -> None:
    """192.168.200.23 resolves to DHAKACOLO-CGS, NX-OS platform."""
    result = lookup_device("192.168.200.23")
    assert result is not None
    assert result.name == "DHAKACOLO-CGS"
    assert result.platform == "NX-OS"


def test_total_map_size() -> None:
    """The device map must contain exactly 35 entries.

    Source of truth (APPENDIX-A-COMPLETE-INTERFACE-MAP.txt lines 11-43) lists
    33 unique device IPs.  Two extra entries are the real mgmt-IP aliases for
    KKT-Core-1 (192.168.202.150) and KKT-Core-2 (192.168.202.151), giving
    33 + 2 = 35 total.
    """
    from src.data.device_map import DEVICE_MAP

    assert len(DEVICE_MAP) == 35, (
        f"Expected 35 entries (33 canonical device IPs + 2 KKT mgmt-IP aliases), "
        f"got {len(DEVICE_MAP)}"
    )
