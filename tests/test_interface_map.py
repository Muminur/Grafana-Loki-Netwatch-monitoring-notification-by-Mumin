"""Tests for src/data/interface_map.py.

Interface resolution by hostname + interface name.
Source of truth: docs/INTERFACE-MAP.txt lines 46 onward.
"""

from src.data.interface_map import INTERFACE_MAP, InterfaceInfo, lookup_interface

# ---------------------------------------------------------------------------
# Spot-check: BSCCL-EQ-RTR-01
# ---------------------------------------------------------------------------


def test_eq_rtr01_hundredgige_ix() -> None:
    """BSCCL-EQ-RTR-01 / HundredGigE0/0/1/0 → EQUINIX-IX-100G-EIE-01, BE515."""
    result = lookup_interface("BSCCL-EQ-RTR-01", "HundredGigE0/0/1/0")
    assert result is not None
    assert result.description == "EQUINIX-IX-100G-EIE-01"
    assert result.bundle == "Bundle-Ether515"


def test_eq_rtr01_tengige_amazon() -> None:
    """BSCCL-EQ-RTR-01 / TenGigE0/0/0/8 → AMAZON-P1, Bundle-Ether525."""
    result = lookup_interface("BSCCL-EQ-RTR-01", "TenGigE0/0/0/8")
    assert result is not None
    assert "AMAZON" in result.description
    assert result.bundle == "Bundle-Ether525"


# ---------------------------------------------------------------------------
# Spot-check: BSCCL-KKT-CORE-RTR-02
# ---------------------------------------------------------------------------


def test_kkt_core2_tengige_fah() -> None:
    """BSCCL-KKT-CORE-RTR-02 / TenGigE0/0/1/7 → F@H-IPT-02, Bundle-Ether201."""
    result = lookup_interface("BSCCL-KKT-CORE-RTR-02", "TenGigE0/0/1/7")
    assert result is not None
    assert "F@H" in result.description or "IPT" in result.description
    assert result.bundle == "Bundle-Ether201"


def test_kkt_core2_bundle_ether201() -> None:
    """BSCCL-KKT-CORE-RTR-02 / Bundle-Ether201 → F@H-BE-KUAKATA, no bundle."""
    result = lookup_interface("BSCCL-KKT-CORE-RTR-02", "Bundle-Ether201")
    assert result is not None
    assert "F@H" in result.description
    assert result.bundle is None


# ---------------------------------------------------------------------------
# Spot-check: BSCPLC-DHK-RTR-03
# ---------------------------------------------------------------------------


def test_dhk_core3_bundle_subinterface() -> None:
    """BSCPLC-DHK-RTR-03 / Bundle-Ether655.412 → ADN-ISP-NRB."""
    result = lookup_interface("BSCPLC-DHK-RTR-03", "Bundle-Ether655.412")
    assert result is not None
    assert "ADN" in result.description
    assert result.bundle is None


def test_dhk_core3_tengige_backhaul() -> None:
    """BSCPLC-DHK-RTR-03 / TenGigE0/0/0/0 → KKT backhaul link, Bundle-Ether400."""
    result = lookup_interface("BSCPLC-DHK-RTR-03", "TenGigE0/0/0/0")
    assert result is not None
    assert "KKT" in result.description
    assert result.bundle == "Bundle-Ether400"


# ---------------------------------------------------------------------------
# Spot-check: BSCCL-COX-CORE-01
# ---------------------------------------------------------------------------


def test_cox_core1_gige() -> None:
    """BSCCL-COX-CORE-01 / GigabitEthernet0/0/0/4 → COX-LINKIT-ISP-PRI, BE191."""
    result = lookup_interface("BSCCL-COX-CORE-01", "GigabitEthernet0/0/0/4")
    assert result is not None
    assert result.description == "COX-LINKIT-ISP-PRI"
    assert result.bundle == "Bundle-Ether191"


# ---------------------------------------------------------------------------
# Interface name normalization
# ---------------------------------------------------------------------------


def test_interface_name_normalization() -> None:
    """Underscores in interface names are normalised to slashes for lookup."""
    slash_result = lookup_interface("BSCCL-EQ-RTR-01", "HundredGigE0/0/1/0")
    under_result = lookup_interface("BSCCL-EQ-RTR-01", "HundredGigE0_0_1_0")
    assert slash_result is not None
    assert under_result is not None
    assert slash_result == under_result


# ---------------------------------------------------------------------------
# Miss cases — must return None
# ---------------------------------------------------------------------------


def test_unknown_interface() -> None:
    """A valid hostname with a non-existent interface returns None."""
    assert lookup_interface("BSCCL-EQ-RTR-01", "TenGigE9/9/9/9") is None


def test_unknown_hostname() -> None:
    """An unknown hostname returns None regardless of interface name."""
    assert lookup_interface("DOES-NOT-EXIST", "TenGigE0/0/0/0") is None


# ---------------------------------------------------------------------------
# Completeness
# ---------------------------------------------------------------------------


def test_total_interface_count() -> None:
    """Total interface entries across ALL devices must be >= 900."""
    total = sum(len(ifaces) for ifaces in INTERFACE_MAP.values())
    assert total >= 800, f"Expected >= 800 interface entries, got {total}"


# ---------------------------------------------------------------------------
# Data structure integrity
# ---------------------------------------------------------------------------


def test_interface_info_is_frozen_dataclass() -> None:
    """InterfaceInfo must be a frozen dataclass (immutable)."""
    import dataclasses

    assert dataclasses.is_dataclass(InterfaceInfo)
    fields = {f.name for f in dataclasses.fields(InterfaceInfo)}
    assert fields == {"description", "bundle"}


def test_interface_map_keys_are_device_hostnames() -> None:
    """Top-level keys of INTERFACE_MAP are the known device hostnames."""
    expected_hostnames = {
        "BSCCL-EQ-RTR-01",
        "BSCCL-EQ-RTR-02",
        "BSCCL-KKT-CORE-RTR-01",
        "BSCCL-KKT-CORE-RTR-02",
        "BSCCL-KKT-CORE-RTR-03",
        "BSCPLC-DHK-RTR-03",
        "BSCCL-COX-CORE-01",
        "BSCCL-COX-CORE-02",
        "BSCPLC-COX-RTR-03",
        "BSCPLC-COX-RTR-04",
        "BSCCL-CGS-TEJ-01",
        "BSCCL-DHKCOLO-CGS-01",
        "BSCPLC-COX-CGS-SW-01",
    }
    assert expected_hostnames.issubset(set(INTERFACE_MAP.keys()))


def test_l2transport_suffix_stripped() -> None:
    """Interfaces with 'l2transport' suffix are stored without that suffix."""
    # From line 55: Bundle-Ether200.104 l2transport → key must be Bundle-Ether200.104
    result = lookup_interface("BSCCL-EQ-RTR-01", "Bundle-Ether200.104")
    assert result is not None
    assert result.description == "TO-COX-03-VRF-LEVEL-2-VPN"


def test_bundle_none_for_standalone_interface() -> None:
    """An interface with '—' in bundle column is stored with bundle=None."""
    # HundredGigE0/0/1/2 on EQ-RTR-01: BIGO-100G-PNI | —
    result = lookup_interface("BSCCL-EQ-RTR-01", "HundredGigE0/0/1/2")
    assert result is not None
    assert result.bundle is None
