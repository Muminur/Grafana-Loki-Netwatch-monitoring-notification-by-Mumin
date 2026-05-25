"""Tests for src/core/enricher.py — TDD: write first, implement second."""

from __future__ import annotations

import pytest

from src.core.enricher import EnrichedLog, enrich
from src.core.parser import parse_syslog

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _parse(raw: str):
    """Parse a raw syslog line; fail the test if it cannot be parsed."""
    parsed = parse_syslog(raw)
    assert parsed is not None, f"parse_syslog returned None for: {raw!r}"
    return parsed


# ---------------------------------------------------------------------------
# 1. BGP Down → CRITICAL, device + AS + neighbor extracted
# ---------------------------------------------------------------------------


def test_enrich_bgp_down(sample_bgp_down_log: str) -> None:
    """BGP Down log → Equinix-RTR-1, CRITICAL, TCLOUD AS399077 neighbour."""
    result = enrich(_parse(sample_bgp_down_log))

    assert isinstance(result, EnrichedLog)
    assert result.device_name == "Equinix-RTR-1"
    assert result.device_location == "Singapore Equinix"
    assert result.classification == "CRITICAL"
    assert "2001:de8:4::39:9077:1" in result.bgp_neighbor
    assert result.as_number == 399077
    assert result.as_name == "TCLOUD Computing"


# ---------------------------------------------------------------------------
# 2. LACP Expired → KKT-Core-2, interface + bundle extracted
# ---------------------------------------------------------------------------


def test_enrich_lacp_expired(sample_lacp_expired_log: str) -> None:
    """LACP Expired log → KKT-Core-2, TenGigE0/0/1/7, Bundle-Ether201."""
    result = enrich(_parse(sample_lacp_expired_log))

    assert "KKT-Core-2" in result.device_name
    assert "TenGigE0/0/1/7" in result.interface_name
    assert "F@H" in result.interface_description
    assert "Bundle-Ether201" in result.bundle_parent


# ---------------------------------------------------------------------------
# 3. Max Prefix → WARNING, KKT-Core-2
# ---------------------------------------------------------------------------


def test_enrich_maxpfx(sample_maxpfx_log: str) -> None:
    """Max Prefix log → KKT-Core-2 device, WARNING classification."""
    result = enrich(_parse(sample_maxpfx_log))

    assert "KKT-Core-2" in result.device_name
    assert result.classification == "WARNING"


# ---------------------------------------------------------------------------
# 4. Remote Fault → TenGigE0/0/0/0, DHK-Core-3
# ---------------------------------------------------------------------------


def test_enrich_remote_fault(sample_remote_fault_log: str) -> None:
    """Remote Fault log → TenGigE0/0/0/0 interface extracted, DHK-Core-3."""
    result = enrich(_parse(sample_remote_fault_log))

    assert result.interface_name == "TenGigE0/0/0/0"
    assert "DHK-Core-3" in result.device_name


# ---------------------------------------------------------------------------
# 5. SFP Alarm Set → GigE0/0/0/4 interface
# ---------------------------------------------------------------------------


def test_enrich_sfp_alarm(sample_sfp_alarm_set_log: str) -> None:
    """SFP Alarm Set log → GigE0/0/0/4 interface extracted."""
    result = enrich(_parse(sample_sfp_alarm_set_log))

    # The SFP alarm message uses the short prefix "GigE0/0/0/4"
    iface = result.interface_name
    assert "GigE0/0/0/4" in iface or "GigabitEthernet0/0/0/4" in iface


# ---------------------------------------------------------------------------
# 6. SSH Login → USER_LOGIN classification, DHK-Core-3
# ---------------------------------------------------------------------------


def test_enrich_ssh_login(sample_ssh_login_log: str) -> None:
    """SSH Login log → USER_LOGIN classification, DHK-Core-3 device."""
    result = enrich(_parse(sample_ssh_login_log))

    assert result.classification == "USER_LOGIN"
    assert "DHK-Core-3" in result.device_name


# ---------------------------------------------------------------------------
# 7. Duplicate IPv6 → Bundle-Ether191 extracted
# ---------------------------------------------------------------------------


def test_enrich_duplicate_ipv6(sample_duplicate_ipv6_log: str) -> None:
    """Duplicate IPv6 log → Bundle-Ether191 interface name extracted."""
    result = enrich(_parse(sample_duplicate_ipv6_log))

    assert "Bundle-Ether191" in result.interface_name


# ---------------------------------------------------------------------------
# 8. Unknown device IP → device_name starts with "UNKNOWN"
# ---------------------------------------------------------------------------


def test_enrich_unknown_device() -> None:
    """Log from an unknown source IP → device_name starts with 'UNKNOWN'."""
    # Craft a valid IOS-XR syslog from an IP not in the device map
    raw = (
        "May 22 10:00:00 10.255.255.255 99999: RP/0/RP0/CPU0:"
        "May 22 10:00:00.000 +06: bgp[1000]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 1.2.3.4 Down - test (VRF: default)"
    )
    parsed = parse_syslog(raw)
    assert parsed is not None

    result = enrich(parsed)
    assert result.device_name.startswith("UNKNOWN")


# ---------------------------------------------------------------------------
# 9. BGP Up → as_number extracted, WARNING
# ---------------------------------------------------------------------------


def test_enrich_bgp_up_has_as(sample_bgp_up_log: str) -> None:
    """BGP Up log → AS399077 extracted, CRITICAL classification."""
    result = enrich(_parse(sample_bgp_up_log))

    assert result.as_number == 399077
    assert result.classification == "CRITICAL"


# ---------------------------------------------------------------------------
# 10. VRF extracted from BGP Down log
# ---------------------------------------------------------------------------


def test_enrich_vrf_extracted(sample_bgp_down_log: str) -> None:
    """BGP Down log → VRF 'network' extracted."""
    result = enrich(_parse(sample_bgp_down_log))

    assert result.vrf == "network"


# ---------------------------------------------------------------------------
# 11. EnrichedLog is immutable (frozen dataclass)
# ---------------------------------------------------------------------------


def test_enriched_log_is_frozen(sample_bgp_down_log: str) -> None:
    """EnrichedLog must be a frozen dataclass."""
    result = enrich(_parse(sample_bgp_down_log))
    with pytest.raises((AttributeError, TypeError)):
        result.device_name = "MUTATED"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 12. BGP Down → notify=True
# ---------------------------------------------------------------------------


def test_enrich_bgp_down_notify(sample_bgp_down_log: str) -> None:
    """BGP Down → notify flag is True."""
    result = enrich(_parse(sample_bgp_down_log))
    assert result.notify is True


# ---------------------------------------------------------------------------
# 13. EEM commit → INFO classification, no notification
# ---------------------------------------------------------------------------


def test_enrich_eem_commit(sample_eem_commit_log: str) -> None:
    """EEM Commit log → INFO classification, notify=False."""
    result = enrich(_parse(sample_eem_commit_log))

    assert result.classification == "INFO"
    assert result.notify is False


# ---------------------------------------------------------------------------
# 14. Port creation failure → INFO, EQ-RTR known issue
# ---------------------------------------------------------------------------


def test_enrich_port_creation_failure(sample_port_creation_failure_log: str) -> None:
    """Port Creation Failure log → INFO, Equinix-RTR-1 device."""
    result = enrich(_parse(sample_port_creation_failure_log))

    assert result.classification == "INFO"
    assert "Equinix-RTR-1" in result.device_name


# ---------------------------------------------------------------------------
# 15. rule_id and event_type are non-empty strings
# ---------------------------------------------------------------------------


def test_enrich_rule_id_and_event_type(sample_bgp_down_log: str) -> None:
    """Enriched log must expose a non-empty rule_id and event_type."""
    result = enrich(_parse(sample_bgp_down_log))

    assert isinstance(result.rule_id, str)
    assert result.rule_id
    assert isinstance(result.event_type, str)
    assert result.event_type


# ---------------------------------------------------------------------------
# 16. Interface lookup attempted even when hostname is empty
# ---------------------------------------------------------------------------


def test_enrich_interface_lookup_with_empty_hostname() -> None:
    """When device_map hostname is empty, interface extraction still runs.

    DHK-Core-1 (192.168.200.2) has hostname="" in the device map.
    The enricher must still attempt to extract the interface name from
    the message rather than skipping the entire interface lookup.
    """
    # DHK-Core-1 has hostname="" — build a log from its IP with an interface
    raw = (
        "May 22 15:23:04 192.168.200.2 12345: LC/0/0/CPU0:"
        "May 22 15:23:29.243 +06: fia_driver[165]: "
        "%PLATFORM-DPA-2-RX_FAULT : Interface TenGigE0/0/0/0, "
        "Detected Remote Fault"
    )
    parsed = parse_syslog(raw)
    assert parsed is not None

    result = enrich(parsed)
    # The interface name should still be extracted from the message
    assert result.interface_name == "TenGigE0/0/0/0"
    # Device must be resolved (not UNKNOWN)
    assert result.device_name == "DHK-Core-1"
