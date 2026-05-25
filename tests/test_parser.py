"""Tests for src.core.parser — all 4 IOS-XR syslog formats."""

from datetime import datetime
from unittest.mock import patch

from src.core.parser import _UTC6, ParsedLog, parse_syslog

# ---------------------------------------------------------------------------
# Format 1 — IOS-XR with +06 offset (EQ-RTR-01, DHK-Core-3)
# ---------------------------------------------------------------------------


def test_parse_iosxr_plus06_bgp_down(sample_bgp_down_log: str) -> None:
    """Format 1: verify every field on the canonical BGP-down log."""
    result = parse_syslog(sample_bgp_down_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.hostname == "BSCCL-EQ-RTR-01"
    assert result.rp_location == "RP/0/RP0/CPU0"
    assert result.facility == "ROUTING"
    assert result.subfacility == "BGP"
    assert result.severity_level == 5
    assert result.mnemonic == "ADJCHANGE"
    assert "neighbor 2001:de8:4::39:9077:1 Down" in result.message
    assert isinstance(result.timestamp, datetime)


def test_parse_iosxr_plus06_bgp_down_sggs(sample_bgp_down_sggs_log: str) -> None:
    """Format 1: second BGP-down log (AS 24482) parses correctly."""
    result = parse_syslog(sample_bgp_down_sggs_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.hostname == "BSCCL-EQ-RTR-01"
    assert result.facility == "ROUTING"
    assert result.subfacility == "BGP"
    assert result.severity_level == 5
    assert result.mnemonic == "ADJCHANGE"
    assert "Down" in result.message
    assert "24482" in result.message


def test_parse_bgp_up(sample_bgp_up_log: str) -> None:
    """Format 1: BGP Up recovery log — message must contain 'Up'."""
    result = parse_syslog(sample_bgp_up_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.facility == "ROUTING"
    assert result.subfacility == "BGP"
    assert result.mnemonic == "ADJCHANGE"
    assert "Up" in result.message


def test_parse_nsr_disabled(sample_nsr_disabled_log: str) -> None:
    """Format 1: NSR-disabled log — correct mnemonic and hostname."""
    result = parse_syslog(sample_nsr_disabled_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.hostname == "BSCCL-EQ-RTR-01"
    assert result.rp_location == "RP/0/RP1/CPU0"
    assert result.facility == "ROUTING"
    assert result.subfacility == "BGP"
    assert result.mnemonic == "NBR_NSR_DISABLED_STANDBY"


def test_parse_remote_fault(sample_remote_fault_log: str) -> None:
    """Format 1 (LC location): RX_FAULT mnemonic."""
    result = parse_syslog(sample_remote_fault_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PLATFORM"
    assert result.subfacility == "DPA"
    assert result.severity_level == 2
    assert result.mnemonic == "RX_FAULT"
    assert "TenGigE0/0/0/0" in result.message


def test_parse_ber_clear(sample_ber_clear_log: str) -> None:
    """Format 1 (LC location): BER-clear log."""
    result = parse_syslog(sample_ber_clear_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PLATFORM"
    assert result.mnemonic == "REPORT_BER_CLEAR"
    assert "TenGigE0/0/0/0" in result.message


def test_parse_interface_up(sample_interface_up_log: str) -> None:
    """Format 1 (LC location): interface state change to Up."""
    result = parse_syslog(sample_interface_up_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PKT_INFRA"
    assert result.subfacility == "LINK"
    assert result.mnemonic == "UPDOWN"
    assert "changed state to Up" in result.message


def test_parse_port_creation_failure(sample_port_creation_failure_log: str) -> None:
    """Format 1 (LC location, hostname present): port creation failure mnemonic."""
    result = parse_syslog(sample_port_creation_failure_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.hostname == "BSCCL-EQ-RTR-01"
    assert result.rp_location == "LC/0/3/CPU0"
    assert result.facility == "PLATFORM"
    assert "PORT_CREATION_FAILURE" in result.mnemonic
    assert "HundredGigE0_3_2_2" in result.message


def test_parse_operation_stalled(sample_operation_stalled_log: str) -> None:
    """Format 1 (LC location, hostname present): operation stalled log."""
    result = parse_syslog(sample_operation_stalled_log)
    assert result is not None
    assert result.source_ip == "192.168.203.1"
    assert result.hostname == "BSCCL-EQ-RTR-01"
    assert result.rp_location == "LC/0/3/CPU0"
    assert result.facility == "PKT_INFRA"
    assert result.mnemonic == "GLOBAL_OPERATION_STALLED"
    assert "51650" in result.message


def test_parse_ssh_login(sample_ssh_login_log: str) -> None:
    """Format 1: SSH login event — security facility."""
    result = parse_syslog(sample_ssh_login_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.facility == "SECURITY"
    assert result.subfacility == "SSHD"
    assert result.severity_level == 6
    assert result.mnemonic == "INFO_SUCCESS"
    assert "rancid" in result.message
    assert "192.168.200.56" in result.message
    assert "vty0" in result.message


def test_parse_ssh_logout(sample_ssh_logout_log: str) -> None:
    """Format 1: SSH logout event — INFO_USER_LOGOUT mnemonic."""
    result = parse_syslog(sample_ssh_logout_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.facility == "SECURITY"
    assert result.subfacility == "SSHD"
    assert result.mnemonic == "INFO_USER_LOGOUT"


# ---------------------------------------------------------------------------
# Format 2 — IOS-XR with BDT timezone (KKT routers — no hostname prefix)
# ---------------------------------------------------------------------------


def test_parse_iosxr_bdt_lacp_expired(sample_lacp_expired_log: str) -> None:
    """Format 2 (BDT): every field on LACP-expired log."""
    result = parse_syslog(sample_lacp_expired_log)
    assert result is not None
    assert result.source_ip == "192.168.202.130"
    assert result.rp_location == "RP/0/RSP1/CPU0"
    assert result.facility == "L2"
    assert result.subfacility == "BM"
    assert result.severity_level == 6
    assert result.mnemonic == "ACTIVE"
    assert "TenGigE0/0/1/7 is no longer Active" in result.message


def test_parse_bgp_maxpfx(sample_maxpfx_log: str) -> None:
    """Format 2 (BDT): max-prefix warning with prefix count in message."""
    result = parse_syslog(sample_maxpfx_log)
    assert result is not None
    assert result.source_ip == "192.168.202.130"
    assert result.rp_location == "RP/0/RSP1/CPU0"
    assert result.facility == "ROUTING"
    assert result.subfacility == "BGP"
    assert result.severity_level == 5
    assert result.mnemonic == "MAXPFX"
    assert "782" in result.message
    assert "1000" in result.message


def test_parse_signal_failure(sample_signal_failure_log: str) -> None:
    """Format 2 (BDT, LC location): signal failure mnemonic."""
    result = parse_syslog(sample_signal_failure_log)
    assert result is not None
    assert result.source_ip == "192.168.202.2"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PLATFORM"
    assert result.mnemonic == "SIGNAL"
    assert "TenGigE0/0/1/6" in result.message


# ---------------------------------------------------------------------------
# Format 3 — IOS-XR ADMIN plane (0/RP0/ADMIN0)
# ---------------------------------------------------------------------------


def test_parse_iosxr_admin_plane(sample_hw_event_log: str) -> None:
    """Format 3: ADMIN plane log — location prefix 0/RP0/ADMIN0."""
    result = parse_syslog(sample_hw_event_log)
    assert result is not None
    assert result.source_ip == "192.168.200.11"
    assert result.rp_location == "0/RP0/ADMIN0"
    assert result.facility == "INFRA"
    assert result.subfacility == "SHELF_MGR"
    assert result.severity_level == 6
    assert result.mnemonic == "HW_EVENT"
    assert "HW_EVENT_OK" in result.message


# ---------------------------------------------------------------------------
# Format 4 — IOS-XR without hostname, no TZ suffix, no fractional seconds
# ---------------------------------------------------------------------------


def test_parse_iosxr_no_hostname_sfp_set(sample_sfp_alarm_set_log: str) -> None:
    """Format 4: no hostname, no TZ — SFP low-rx-power alarm set."""
    result = parse_syslog(sample_sfp_alarm_set_log)
    assert result is not None
    assert result.source_ip == "192.168.200.8"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PLATFORM"
    assert result.subfacility == "SFP"
    assert result.severity_level == 2
    assert result.mnemonic == "LOW_RX_POWER_ALARM"
    assert "Set|envmon_lc" in result.message


def test_parse_sfp_alarm_clear(sample_sfp_alarm_clear_log: str) -> None:
    """Format 4: no hostname, no TZ — SFP alarm clear."""
    result = parse_syslog(sample_sfp_alarm_clear_log)
    assert result is not None
    assert result.source_ip == "192.168.200.8"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "PLATFORM"
    assert result.subfacility == "SFP"
    assert result.severity_level == 2
    assert result.mnemonic == "LOW_RX_POWER_ALARM"
    assert "Clear|envmon_lc" in result.message


def test_parse_duplicate_ipv6(sample_duplicate_ipv6_log: str) -> None:
    """Format 4: duplicate IPv6 address detected on Bundle interface."""
    result = parse_syslog(sample_duplicate_ipv6_log)
    assert result is not None
    assert result.source_ip == "192.168.200.8"
    assert result.rp_location == "LC/0/0/CPU0"
    assert result.facility == "IP"
    assert result.mnemonic == "ADDRESS_DUPLICATE"
    assert "2406:4b00:4:4::1" in result.message
    assert "Bundle-Ether191" in result.message


def test_parse_eem_commit(sample_eem_commit_log: str) -> None:
    """Format 4: EEM automation config commit — no hostname, no TZ."""
    result = parse_syslog(sample_eem_commit_log)
    assert result is not None
    assert result.source_ip == "192.168.200.8"
    assert result.facility == "MGBL"
    assert result.subfacility == "CONFIG"
    assert result.severity_level == 6
    assert result.mnemonic == "DB_COMMIT"
    assert "event_manager_user" in result.message


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------


def test_timestamp_normalization_plus06(sample_bgp_down_log: str) -> None:
    """Timestamp parsed from +06 log is a proper datetime instance."""
    result = parse_syslog(sample_bgp_down_log)
    assert result is not None
    assert isinstance(result.timestamp, datetime)
    # Month May = 5
    assert result.timestamp.month == 5
    assert result.timestamp.day == 22


def test_timestamp_normalization_bdt(sample_lacp_expired_log: str) -> None:
    """Timestamp parsed from BDT log is a proper datetime instance."""
    result = parse_syslog(sample_lacp_expired_log)
    assert result is not None
    assert isinstance(result.timestamp, datetime)
    assert result.timestamp.month == 5
    assert result.timestamp.day == 22


# ---------------------------------------------------------------------------
# raw field preservation
# ---------------------------------------------------------------------------


def test_parse_preserves_raw_line(sample_bgp_down_log: str) -> None:
    """result.raw must equal the original input string exactly."""
    result = parse_syslog(sample_bgp_down_log)
    assert result is not None
    assert result.raw == sample_bgp_down_log


def test_parse_preserves_raw_line_format4(sample_sfp_alarm_set_log: str) -> None:
    """result.raw preservation holds for Format 4 as well."""
    result = parse_syslog(sample_sfp_alarm_set_log)
    assert result is not None
    assert result.raw == sample_sfp_alarm_set_log


# ---------------------------------------------------------------------------
# Negative / edge-case tests
# ---------------------------------------------------------------------------


def test_parse_returns_none_for_garbage() -> None:
    """Completely unrecognised input returns None, not an exception."""
    result = parse_syslog("random garbage string that matches nothing")
    assert result is None


def test_parse_returns_none_for_empty() -> None:
    """Empty string returns None."""
    result = parse_syslog("")
    assert result is None


def test_parse_returns_none_for_whitespace_only() -> None:
    """Whitespace-only string returns None."""
    result = parse_syslog("   \t\n  ")
    assert result is None


def test_parsed_log_is_dataclass(sample_bgp_down_log: str) -> None:
    """parse_syslog returns a ParsedLog instance (not a plain dict)."""
    result = parse_syslog(sample_bgp_down_log)
    assert result is not None
    assert isinstance(result, ParsedLog)


# ---------------------------------------------------------------------------
# Year-rollover edge cases
# ---------------------------------------------------------------------------


def test_year_rollover_dec_to_jan_forward() -> None:
    """In December, a January log should roll forward to the next year."""
    # Simulate "now" being December 15, 2026
    fake_now = datetime(2026, 12, 15, 10, 0, 0, tzinfo=_UTC6)

    # Build a syslog line with a January timestamp
    raw = (
        "Jan 3 10:00:00 192.168.203.1 99999: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:Jan 3 10:00:00.000 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 1.2.3.4 Down - test "
        "(VRF: default) (AS: 12345)"
    )

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        result = parse_syslog(raw)

    assert result is not None
    # January log received in December → should be year 2027
    assert result.timestamp.year == 2027
    assert result.timestamp.month == 1


def test_year_rollover_jan_receives_dec_log() -> None:
    """In January, a December log should roll back to the previous year."""
    # Simulate "now" being January 3, 2027
    fake_now = datetime(2027, 1, 3, 10, 0, 0, tzinfo=_UTC6)

    raw = (
        "Dec 31 23:59:59 192.168.203.1 99999: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:Dec 31 23:59:59.000 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 1.2.3.4 Down - test "
        "(VRF: default) (AS: 12345)"
    )

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        result = parse_syslog(raw)

    assert result is not None
    # December log received in January → should be year 2026
    assert result.timestamp.year == 2026
    assert result.timestamp.month == 12


def test_year_rollover_nov_receives_jan_forward() -> None:
    """In November, a January log should roll forward to the next year."""
    fake_now = datetime(2026, 11, 28, 10, 0, 0, tzinfo=_UTC6)

    raw = (
        "Jan 2 08:00:00 192.168.203.1 99999: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:Jan 2 08:00:00.000 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 1.2.3.4 Down - test "
        "(VRF: default) (AS: 12345)"
    )

    with patch("src.core.parser.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)  # noqa: DTZ001
        result = parse_syslog(raw)

    assert result is not None
    # January log received in November → should be year 2027
    assert result.timestamp.year == 2027
    assert result.timestamp.month == 1
