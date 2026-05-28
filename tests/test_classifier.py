"""Tests for the classifier engine — all 25 rules + priority + default.

TDD: tests written before implementation.  Run first to confirm RED,
then implement src/data/classification_rules.py and src/core/classifier.py
to go GREEN.
"""

from __future__ import annotations

import pytest

from src.core.classifier import ClassificationResult, classify
from src.core.parser import ParsedLog, parse_syslog
from src.data.classification_rules import CLASSIFICATION_RULES, ClassificationRule

# ---------------------------------------------------------------------------
# Local fixtures for logs not in conftest.py
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_intf_down_log() -> str:
    """CRITICAL — Interface Down (DHK-Core-3)."""
    return (
        "May 22 11:10:14 192.168.200.11 52370: LC/0/0/CPU0:"
        "May 22 11:10:38.422 +06: ifmgr[213]: "
        "%PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/0/0/0, "
        "changed state to Down"
    )


@pytest.fixture
def sample_lineproto_down_log() -> str:
    """CRITICAL — Line Protocol Down (DHK-Core-3)."""
    return (
        "May 22 11:10:14 192.168.200.11 52371: LC/0/0/CPU0:"
        "May 22 11:10:38.500 +06: ifmgr[213]: "
        "%PKT_INFRA-LINEPROTO-5-UPDOWN : Line protocol on Interface "
        "TenGigE0/0/0/0, changed state to Down"
    )


@pytest.fixture
def sample_lineproto_up_log() -> str:
    """WARNING — Line Protocol Up (DHK-Core-3)."""
    return (
        "May 22 11:15:42 192.168.200.11 52378: LC/0/0/CPU0:"
        "May 22 11:16:06.100 +06: ifmgr[213]: "
        "%PKT_INFRA-LINEPROTO-5-UPDOWN : Line protocol on Interface "
        "TenGigE0/0/0/0, changed state to Up"
    )


@pytest.fixture
def sample_lacp_active_log() -> str:
    """WARNING — LACP Bundle Member Active (KKT-Core-2)."""
    return (
        "May 22 11:20:00 192.168.202.130 395440: RP/0/RSP1/CPU0:"
        "May 22 11:20:00.100 BDT: BM-DISTRIB[1294]: %L2-BM-6-ACTIVE : "
        "TenGigE0/0/1/7 is now Active as part of Bundle-Ether201"
    )


@pytest.fixture
def sample_local_fault_log() -> str:
    """CRITICAL — Local Fault (DHK-Core-3)."""
    return (
        "May 22 16:00:01 192.168.200.11 52500: LC/0/0/CPU0:"
        "May 22 16:00:26.000 +06: fia_driver[165]: "
        "%PLATFORM-DPA-2-RX_FAULT : Interface TenGigE0/0/0/1, "
        "Detected Local Fault"
    )


@pytest.fixture
def sample_config_commit_user_log() -> str:
    """USER_LOGIN — Config commit by a real user (not EEM)."""
    return (
        "May 22 14:00:00 192.168.200.11 52600: RP/0/RP0/CPU0:"
        "May 22 14:00:00 : config[12345]: "
        "%MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user "
        "'admin'. Use 'show configuration commit changes 1000013700' "
        "to view the changes."
    )


@pytest.fixture
def sample_eem_script_log() -> str:
    """INFO — EEM Script action syslog (COX-Core-1)."""
    return (
        "May 22 10:50:00 192.168.200.8 29220: RP/0/RSP0/CPU0:"
        "May 22 10:50:00 : eem_ed_syslog[100]: "
        "%HA-HA_EEM-6-ACTION_SYSLOG_LOG_INFO : fh_io_msg: namePair "
        "eem_action/syslog: eem_action_syslog_message"
    )


# ---------------------------------------------------------------------------
# Helper — parse + assert not None
# ---------------------------------------------------------------------------


def _parse(raw: str) -> ParsedLog:
    result = parse_syslog(raw)
    assert result is not None, f"parse_syslog returned None for: {raw!r}"
    return result


# ---------------------------------------------------------------------------
# Structural sanity
# ---------------------------------------------------------------------------


def test_rules_list_has_26_entries() -> None:
    """CLASSIFICATION_RULES must contain exactly 26 entries."""
    assert len(CLASSIFICATION_RULES) == 26


def test_all_rules_are_classification_rule_instances() -> None:
    """Every entry in CLASSIFICATION_RULES is a ClassificationRule dataclass."""
    for rule in CLASSIFICATION_RULES:
        assert isinstance(rule, ClassificationRule)


def test_rule_ids_are_unique() -> None:
    """No two rules share the same id."""
    ids = [r.id for r in CLASSIFICATION_RULES]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# CRITICAL rules (1-10) — must classify + notify=True
# ---------------------------------------------------------------------------


def test_classify_bgp_down(sample_bgp_down_log: str) -> None:
    """Rule BGP_DOWN: ADJCHANGE … Down → CRITICAL."""
    result = classify(_parse(sample_bgp_down_log))
    assert isinstance(result, ClassificationResult)
    assert result.rule_id == "BGP_DOWN"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_bgp_maxpfx(sample_maxpfx_log: str) -> None:
    """Rule BGP_MAXPFX: %ROUTING-BGP-5-MAXPFX → CRITICAL."""
    result = classify(_parse(sample_maxpfx_log))
    assert result.rule_id == "BGP_MAXPFX"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_lacp_expired(sample_lacp_expired_log: str) -> None:
    """Rule LACP_EXPIRED: BM-6-ACTIVE … no longer Active → CRITICAL."""
    result = classify(_parse(sample_lacp_expired_log))
    assert result.rule_id == "LACP_EXPIRED"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_remote_fault(sample_remote_fault_log: str) -> None:
    """Rule REMOTE_FAULT: DPA-2-RX_FAULT … Remote Fault → CRITICAL."""
    result = classify(_parse(sample_remote_fault_log))
    assert result.rule_id == "REMOTE_FAULT"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_local_fault(sample_local_fault_log: str) -> None:
    """Rule LOCAL_FAULT: DPA-2-RX_FAULT … Local Fault → CRITICAL."""
    result = classify(_parse(sample_local_fault_log))
    assert result.rule_id == "LOCAL_FAULT"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_signal_failure(sample_signal_failure_log: str) -> None:
    """Rule SIGNAL_FAILURE: VIC-4-SIGNAL … Signal failure → CRITICAL."""
    result = classify(_parse(sample_signal_failure_log))
    assert result.rule_id == "SIGNAL_FAILURE"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_sfp_alarm_set(sample_sfp_alarm_set_log: str) -> None:
    """Rule SFP_ALARM_SET: LOW_RX_POWER_ALARM … Set → CRITICAL."""
    result = classify(_parse(sample_sfp_alarm_set_log))
    assert result.rule_id == "SFP_ALARM_SET"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_duplicate_ipv6(sample_duplicate_ipv6_log: str) -> None:
    """Rule DUPLICATE_IPV6: IPV6_ND-3-ADDRESS_DUPLICATE → CRITICAL."""
    result = classify(_parse(sample_duplicate_ipv6_log))
    assert result.rule_id == "DUPLICATE_IPV6"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_intf_down(sample_intf_down_log: str) -> None:
    """Rule INTF_DOWN: LINK-3-UPDOWN … changed state to Down → CRITICAL."""
    result = classify(_parse(sample_intf_down_log))
    assert result.rule_id == "INTF_DOWN"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_lineproto_down(sample_lineproto_down_log: str) -> None:
    """Rule LINEPROTO_DOWN: LINEPROTO-5-UPDOWN … changed state to Down → CRITICAL."""
    result = classify(_parse(sample_lineproto_down_log))
    assert result.rule_id == "LINEPROTO_DOWN"
    assert result.classification == "CRITICAL"
    assert result.notify is True


# ---------------------------------------------------------------------------
# WARNING rules (11-16) — notify=False
# ---------------------------------------------------------------------------


def test_classify_ber_clear(sample_ber_clear_log: str) -> None:
    """Rule BER_CLEAR: REPORT_BER_CLEAR → WARNING."""
    result = classify(_parse(sample_ber_clear_log))
    assert result.rule_id == "BER_CLEAR"
    assert result.classification == "WARNING"
    assert result.notify is False


def test_classify_bgp_up(sample_bgp_up_log: str) -> None:
    """Rule BGP_UP: ADJCHANGE … Up → CRITICAL."""
    result = classify(_parse(sample_bgp_up_log))
    assert result.rule_id == "BGP_UP"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_intf_up(sample_interface_up_log: str) -> None:
    """Rule INTF_UP: LINK-3-UPDOWN … changed state to Up → CRITICAL."""
    result = classify(_parse(sample_interface_up_log))
    assert result.rule_id == "INTF_UP"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_lineproto_up(sample_lineproto_up_log: str) -> None:
    """Rule LINEPROTO_UP: LINEPROTO-5-UPDOWN … changed state to Up → CRITICAL."""
    result = classify(_parse(sample_lineproto_up_log))
    assert result.rule_id == "LINEPROTO_UP"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_sfp_alarm_clear(sample_sfp_alarm_clear_log: str) -> None:
    """Rule SFP_ALARM_CLEAR: LOW_RX_POWER_ALARM … Clear → WARNING."""
    result = classify(_parse(sample_sfp_alarm_clear_log))
    assert result.rule_id == "SFP_ALARM_CLEAR"
    assert result.classification == "WARNING"
    assert result.notify is False


def test_classify_lacp_active(sample_lacp_active_log: str) -> None:
    """Rule LACP_ACTIVE: BM-6-ACTIVE … Active → CRITICAL."""
    result = classify(_parse(sample_lacp_active_log))
    assert result.rule_id == "LACP_ACTIVE"
    assert result.classification == "CRITICAL"
    assert result.notify is True


# ---------------------------------------------------------------------------
# INFO rules (17-22) — notify=False
# ---------------------------------------------------------------------------


def test_classify_port_creation_fail(sample_port_creation_failure_log: str) -> None:
    """Rule PORT_CREATION_FAIL: BCMDPA_L1_PORT_CREATION_FAILURE → INFO."""
    result = classify(_parse(sample_port_creation_failure_log))
    assert result.rule_id == "PORT_CREATION_FAIL"
    assert result.classification == "INFO"
    assert result.notify is False


def test_classify_operation_stalled(sample_operation_stalled_log: str) -> None:
    """Rule OPERATION_STALLED: GLOBAL_OPERATION_STALLED → INFO."""
    result = classify(_parse(sample_operation_stalled_log))
    assert result.rule_id == "OPERATION_STALLED"
    assert result.classification == "INFO"
    assert result.notify is False


def test_classify_hw_event_ok(sample_hw_event_log: str) -> None:
    """Rule HW_EVENT_OK: HW_EVENT … HW_EVENT_OK → INFO."""
    result = classify(_parse(sample_hw_event_log))
    assert result.rule_id == "HW_EVENT_OK"
    assert result.classification == "INFO"
    assert result.notify is False


def test_classify_eem_commit(sample_eem_commit_log: str) -> None:
    """Rule EEM_COMMIT: DB_COMMIT … event_manager_user → INFO."""
    result = classify(_parse(sample_eem_commit_log))
    assert result.rule_id == "EEM_COMMIT"
    assert result.classification == "INFO"
    assert result.notify is False


def test_classify_eem_script(sample_eem_script_log: str) -> None:
    """Rule EEM_SCRIPT: ACTION_SYSLOG_LOG_INFO → INFO."""
    result = classify(_parse(sample_eem_script_log))
    assert result.rule_id == "EEM_SCRIPT"
    assert result.classification == "INFO"
    assert result.notify is False


def test_classify_nsr_disabled(sample_nsr_disabled_log: str) -> None:
    """Rule NSR_DISABLED: NBR_NSR_DISABLED_STANDBY → INFO."""
    result = classify(_parse(sample_nsr_disabled_log))
    assert result.rule_id == "NSR_DISABLED"
    assert result.classification == "INFO"
    assert result.notify is False


# ---------------------------------------------------------------------------
# USER_LOGIN rules (23-25) — notify=False
# ---------------------------------------------------------------------------


def test_classify_ssh_login(sample_ssh_login_log: str) -> None:
    """Rule SSH_LOGIN: SSHD-6-INFO_SUCCESS → USER_LOGIN."""
    result = classify(_parse(sample_ssh_login_log))
    assert result.rule_id == "SSH_LOGIN"
    assert result.classification == "USER_LOGIN"
    assert result.notify is False


def test_classify_ssh_logout(sample_ssh_logout_log: str) -> None:
    """Rule SSH_LOGOUT: SSHD-6-INFO_USER_LOGOUT → USER_LOGIN."""
    result = classify(_parse(sample_ssh_logout_log))
    assert result.rule_id == "SSH_LOGOUT"
    assert result.classification == "USER_LOGIN"
    assert result.notify is False


def test_classify_config_commit_user(sample_config_commit_user_log: str) -> None:
    """Rule CONFIG_COMMIT_USER: DB_COMMIT (non-EEM user) → USER_LOGIN."""
    result = classify(_parse(sample_config_commit_user_log))
    assert result.rule_id == "CONFIG_COMMIT_USER"
    assert result.classification == "USER_LOGIN"
    assert result.notify is False


# ---------------------------------------------------------------------------
# Priority tests
# ---------------------------------------------------------------------------


def test_rule_priority_bgp_down_before_up(
    sample_bgp_down_log: str, sample_bgp_up_log: str
) -> None:
    """BGP_DOWN must be listed before BGP_UP (both match ADJCHANGE)."""
    down_idx = next(i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "BGP_DOWN")
    up_idx = next(i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "BGP_UP")
    assert down_idx < up_idx, "BGP_DOWN must precede BGP_UP in the rules list"

    # Also verify correct runtime behaviour
    assert classify(_parse(sample_bgp_down_log)).rule_id == "BGP_DOWN"
    assert classify(_parse(sample_bgp_up_log)).rule_id == "BGP_UP"


def test_eem_before_config_commit(
    sample_eem_commit_log: str, sample_config_commit_user_log: str
) -> None:
    """EEM_COMMIT (rule 20) must come before CONFIG_COMMIT_USER (rule 25).

    Both match DB_COMMIT; EEM_COMMIT additionally requires event_manager_user.
    The EEM log must resolve to EEM_COMMIT, not CONFIG_COMMIT_USER.
    The non-EEM log must resolve to CONFIG_COMMIT_USER.
    """
    eem_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "EEM_COMMIT"
    )
    commit_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "CONFIG_COMMIT_USER"
    )
    assert eem_idx < commit_idx, "EEM_COMMIT must precede CONFIG_COMMIT_USER"

    assert classify(_parse(sample_eem_commit_log)).rule_id == "EEM_COMMIT"
    assert (
        classify(_parse(sample_config_commit_user_log)).rule_id == "CONFIG_COMMIT_USER"
    )


def test_intf_down_before_up(
    sample_intf_down_log: str, sample_interface_up_log: str
) -> None:
    """INTF_DOWN must be listed before INTF_UP (both match LINK-3-UPDOWN)."""
    down_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "INTF_DOWN"
    )
    up_idx = next(i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "INTF_UP")
    assert down_idx < up_idx, "INTF_DOWN must precede INTF_UP in the rules list"

    assert classify(_parse(sample_intf_down_log)).rule_id == "INTF_DOWN"
    assert classify(_parse(sample_interface_up_log)).rule_id == "INTF_UP"


def test_lineproto_down_before_up(
    sample_lineproto_down_log: str, sample_lineproto_up_log: str
) -> None:
    """LINEPROTO_DOWN must be listed before LINEPROTO_UP."""
    down_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "LINEPROTO_DOWN"
    )
    up_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "LINEPROTO_UP"
    )
    assert down_idx < up_idx, "LINEPROTO_DOWN must precede LINEPROTO_UP"

    assert classify(_parse(sample_lineproto_down_log)).rule_id == "LINEPROTO_DOWN"
    assert classify(_parse(sample_lineproto_up_log)).rule_id == "LINEPROTO_UP"


def test_lacp_expired_before_active(
    sample_lacp_expired_log: str, sample_lacp_active_log: str
) -> None:
    """LACP_EXPIRED must be listed before LACP_ACTIVE (both match BM-6-ACTIVE)."""
    expired_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "LACP_EXPIRED"
    )
    active_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "LACP_ACTIVE"
    )
    assert expired_idx < active_idx, "LACP_EXPIRED must precede LACP_ACTIVE"

    assert classify(_parse(sample_lacp_expired_log)).rule_id == "LACP_EXPIRED"
    assert classify(_parse(sample_lacp_active_log)).rule_id == "LACP_ACTIVE"


def test_sfp_alarm_set_before_clear(
    sample_sfp_alarm_set_log: str, sample_sfp_alarm_clear_log: str
) -> None:
    """SFP_ALARM_SET must be listed before SFP_ALARM_CLEAR."""
    set_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "SFP_ALARM_SET"
    )
    clear_idx = next(
        i for i, r in enumerate(CLASSIFICATION_RULES) if r.id == "SFP_ALARM_CLEAR"
    )
    assert set_idx < clear_idx, "SFP_ALARM_SET must precede SFP_ALARM_CLEAR"

    assert classify(_parse(sample_sfp_alarm_set_log)).rule_id == "SFP_ALARM_SET"
    assert classify(_parse(sample_sfp_alarm_clear_log)).rule_id == "SFP_ALARM_CLEAR"


# ---------------------------------------------------------------------------
# Default / fallback classification
# ---------------------------------------------------------------------------


def test_default_classification_returns_info_for_unknown() -> None:
    """An unrecognised raw log string classified directly returns INFO/UNKNOWN."""
    # We need a ParsedLog with a raw line that matches no rule.
    # Craft a valid-looking but unmatched log:
    unknown_raw = (
        "May 22 10:00:00 192.168.200.1 12345: RP/0/RP0/CPU0:"
        "May 22 10:00:00 : someproc[999]: "
        "%TOTALLY-UNKNOWN-9-NOMATCHING : this log line matches no rule at all"
    )
    parsed = parse_syslog(unknown_raw)
    assert parsed is not None
    result = classify(parsed)
    assert result.rule_id == "UNKNOWN"
    assert result.classification == "INFO"
    assert result.notify is False


# ---------------------------------------------------------------------------
# Notify flag bulk checks
# ---------------------------------------------------------------------------


def test_notify_flag_all_critical_rules_true() -> None:
    """Every rule with classification=='CRITICAL' must have notify=True."""
    critical_rules = [r for r in CLASSIFICATION_RULES if r.classification == "CRITICAL"]
    assert len(critical_rules) == 15, "Expected exactly 15 CRITICAL rules"
    for rule in critical_rules:
        assert rule.notify is True, f"Rule {rule.id} is CRITICAL but notify=False"


def test_notify_flag_non_critical_rules_false() -> None:
    """WARNING / INFO / USER_LOGIN rules must all have notify=False."""
    non_critical = [r for r in CLASSIFICATION_RULES if r.classification != "CRITICAL"]
    for rule in non_critical:
        assert rule.notify is False, (
            f"Rule {rule.id} ({rule.classification}) has notify=True"
            " but should be False"
        )


# ---------------------------------------------------------------------------
# ClassificationResult structure
# ---------------------------------------------------------------------------


def test_classification_result_has_required_fields(sample_bgp_down_log: str) -> None:
    """ClassificationResult exposes all required fields."""
    result = classify(_parse(sample_bgp_down_log))
    assert hasattr(result, "rule_id")
    assert hasattr(result, "classification")
    assert hasattr(result, "event_type")
    assert hasattr(result, "notify")
    assert hasattr(result, "summary_template")


def test_classification_result_is_frozen(sample_bgp_down_log: str) -> None:
    """ClassificationResult dataclass should be immutable (frozen=True)."""
    result = classify(_parse(sample_bgp_down_log))
    with pytest.raises((AttributeError, TypeError)):
        result.rule_id = "TAMPERED"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Error handling — graceful None input
# ---------------------------------------------------------------------------


def test_classify_none_input_returns_default() -> None:
    """Passing None to classify() must return the default result, not crash."""
    result = classify(None)  # type: ignore[arg-type]
    assert result.rule_id == "UNKNOWN"
    assert result.classification == "INFO"
    assert result.notify is False


# ---------------------------------------------------------------------------
# RFI_FAULT rule — positive match + false-positive guard
# ---------------------------------------------------------------------------


def test_classify_rfi_fault() -> None:
    """Synthetic RFI log classifies as RFI_FAULT/CRITICAL."""
    rfi_raw = (
        "May 22 16:00:01 192.168.200.11 52501: LC/0/0/CPU0:"
        "May 22 16:00:26.000 +06: optics_driver[165]: "
        "%PLATFORM-RFI-2-FAULT : Interface TenGigE0/0/0/1, "
        "Detected Remote Fault Indication"
    )
    parsed = parse_syslog(rfi_raw)
    assert parsed is not None, "parse_syslog returned None for RFI_FAULT sample"
    result = classify(parsed)
    assert result.rule_id == "RFI_FAULT"
    assert result.classification == "CRITICAL"
    assert result.notify is True


def test_classify_rfi_no_false_positive_on_rfid() -> None:
    """A log containing 'RFID' must NOT match the RFI_FAULT rule (word boundary)."""
    rfid_raw = (
        "May 22 16:00:01 192.168.200.11 52502: LC/0/0/CPU0:"
        "May 22 16:00:26.000 +06: inventory[165]: "
        "%PLATFORM-RFID-6-READ : RFID tag read successfully on module 0/0"
    )
    parsed = parse_syslog(rfid_raw)
    assert parsed is not None, "parse_syslog returned None for RFID sample"
    result = classify(parsed)
    # RFID must NOT match RFI_FAULT
    assert result.rule_id != "RFI_FAULT"
