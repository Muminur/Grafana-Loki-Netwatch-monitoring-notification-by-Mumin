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
# CRITICAL rules — parametrized table (rule_id, fixture, classification,
# notify).  All CRITICAL rules must have notify=True.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_id"),
    [
        ("sample_bgp_down_log", "BGP_DOWN"),
        ("sample_maxpfx_log", "BGP_MAXPFX"),
        ("sample_lacp_expired_log", "LACP_EXPIRED"),
        ("sample_remote_fault_log", "REMOTE_FAULT"),
        ("sample_local_fault_log", "LOCAL_FAULT"),
        ("sample_signal_failure_log", "SIGNAL_FAILURE"),
        ("sample_sfp_alarm_set_log", "SFP_ALARM_SET"),
        ("sample_duplicate_ipv6_log", "DUPLICATE_IPV6"),
        ("sample_intf_down_log", "INTF_DOWN"),
        ("sample_lineproto_down_log", "LINEPROTO_DOWN"),
        ("sample_bgp_up_log", "BGP_UP"),
        ("sample_interface_up_log", "INTF_UP"),
        ("sample_lineproto_up_log", "LINEPROTO_UP"),
        ("sample_lacp_active_log", "LACP_ACTIVE"),
    ],
    ids=[
        "bgp-down",
        "bgp-maxpfx",
        "lacp-expired",
        "remote-fault",
        "local-fault",
        "signal-failure",
        "sfp-alarm-set",
        "duplicate-ipv6",
        "intf-down",
        "lineproto-down",
        "bgp-up",
        "intf-up",
        "lineproto-up",
        "lacp-active",
    ],
)
def test_classify_critical_rules(
    fixture_name: str,
    expected_rule_id: str,
    request: pytest.FixtureRequest,
) -> None:
    """Every CRITICAL rule fires on its corresponding log sample with notify=True."""
    raw: str = request.getfixturevalue(fixture_name)
    result = classify(_parse(raw))
    assert isinstance(result, ClassificationResult)
    assert result.rule_id == expected_rule_id
    assert result.classification == "CRITICAL"
    assert result.notify is True


# ---------------------------------------------------------------------------
# WARNING rules — parametrized table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_id"),
    [
        ("sample_ber_clear_log", "BER_CLEAR"),
        ("sample_sfp_alarm_clear_log", "SFP_ALARM_CLEAR"),
    ],
    ids=["ber-clear", "sfp-alarm-clear"],
)
def test_classify_warning_rules(
    fixture_name: str,
    expected_rule_id: str,
    request: pytest.FixtureRequest,
) -> None:
    """Every WARNING rule fires on its corresponding log sample with notify=False."""
    raw: str = request.getfixturevalue(fixture_name)
    result = classify(_parse(raw))
    assert isinstance(result, ClassificationResult)
    assert result.rule_id == expected_rule_id
    assert result.classification == "WARNING"
    assert result.notify is False


# ---------------------------------------------------------------------------
# INFO rules — parametrized table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_id"),
    [
        ("sample_port_creation_failure_log", "PORT_CREATION_FAIL"),
        ("sample_operation_stalled_log", "OPERATION_STALLED"),
        ("sample_hw_event_log", "HW_EVENT_OK"),
        ("sample_eem_commit_log", "EEM_COMMIT"),
        ("sample_eem_script_log", "EEM_SCRIPT"),
        ("sample_nsr_disabled_log", "NSR_DISABLED"),
    ],
    ids=[
        "port-creation-fail",
        "operation-stalled",
        "hw-event-ok",
        "eem-commit",
        "eem-script",
        "nsr-disabled",
    ],
)
def test_classify_info_rules(
    fixture_name: str,
    expected_rule_id: str,
    request: pytest.FixtureRequest,
) -> None:
    """Every INFO rule fires on its corresponding log sample with notify=False."""
    raw: str = request.getfixturevalue(fixture_name)
    result = classify(_parse(raw))
    assert isinstance(result, ClassificationResult)
    assert result.rule_id == expected_rule_id
    assert result.classification == "INFO"
    assert result.notify is False


# ---------------------------------------------------------------------------
# USER_LOGIN rules — parametrized table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_id"),
    [
        ("sample_ssh_login_log", "SSH_LOGIN"),
        ("sample_ssh_logout_log", "SSH_LOGOUT"),
        ("sample_config_commit_user_log", "CONFIG_COMMIT_USER"),
    ],
    ids=["ssh-login", "ssh-logout", "config-commit-user"],
)
def test_classify_user_login_rules(
    fixture_name: str,
    expected_rule_id: str,
    request: pytest.FixtureRequest,
) -> None:
    """Every USER_LOGIN rule fires on its corresponding log sample with notify=False."""
    raw: str = request.getfixturevalue(fixture_name)
    result = classify(_parse(raw))
    assert isinstance(result, ClassificationResult)
    assert result.rule_id == expected_rule_id
    assert result.classification == "USER_LOGIN"
    assert result.notify is False


# ---------------------------------------------------------------------------
# Priority tests — ordering constraints within the rule list
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
# Word-boundary false-positive regression tests — parametrized table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "forbidden_rule_id", "description"),
    [
        (
            (
                "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
                "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
                "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
                "Downloading update (VRF: network) (AS: 399077)"
            ),
            "BGP_DOWN",
            "BGP_DOWN must NOT match 'Downloading'",
        ),
        (
            (
                "May 22 05:27:59 192.168.200.8 29146: LC/0/0/CPU0:"
                "May 22 05:27:59 : pfm_node_lc[298]: "
                "%PLATFORM-SFP-2-LOW_RX_POWER_ALARM : "
                "Setting|envmon_lc[172121]|0x1029004|GigE0/0/0/4"
            ),
            "SFP_ALARM_SET",
            "SFP_ALARM_SET must NOT match 'Setting'",
        ),
        (
            (
                "May 22 19:11:24 192.168.203.1 9238458: BSCCL-EQ-RTR-01 "
                "RP/0/RP0/CPU0:May 22 19:11:24.816 +06: bgp[1097]: "
                "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
                "Upload complete (VRF: network) (AS: 399077)"
            ),
            "BGP_UP",
            "BGP_UP must NOT match 'Upload'",
        ),
        (
            (
                "May 22 12:57:48 192.168.200.8 29298: LC/0/0/CPU0:"
                "May 22 12:57:48 : pfm_node_lc[298]: "
                "%PLATFORM-SFP-2-LOW_RX_POWER_ALARM : "
                "Cleared|envmon_lc[172121]|0x1029004|GigE0/0/0/4"
            ),
            "SFP_ALARM_CLEAR",
            "SFP_ALARM_CLEAR must NOT match 'Cleared'",
        ),
    ],
    ids=[
        "bgp-down-no-false-positive-downloading",
        "sfp-alarm-set-no-false-positive-setting",
        "bgp-up-no-false-positive-upload",
        "sfp-alarm-clear-no-false-positive-cleared",
    ],
)
def test_word_boundary_false_positives(
    raw: str, forbidden_rule_id: str, description: str
) -> None:
    """Word-boundary guard: near-match strings must NOT trigger the named rule."""
    result = classify(_parse(raw))
    assert result.rule_id != forbidden_rule_id, description


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
