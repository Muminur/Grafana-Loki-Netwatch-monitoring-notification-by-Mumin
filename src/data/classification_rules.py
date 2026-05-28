"""Classification rules for BSCCL NetWatch syslog classifier.

26 rules evaluated top-to-bottom; first match wins.

Rule ordering is critical:
  - BGP_DOWN   before BGP_UP   (both match ADJCHANGE)
  - INTF_DOWN  before INTF_UP  (both match LINK-3-UPDOWN)
  - LINEPROTO_DOWN before LINEPROTO_UP (both match LINEPROTO-5-UPDOWN)
  - LACP_EXPIRED  before LACP_ACTIVE  (both match BM-6-ACTIVE)
  - SFP_ALARM_SET before SFP_ALARM_CLEAR (both match LOW_RX_POWER_ALARM)
  - EEM_COMMIT (rule 20) before CONFIG_COMMIT_USER (rule 25) — EEM is more specific
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ClassificationRule:
    """A single classification rule.

    Attributes:
        id:               Unique identifier, e.g. ``"BGP_DOWN"``.
        pattern:          Regex matched against the raw syslog line.
        classification:   One of CRITICAL / WARNING / INFO / USER_LOGIN.
        event_type:       Human-readable event description.
        notify:           ``True`` → send Discord/Telegram notification.
        extract:          Field names to extract (reserved for enricher).
        summary_template: Jinja-style template for notification text.
        _compiled:        Compiled regex (excluded from hashing/equality).
    """

    id: str
    pattern: str
    classification: str
    event_type: str
    notify: bool
    extract: tuple[str, ...]
    summary_template: str

    def compiled(self) -> re.Pattern[str]:
        """Return a compiled regex for this rule's pattern."""
        return re.compile(self.pattern)


# ---------------------------------------------------------------------------
# Pre-compile all patterns at module load for performance
# ---------------------------------------------------------------------------


def _rule(
    id: str,  # noqa: A002
    pattern: str,
    classification: str,
    event_type: str,
    notify: bool,
    extract: list[str] | None = None,
    summary_template: str = "",
) -> ClassificationRule:
    return ClassificationRule(
        id=id,
        pattern=pattern,
        classification=classification,
        event_type=event_type,
        notify=notify,
        extract=tuple(extract or []),
        summary_template=summary_template,
    )


# ---------------------------------------------------------------------------
# Rules — ordered list, first match wins
# ---------------------------------------------------------------------------

CLASSIFICATION_RULES: list[ClassificationRule] = [
    # ── CRITICAL (rules 1-10, notify=True) ──────────────────────────────────
    #
    # 1. BGP peer went Down — must come BEFORE BGP_UP (both match ADJCHANGE)
    _rule(
        id="BGP_DOWN",
        pattern=r"%ROUTING-BGP-5-ADJCHANGE.*\bDown\b",
        classification="CRITICAL",
        event_type="BGP Peer Down",
        notify=True,
        extract=["neighbor", "as_number", "vrf"],
        summary_template="{device}: BGP peer {neighbor} Down (AS {as_number})",
    ),
    # 2. BGP max-prefix limit reached — CRITICAL path protection alert
    _rule(
        id="BGP_MAXPFX",
        pattern=r"%ROUTING-BGP-5-MAXPFX",
        classification="CRITICAL",
        event_type="BGP Max Prefix Reached",
        notify=True,
        extract=["neighbor", "prefix_count", "max_prefixes"],
        summary_template=(
            "{device}: BGP max-prefix on {neighbor} ({prefix_count}/{max_prefixes})"
        ),
    ),
    # 3. LACP bundle member expired — must come BEFORE LACP_ACTIVE (both
    #    match BM-6-ACTIVE)
    _rule(
        id="LACP_EXPIRED",
        pattern=r"%L2-BM-6-ACTIVE.*no longer Active",
        classification="CRITICAL",
        event_type="LACP Bundle Member Expired",
        notify=True,
        extract=["interface", "bundle"],
        summary_template="{device}: {interface} LACP expired, left {bundle}",
    ),
    # 4. Remote fault on physical interface — must come BEFORE LOCAL_FAULT
    _rule(
        id="REMOTE_FAULT",
        pattern=r"%PLATFORM-DPA-2-RX_FAULT.*Remote Fault",
        classification="CRITICAL",
        event_type="Remote Fault Detected",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Remote Fault on {interface}",
    ),
    # 5. Local fault on physical interface
    _rule(
        id="LOCAL_FAULT",
        pattern=r"%PLATFORM-DPA-2-RX_FAULT.*Local Fault",
        classification="CRITICAL",
        event_type="Local Fault Detected",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Local Fault on {interface}",
    ),
    # 5b. RFI (Remote Fault Indication) — different facility than RX_FAULT
    _rule(
        id="RFI_FAULT",
        pattern=r"-RFI\b.*Detected.*Fault",
        classification="CRITICAL",
        event_type="Fault Detected (RFI)",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Fault detected (RFI) on {interface}",
    ),
    # 6. Optical signal failure
    _rule(
        id="SIGNAL_FAILURE",
        pattern=r"%PLATFORM-VIC-4-SIGNAL.*Signal failure",
        classification="CRITICAL",
        event_type="Signal Failure",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Signal failure on {interface}",
    ),
    # 7. SFP low-rx-power alarm SET — must come BEFORE SFP_ALARM_CLEAR
    _rule(
        id="SFP_ALARM_SET",
        pattern=r"%PLATFORM-SFP-2-LOW_RX_POWER_ALARM.*\bSet\b",
        classification="CRITICAL",
        event_type="SFP Alarm Set",
        notify=True,
        extract=["interface"],
        summary_template="{device}: SFP low-rx-power alarm SET on {interface}",
    ),
    # 8. Duplicate IPv6 address detected
    _rule(
        id="DUPLICATE_IPV6",
        pattern=r"%IP-IPV6_ND-3-ADDRESS_DUPLICATE",
        classification="CRITICAL",
        event_type="Duplicate IPv6 Address",
        notify=True,
        extract=["address", "interface"],
        summary_template="{device}: Duplicate IPv6 {address} on {interface}",
    ),
    # 9. Interface link state → Down — must come BEFORE INTF_UP
    _rule(
        id="INTF_DOWN",
        pattern=r"%PKT_INFRA-LINK-3-UPDOWN.*changed state to Down",
        classification="CRITICAL",
        event_type="Interface Down",
        notify=True,
        extract=["interface"],
        summary_template="{device}: {interface} changed state to Down",
    ),
    # 10. Line protocol → Down — must come BEFORE LINEPROTO_UP
    _rule(
        id="LINEPROTO_DOWN",
        pattern=r"%PKT_INFRA-LINEPROTO-5-UPDOWN.*changed state to Down",
        classification="CRITICAL",
        event_type="Line Protocol Down",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Line protocol on {interface} changed state to Down",
    ),
    # ── WARNING (rules 11-16, notify=False) ─────────────────────────────────
    #
    # 11. BER clear — signal quality recovered
    _rule(
        id="BER_CLEAR",
        pattern=r"%PLATFORM-PLAT_VETHER_DRIVER-3-REPORT_BER_CLEAR",
        classification="WARNING",
        event_type="BER Clear",
        notify=False,
        extract=["interface"],
        summary_template="{device}: BER clear on {interface}",
    ),
    # 12. BGP peer came Up (recovery — still CRITICAL for NOC visibility)
    _rule(
        id="BGP_UP",
        pattern=r"%ROUTING-BGP-5-ADJCHANGE.*\bUp\b",
        classification="CRITICAL",
        event_type="BGP Peer Up",
        notify=True,
        extract=["neighbor", "as_number", "vrf"],
        summary_template="{device}: BGP peer {neighbor} Up (AS {as_number})",
    ),
    # 13. Interface link state → Up (recovery — still CRITICAL for NOC visibility)
    _rule(
        id="INTF_UP",
        pattern=r"%PKT_INFRA-LINK-3-UPDOWN.*changed state to Up",
        classification="CRITICAL",
        event_type="Interface Up",
        notify=True,
        extract=["interface"],
        summary_template="{device}: {interface} changed state to Up",
    ),
    # 14. Line protocol → Up (recovery — still CRITICAL for NOC visibility)
    _rule(
        id="LINEPROTO_UP",
        pattern=r"%PKT_INFRA-LINEPROTO-5-UPDOWN.*changed state to Up",
        classification="CRITICAL",
        event_type="Line Protocol Up",
        notify=True,
        extract=["interface"],
        summary_template="{device}: Line protocol on {interface} changed state to Up",
    ),
    # 15. SFP low-rx-power alarm CLEARED
    _rule(
        id="SFP_ALARM_CLEAR",
        pattern=r"%PLATFORM-SFP-2-LOW_RX_POWER_ALARM.*\bClear\b",
        classification="WARNING",
        event_type="SFP Alarm Clear",
        notify=False,
        extract=["interface"],
        summary_template="{device}: SFP low-rx-power alarm CLEARED on {interface}",
    ),
    # 16. LACP bundle member became Active (recovery — CRITICAL for NOC visibility)
    _rule(
        id="LACP_ACTIVE",
        pattern=r"%L2-BM-6-ACTIVE.*(?:is|now) Active",
        classification="CRITICAL",
        event_type="LACP Bundle Member Active",
        notify=True,
        extract=["interface", "bundle"],
        summary_template="{device}: {interface} Active in {bundle}",
    ),
    # ── INFO (rules 17-22, notify=False) ────────────────────────────────────
    #
    # 17. EQ-RTR-01 known hardware issue — HundredGigE0/3/2/2 LC fault
    _rule(
        id="PORT_CREATION_FAIL",
        pattern=r"%PLATFORM-VEEA-3-BCMDPA_L1_PORT_CREATION_FAILURE",
        classification="INFO",
        event_type="Port Creation Failure",
        notify=False,
        extract=["interface"],
        summary_template=(
            "{device}: Port creation failure on {interface} (known LC fault)"
        ),
    ),
    # 18. EQ-RTR-01 known issue — operation retries (LC/0/3 fault)
    _rule(
        id="OPERATION_STALLED",
        pattern=r"%PKT_INFRA-GIRO-3-GLOBAL_OPERATION_STALLED",
        classification="INFO",
        event_type="Operation Stalled",
        notify=False,
        extract=[],
        summary_template="{device}: Global operation stalled (pending retries)",
    ),
    # 19. Hardware shelf manager OK event (ADMIN plane)
    _rule(
        id="HW_EVENT_OK",
        pattern=r"%INFRA-SHELF_MGR-6-HW_EVENT.*HW_EVENT_OK",
        classification="INFO",
        event_type="HW Event OK",
        notify=False,
        extract=[],
        summary_template="{device}: HW_EVENT_OK from shelf manager",
    ),
    # 20. EEM automation script config commit — MUST precede CONFIG_COMMIT_USER
    #     (more specific: requires 'event_manager_user' in the raw line)
    _rule(
        id="EEM_COMMIT",
        pattern=r"%MGBL-CONFIG-6-DB_COMMIT.*event_manager_user",
        classification="INFO",
        event_type="EEM Config Commit",
        notify=False,
        extract=[],
        summary_template="{device}: EEM automation config commit",
    ),
    # 21. EEM script action syslog message
    _rule(
        id="EEM_SCRIPT",
        pattern=r"%HA-HA_EEM-6-ACTION_SYSLOG_LOG_INFO",
        classification="INFO",
        event_type="EEM Script",
        notify=False,
        extract=[],
        summary_template="{device}: EEM script action",
    ),
    # 22. BGP NSR disabled on standby RP (follows BGP down, informational)
    _rule(
        id="NSR_DISABLED",
        pattern=r"%ROUTING-BGP-5-NBR_NSR_DISABLED_STANDBY",
        classification="INFO",
        event_type="NSR Disabled",
        notify=False,
        extract=["neighbor"],
        summary_template="{device}: NSR disabled for {neighbor} on standby RP",
    ),
    # ── USER_LOGIN (rules 23-25, notify=False) ───────────────────────────────
    #
    # 23. SSH authentication success
    _rule(
        id="SSH_LOGIN",
        pattern=r"%SECURITY-SSHD-6-INFO_SUCCESS",
        classification="USER_LOGIN",
        event_type="SSH Login",
        notify=False,
        extract=["user", "source_ip", "vty"],
        summary_template="{device}: SSH login by {user} from {source_ip}",
    ),
    # 24. SSH session logout
    _rule(
        id="SSH_LOGOUT",
        pattern=r"%SECURITY-SSHD-6-INFO_USER_LOGOUT",
        classification="USER_LOGIN",
        event_type="SSH Logout",
        notify=False,
        extract=["user", "source_ip", "vty"],
        summary_template="{device}: SSH logout by {user} from {source_ip}",
    ),
    # 25. Config commit by a real user — must come AFTER EEM_COMMIT (rule 20)
    _rule(
        id="CONFIG_COMMIT_USER",
        pattern=r"%MGBL-CONFIG-6-DB_COMMIT",
        classification="USER_LOGIN",
        event_type="Config Commit by User",
        notify=False,
        extract=["user"],
        summary_template="{device}: Config committed by {user}",
    ),
]

# Pre-compile all patterns at module level for performance.
_COMPILED_RULES: list[tuple[re.Pattern[str], ClassificationRule]] = [
    (re.compile(rule.pattern), rule) for rule in CLASSIFICATION_RULES
]
