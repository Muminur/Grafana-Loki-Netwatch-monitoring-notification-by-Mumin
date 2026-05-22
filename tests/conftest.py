"""Shared test fixtures for BSCCL NetWatch test suite."""

import pytest


@pytest.fixture
def sample_bgp_down_log() -> str:
    """CRITICAL - BGP Down (EQ-RTR-01, TCLOUD AS399077)."""
    return (
        "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
        "Down - BGP Notification received, maximum number of prefixes "
        "reached (VRF: network) (AS: 399077)"
    )


@pytest.fixture
def sample_bgp_down_sggs_log() -> str:
    """CRITICAL - BGP Down (EQ-RTR-01, SG.GS AS24482)."""
    return (
        "May 22 19:11:04 192.168.203.1 9238456: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:May 22 19:11:04.680 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::2:4482:1 "
        "Down - BGP Notification received, maximum number of prefixes "
        "reached (VRF: network) (AS: 24482)"
    )


@pytest.fixture
def sample_maxpfx_log() -> str:
    """CRITICAL - Max Prefix (KKT-Core-2, F@H) - BDT timezone format."""
    return (
        "May 22 20:42:24 192.168.202.130 395444: RP/0/RSP1/CPU0:"
        "May 22 20:42:24.749 BDT: bgp[1087]: %ROUTING-BGP-5-MAXPFX : "
        "No. of IPv4 Unicast prefixes received from 163.47.83.6 has "
        "reached 782, max 1000"
    )


@pytest.fixture
def sample_lacp_expired_log() -> str:
    """CRITICAL - LACP Expired (KKT-Core-2, F@H Bundle) - BDT timezone."""
    return (
        "May 22 19:33:37 192.168.202.130 395436: RP/0/RSP1/CPU0:"
        "May 22 19:33:37.787 BDT: BM-DISTRIB[1294]: %L2-BM-6-ACTIVE : "
        "TenGigE0/0/1/7 is no longer Active as part of Bundle-Ether201 "
        "(Link is Expired; LACPDUs are not being received from the partner)"
    )


@pytest.fixture
def sample_remote_fault_log() -> str:
    """CRITICAL - Remote Fault (DHK-Core-3)."""
    return (
        "May 22 15:23:04 192.168.200.11 52474: LC/0/0/CPU0:"
        "May 22 15:23:29.243 +06: fia_driver[165]: "
        "%PLATFORM-DPA-2-RX_FAULT : Interface TenGigE0/0/0/0, "
        "Detected Remote Fault"
    )


@pytest.fixture
def sample_signal_failure_log() -> str:
    """CRITICAL - Signal Failure (KKT-Core-1) - BDT timezone."""
    return (
        "May 22 15:23:04 192.168.202.2 17138436: LC/0/0/CPU0:"
        "May 22 15:23:04.884 BDT: vic_1_0[262]: "
        "%PLATFORM-VIC-4-SIGNAL : Interface TenGigE0/0/1/6, "
        "Detected Signal failure"
    )


@pytest.fixture
def sample_duplicate_ipv6_log() -> str:
    """CRITICAL - Duplicate IPv6 (COX-Core-1)."""
    return (
        "May 22 12:57:51 192.168.200.8 29308: LC/0/0/CPU0:"
        "May 22 12:57:51 : ipv6_nd[251]: "
        "%IP-IPV6_ND-3-ADDRESS_DUPLICATE : Duplicate address "
        "2406:4b00:4:4::1 has been detected on Bundle-Ether191"
    )


@pytest.fixture
def sample_sfp_alarm_set_log() -> str:
    """CRITICAL - SFP Alarm Set (COX-Core-1)."""
    return (
        "May 22 05:27:59 192.168.200.8 29146: LC/0/0/CPU0:"
        "May 22 05:27:59 : pfm_node_lc[298]: "
        "%PLATFORM-SFP-2-LOW_RX_POWER_ALARM : "
        "Set|envmon_lc[172121]|0x1029004|GigE0/0/0/4"
    )


@pytest.fixture
def sample_ber_clear_log() -> str:
    """WARNING - BER Clear (DHK-Core-3)."""
    return (
        "May 22 15:22:35 192.168.200.11 52464: LC/0/0/CPU0:"
        "May 22 15:22:59.610 +06: fia_driver[165]: "
        "%PLATFORM-PLAT_VETHER_DRIVER-3-REPORT_BER_CLEAR : "
        "Interface TenGigE0/0/0/0 : SF-BER is less than the "
        "threshold limit for the BER level [e^-8]"
    )


@pytest.fixture
def sample_bgp_up_log() -> str:
    """WARNING - BGP Up recovery (EQ-RTR-01)."""
    return (
        "May 22 19:11:24 192.168.203.1 9238458: BSCCL-EQ-RTR-01 "
        "RP/0/RP0/CPU0:May 22 19:11:24.816 +06: bgp[1097]: "
        "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
        "Up (VRF: network) (AS: 399077)"
    )


@pytest.fixture
def sample_interface_up_log() -> str:
    """WARNING - Interface Up (DHK-Core-3)."""
    return (
        "May 22 11:15:38 192.168.200.11 52376: LC/0/0/CPU0:"
        "May 22 11:16:02.886 +06: ifmgr[213]: "
        "%PKT_INFRA-LINK-3-UPDOWN : Interface TenGigE0/0/0/0, "
        "changed state to Up"
    )


@pytest.fixture
def sample_sfp_alarm_clear_log() -> str:
    """WARNING - SFP Alarm Clear (COX-Core-1)."""
    return (
        "May 22 12:57:48 192.168.200.8 29298: LC/0/0/CPU0:"
        "May 22 12:57:48 : pfm_node_lc[298]: "
        "%PLATFORM-SFP-2-LOW_RX_POWER_ALARM : "
        "Clear|envmon_lc[172121]|0x1029004|GigE0/0/0/4"
    )


@pytest.fixture
def sample_port_creation_failure_log() -> str:
    """INFO - Port Creation Failure (EQ-RTR-01 known issue)."""
    return (
        "May 22 20:31:50 192.168.203.1 9238658: BSCCL-EQ-RTR-01 "
        "LC/0/3/CPU0:May 22 20:31:50.165 +06: eth_intf_ea[178]: "
        "%PLATFORM-VEEA-3-BCMDPA_L1_PORT_CREATION_FAILURE : "
        "bcmdpa l1 port create failed, ifname: HundredGigE0_3_2_2, unit:0"
    )


@pytest.fixture
def sample_operation_stalled_log() -> str:
    """INFO - Stalled Operation (EQ-RTR-01 known issue)."""
    return (
        "May 22 20:12:37 192.168.203.1 9238620: BSCCL-EQ-RTR-01 "
        "LC/0/3/CPU0:May 22 20:12:37.633 +06: eth_intf_ma[314]: "
        "%PKT_INFRA-GIRO-3-GLOBAL_OPERATION_STALLED : "
        "Pending operation(s) (IM operation of type Interface Create) "
        "have retried unsuccessfully at least 51650 times"
    )


@pytest.fixture
def sample_hw_event_log() -> str:
    """INFO - HW Event OK (DHK-Core-3) - ADMIN plane format."""
    return (
        "May 22 20:22:37 192.168.200.11 52534: 0/RP0/ADMIN0:"
        "May 22 20:23:02.420 +06: shelf_mgr[2117]: "
        "%INFRA-SHELF_MGR-6-HW_EVENT : Rcvd HW event HW_EVENT_OK, "
        "event_reason_str 'HW Operational' for card 0/PM3"
    )


@pytest.fixture
def sample_eem_commit_log() -> str:
    """INFO - EEM Script commit (COX-Core-1 automation)."""
    return (
        "May 22 10:49:36 192.168.200.8 29214: RP/0/RSP0/CPU0:"
        "May 22 10:49:36 : config[65923]: "
        "%MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user "
        "'event_manager_user'. Use 'show configuration commit changes "
        "1000013644' to view the changes."
    )


@pytest.fixture
def sample_nsr_disabled_log() -> str:
    """INFO - NSR Disabled (EQ-RTR-01, follows BGP down)."""
    return (
        "May 22 19:11:04 192.168.203.1 9238454: BSCCL-EQ-RTR-01 "
        "RP/0/RP1/CPU0:May 22 19:11:04.681 +06: bgp[1097]: "
        "%ROUTING-BGP-5-NBR_NSR_DISABLED_STANDBY : NSR disabled on "
        "neighbor 2001:de8:4::2:4482:1 on standby RP due to BGP "
        "Notification received (VRF: network)"
    )


@pytest.fixture
def sample_ssh_login_log() -> str:
    """USER_LOGIN - SSH login (DHK-Core-3)."""
    return (
        "May 22 21:00:31 192.168.200.11 52536: RP/0/RP0/CPU0:"
        "May 22 21:00:56.247 +06: SSHD_[68879]: "
        "%SECURITY-SSHD-6-INFO_SUCCESS : Successfully authenticated "
        "user 'rancid' from '192.168.200.56' on 'vty0'"
        "(cipher 'chacha20-poly1305@openssh.com', mac 'chacha20-poly1305')"
    )


@pytest.fixture
def sample_ssh_logout_log() -> str:
    """USER_LOGIN - SSH logout (DHK-Core-3)."""
    return (
        "May 22 19:00:50 192.168.200.11 52514: RP/0/RP0/CPU0:"
        "May 22 19:01:14.971 +06: SSHD_[67192]: "
        "%SECURITY-SSHD-6-INFO_USER_LOGOUT : User 'rancid' from "
        "'192.168.200.56' logged out on 'vty0'"
    )
