"""Interface-to-description mapping for all BSCCL network devices."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class InterfaceInfo:
    """Description and parent bundle for a network interface."""

    description: str
    bundle: str | None


_UNDERSCORE_RE = re.compile(r"(?<=[a-zA-Z0-9])_(?=\d)")


def _normalize_interface(name: str) -> str:
    """Normalize underscores between type and slot numbers to slashes."""
    return _UNDERSCORE_RE.sub("/", name)


INTERFACE_MAP: dict[str, dict[str, InterfaceInfo]] = {
    "BSCCL-CGS-TEJ-01": {
        "Ethernet1/1": InterfaceInfo("FIREWALL-UPLINK", None),
        "Ethernet1/10": InterfaceInfo(
            "TRUNK-PORT-AGG-RTR-TenGigE0/6/1/3", "port-channel550"
        ),
        "Ethernet1/11": InterfaceInfo("AGG-02-TenGigE0/3/1/5", "port-channel550"),
        "Ethernet1/13": InterfaceInfo("CLOUDFLARE-OBB", None),
        "Ethernet1/14": InterfaceInfo("TRUNK-TO-LAN-01", None),
        "Ethernet1/15": InterfaceInfo("SKYTEL-TEJ", None),
        "Ethernet1/16": InterfaceInfo("BDREN-ISP-SECONDARY-VLAN-520", None),
        "Ethernet1/17": InterfaceInfo("EQUITEL", None),
        "Ethernet1/19": InterfaceInfo("PEEREX-CWDM-01", "port-channel518"),
        "Ethernet1/2": InterfaceInfo("SERVER_SET_2_VLAN999", None),
        "Ethernet1/20": InterfaceInfo("TRUNK-BTCL-MOG-E1/2-BTCL-TR", "port-channel560"),
        "Ethernet1/21": InterfaceInfo("DHKLINK-02", None),
        "Ethernet1/22": InterfaceInfo("TRUNK-BTCL-MOG-E1/1-BTCL-TR", "port-channel560"),
        "Ethernet1/23": InterfaceInfo("TRUNK-F@H-MOG-LINK-1", "port-channel560"),
        "Ethernet1/24": InterfaceInfo("TRUNK-F@H-MOG-LINK-2", "port-channel560"),
        "Ethernet1/25": InterfaceInfo("LINK3-ISP", None),
        "Ethernet1/27": InterfaceInfo("BDREN-PRIMARY-1", "port-channel519"),
        "Ethernet1/28": InterfaceInfo("BDREN-PRIMARY-2", "port-channel519"),
        "Ethernet1/29": InterfaceInfo("VELOCITY-TEJ-2", "port-channel451"),
        "Ethernet1/3": InterfaceInfo("SERVER_SET_2_VLAN999", None),
        "Ethernet1/30": InterfaceInfo("ADN-ISP-TEJGAO-PRI", None),
        "Ethernet1/31": InterfaceInfo("ADN-ISP-TEJGAO-SEC", None),
        "Ethernet1/32": InterfaceInfo("VELOCITY-TEJ-1", "port-channel451"),
        "Ethernet1/33": InterfaceInfo("DHKLINK-LINK-01", None),
        "Ethernet1/34": InterfaceInfo("EXABYTE-IPT-10Gb-TEJ-01", "port-channel903"),
        "Ethernet1/35": InterfaceInfo("ICT-TOWER", None),
        "Ethernet1/36": InterfaceInfo("EXABYTE-IPT-10Gb-TEJ-02", "port-channel903"),
        "Ethernet1/38": InterfaceInfo("SSONLINE-CDN-2Gb-PEERING", None),
        "Ethernet1/39": InterfaceInfo("KHAJA-LINK-01", "port-channel570"),
        "Ethernet1/4": InterfaceInfo("SERVER_SET_2_VLAN999", None),
        "Ethernet1/40": InterfaceInfo("KHAJA-LINK-02", "port-channel570"),
        "Ethernet1/41": InterfaceInfo("KHAJA-LINK-03", "port-channel570"),
        "Ethernet1/42": InterfaceInfo("KHAJA-LINK-04", "port-channel570"),
        "Ethernet1/43": InterfaceInfo("KHAJA-LINK-01-CWDM-02", "port-channel570"),
        "Ethernet1/44": InterfaceInfo("KHAJA-LINK-02-CWDM-02", "port-channel570"),
        "Ethernet1/45": InterfaceInfo("TO-NEXUS-01", None),
        "Ethernet1/46": InterfaceInfo("TO-BSCIX-ROUTE-SERVER", None),
        "Ethernet1/47": InterfaceInfo(
            "SUMMIT-Link-01-DHAKACOLO_CGS-Eth1/48-bscl_040124_001_nc-ODF-9/44",
            "port-channel570",
        ),
        "Ethernet1/48": InterfaceInfo(
            "SUMMIT-Link-02-DHAKACOLO_CGS-Eth1/47-bscl_040124_002_nc-ODF-9/20",
            "port-channel570",
        ),
        "Ethernet1/5": InterfaceInfo("CAMERA-NVR-INTERNET", None),
        "Ethernet1/51": InterfaceInfo("BAISHAN-LINK-1", "port-channel120"),
        "Ethernet1/52": InterfaceInfo("FROM-DHK-CORE-03-100G-LINK-01", None),
        "Ethernet1/53": InterfaceInfo("CLOUDFLARE-LINK-1", "port-channel420"),
        "Ethernet1/6": InterfaceInfo(
            "TRUNK-PORT-AGG-RTR-TenGigE0/5/0/18", "port-channel550"
        ),
        "Ethernet1/7": InterfaceInfo(
            "TRUNK-PORT-AGG-RTR-TenGigE0/6/0/1", "port-channel550"
        ),
        "Ethernet1/8": InterfaceInfo(
            "TRUNK-PORT-AGG-RTR-TenGigE0/7/0/1", "port-channel550"
        ),
        "Ethernet1/9": InterfaceInfo("NOVOCOM-TEJ", None),
        "Vlan200": InterfaceInfo("Management-VLAN", None),
        "port-channel120": InterfaceInfo("PO-BAISHAN", None),
        "port-channel420": InterfaceInfo("PO-CLOUDFLARE", None),
        "port-channel451": InterfaceInfo("VELOCITY-TEJ", None),
        "port-channel517": InterfaceInfo("PEEREX-IIG-DDoS", None),
        "port-channel518": InterfaceInfo("PEEREX-IIG-PRIMARY-CWDM", None),
        "port-channel519": InterfaceInfo("PO-BDREN-PRI", None),
        "port-channel522": InterfaceInfo("NEXUS-CGS-LACP", None),
        "port-channel550": InterfaceInfo("BUNDLE-TO-DHK-AGG-01", None),
        "port-channel552": InterfaceInfo("EARTH-IIG-PORT-channel", None),
        "port-channel560": InterfaceInfo("BUNDLE-TO-MOGHBAZAR-BTCL-POP", None),
        "port-channel570": InterfaceInfo("BUNDLE-TO-KHAJA-POP", None),
        "port-channel580": InterfaceInfo("ICT-TOWER", None),
    },
    "BSCCL-COX-CORE-01": {
        "Bundle-Ether100": InterfaceInfo("Subscriber-facing end", None),
        "Bundle-Ether13": InterfaceInfo("TO-COX-RTR-03", None),
        "Bundle-Ether13.104": InterfaceInfo("TO-COX-RTR-03-VRF-LEVEL-2-VPN", None),
        "Bundle-Ether13.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether13.2": InterfaceInfo("TO-COX-RTR-03-VRF-NETWORK", None),
        "Bundle-Ether13.3": InterfaceInfo("TO-COX-RTR-03-VRF-MGMT", None),
        "Bundle-Ether13.4": InterfaceInfo("TO-COX-RTR-03-VRF-PNI", None),
        "Bundle-Ether155": InterfaceInfo("TEST-LACP-CTG", None),
        "Bundle-Ether160": InterfaceInfo("BSCCL-COX-CTG-BH", None),
        "Bundle-Ether160.602": InterfaceInfo("COL-ISP-CTG-SEC", None),
        "Bundle-Ether160.607": InterfaceInfo("COL-ISP-CTG-BE", None),
        "Bundle-Ether160.608": InterfaceInfo("TELETALK-CTG-PRIMARY", None),
        "Bundle-Ether160.609": InterfaceInfo("TELETALK-CTG-SECONDARY", None),
        "Bundle-Ether170": InterfaceInfo("BSCCL-COX-CTG-BH", None),
        "Bundle-Ether170.602": InterfaceInfo("COL-ISP-CTG-SEC", None),
        "Bundle-Ether170.607": InterfaceInfo("COL-ISP-CTG-BE", None),
        "Bundle-Ether170.608": InterfaceInfo("TELETALK-CTG-PRIMARY", None),
        "Bundle-Ether170.609": InterfaceInfo("TELETALK-CTG-SECONDARY", None),
        "Bundle-Ether180": InterfaceInfo("CONNECTED-TO-NEXUS-SW", None),
        "Bundle-Ether180.701": InterfaceInfo("SUMMIT-COX-CTG-BE-NEXUS", None),
        "Bundle-Ether180.702": InterfaceInfo("test", None),
        "Bundle-Ether190": InterfaceInfo("COL-ISP-COX", None),
        "Bundle-Ether191": InterfaceInfo("COX-LINKIT-ISP-BE", None),
        "Bundle-Ether193": InterfaceInfo("DELTA-IIG-BE", None),
        "Bundle-Ether193.708": InterfaceInfo("DELTA-IPT-PEERING", None),
        "Bundle-Ether193.713": InterfaceInfo("DELTA-LD-PEERING", None),
        "Bundle-Ether200": InterfaceInfo("Network-facing end", None),
        "Bundle-Ether251": InterfaceInfo("TEST-BE", None),
        "Bundle-Ether300": InterfaceInfo("BUNDLE-TO-COX-NUXUS-SW", None),
        "Bundle-Ether300.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether300.2130": InterfaceInfo("GFCL-IPT", None),
        "Bundle-Ether300.2131": InterfaceInfo("GFCL-LD", None),
        "Bundle-Ether301": InterfaceInfo("BE-GFCL", None),
        "Bundle-Ether301.2130": InterfaceInfo("GFCL-IPT", None),
        "Bundle-Ether301.2131": InterfaceInfo("GFCL-LD", None),
        "Bundle-Ether313": InterfaceInfo("BDHUB-IIG-BE", None),
        "Bundle-Ether313.206": InterfaceInfo("BDHUB-LD-PEERING", None),
        "Bundle-Ether313.207": InterfaceInfo("BDHUB-IPT-PEERING", None),
        "GigabitEthernet0/0/0/4": InterfaceInfo(
            "COX-LINKIT-ISP-PRI", "Bundle-Ether191"
        ),
        "GigabitEthernet0/0/0/5": InterfaceInfo("COX-CLS-INTERNET-new", None),
        "GigabitEthernet0/0/1/10": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/41", None),
        "GigabitEthernet0/0/1/11": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/42", None),
        "GigabitEthernet0/0/1/12": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/43", None),
        "GigabitEthernet0/0/1/13": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/44", None),
        "GigabitEthernet0/0/1/14": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/45", None),
        "GigabitEthernet0/0/1/15": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/46", None),
        "GigabitEthernet0/0/1/16": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/47", None),
        "GigabitEthernet0/0/1/17": InterfaceInfo("CONNECTED-TO-COX-NX-Eth1/48", None),
        "GigabitEthernet0/0/1/18": InterfaceInfo("TRUNK-TO-COX-SW", None),
        "GigabitEthernet0/0/1/18.104": InterfaceInfo("TO-SMW4-MONITORING-L2", None),
        "GigabitEthernet0/0/1/18.301": InterfaceInfo("CC-NVR-COX", None),
        "GigabitEthernet0/0/1/19": InterfaceInfo("COX-IIG-Terminal", None),
        "GigabitEthernet0/0/1/2": InterfaceInfo(
            "COX-LINKIT-ISP-SEC", "Bundle-Ether191"
        ),
        "HundredGigE0/7/0/0": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-RTR-O2", "Bundle-Ether13"
        ),
        "Loopback1": InterfaceInfo("VRF-NETWORK", None),
        "Loopback10": InterfaceInfo("ROUTE_TEST", None),
        "Loopback3": InterfaceInfo("VRF-MGMT", None),
        "MgmtEth0/RSP0/CPU0/0": InterfaceInfo(
            '"Connected to BSCCL-LAN-SW-02 GE- 0/6"', None
        ),
        "TenGigE0/2/0/0": InterfaceInfo("To-BSCCL-SCE-02", "Bundle-Ether100"),
        "TenGigE0/2/0/1": InterfaceInfo("DELTA-IIG-LINK-01", "Bundle-Ether193"),
        "TenGigE0/2/0/2": InterfaceInfo("COX-BACKHAUL-LINK-01-STM64-BTCL", None),
        "TenGigE0/2/0/3": InterfaceInfo("COX-DHK-BAHON-LINK-02", None),
        "TenGigE0/2/1/0": InterfaceInfo("From-BSCCL-SCE-02", "Bundle-Ether200"),
        "TenGigE0/2/1/1": InterfaceInfo("COX-DHK-BAHON-LINK-01", None),
        "TenGigE0/2/1/2": InterfaceInfo("BDHUB-IIG-LINK-01", "Bundle-Ether313"),
        "TenGigE0/2/1/3": InterfaceInfo(
            "FOR-COX-DHK-BH-LINK-03-NEW-SUMMIT-DHK-Te0/3/1/4", None
        ),
        "TenGigE0/5/0/0": InterfaceInfo("BDHUB-IIG-LINK-02", "Bundle-Ether313"),
        "TenGigE0/5/0/1": InterfaceInfo("BSCCL-COX-CTG-BH-F@H-DWDM", "Bundle-Ether170"),
        "TenGigE0/5/1/0": InterfaceInfo("BDHUB-IIG-LINK-03", "Bundle-Ether313"),
        "TenGigE0/5/1/1": InterfaceInfo("DELTA-IIG-LINK-04", "Bundle-Ether193"),
        "TenGigE0/7/1/0": InterfaceInfo("DELTA-IIG-LINK-02", "Bundle-Ether193"),
        "TenGigE0/7/1/1": InterfaceInfo("BSCCL-COX-CTG-BH-SUMMIT", "Bundle-Ether170"),
        "TenGigE0/7/1/2": InterfaceInfo("COL-LD", None),
        "TenGigE0/7/1/2.3202": InterfaceInfo("COL-LD-PEERING", None),
        "TenGigE0/7/1/3": InterfaceInfo("CONNECTED-TO-NX-E1/41", "Bundle-Ether300"),
        "TenGigE0/7/1/4": InterfaceInfo("CONNECTED-TO-NX-E1/42", "Bundle-Ether300"),
        "TenGigE0/7/1/5": InterfaceInfo("GFCL-10G-LINK-01", "Bundle-Ether301"),
        "TenGigE0/7/1/6": InterfaceInfo("DELTA-IIG-LINK-03", "Bundle-Ether193"),
        "TenGigE0/7/1/7": InterfaceInfo("GFCL-10G-LINK-02", "Bundle-Ether301"),
        "preconfigure POS0/7/0/0": InterfaceInfo("TIS-MARSEILLE-10GE-02-LINK", None),
    },
    "BSCCL-COX-CORE-02": {
        "Bundle-Ether185": InterfaceInfo("HE-SMW4-ETHER-BUNDLE", None),
        "Bundle-Ether190": InterfaceInfo("CONNECTED-TO-NEXUS-SW", None),
        "Bundle-Ether190.2130": InterfaceInfo("GFCL-IPT", None),
        "Bundle-Ether190.601": InterfaceInfo("GREENMAX-IIG-COX-BLACKHOLE", None),
        "Bundle-Ether190.602": InterfaceInfo("GREENMAX-IIG-COX-MAIN", None),
        "Bundle-Ether190.703": InterfaceInfo("FatH-IIG-COX-BE", None),
        "Bundle-Ether190.704": InterfaceInfo("FatH-IIG-COX-BE-BLACKHOLE", None),
        "Bundle-Ether190.708": InterfaceInfo("DELTA-IIG-COX-F@H-BH", None),
        "Bundle-Ether190.710": InterfaceInfo("PEEREX-9.5G", None),
        "Bundle-Ether190.711": InterfaceInfo("REGO-IIG", None),
        "Bundle-Ether190.712": InterfaceInfo("REGO-IIG-BLACKHOLE", None),
        "Bundle-Ether24": InterfaceInfo("TO-COX-RTR-04", None),
        "Bundle-Ether24.2": InterfaceInfo("TO-COX-RTR-04-BE", None),
        "Bundle-Ether43": InterfaceInfo("TO-COX-RTR-03", None),
        "Bundle-Ether43.2": InterfaceInfo("TO-COX-RTR-03-VRF-NETWORK", None),
        "Bundle-Ether500": InterfaceInfo("TO-EQ-RTR-02", None),
        "HundredGigE0/7/0/0": InterfaceInfo(
            "CONNECTED-TO-COX-RTR-04", "Bundle-Ether43"
        ),
        "Loopback0": InterfaceInfo('"Internal IGP/OSPF Purpose"', None),
        "MgmtEth0/RSP0/CPU0/0": InterfaceInfo(
            '"Connected to BSCCL-LAN-SW-02 GE-0/4"', None
        ),
        "MgmtEth0/RSP1/CPU0/0": InterfaceInfo('"Backup Management Port"', None),
        "TenGigE0/1/0/0": InterfaceInfo("PEEREX-3432", None),
        "TenGigE0/1/0/1": InterfaceInfo(
            "TO-COX-02-EQ-02-LINK-01-ORANGE-BH-02-10G (COX/TUS/10GE/(LAN PHY)/054/M)",
            "Bundle-Ether500",
        ),
        "TenGigE0/1/0/2": InterfaceInfo(
            "EQ-02-LINK-3-ORANGE-BH-03(LD020853)-COX/TUS/10GE (LAN PHY)/041/M",
            "Bundle-Ether500",
        ),
        "TenGigE0/1/0/3": InterfaceInfo(
            "EQ-02-LINK-02 (COX/TUS/10GE/(LAN PHY)/016/M)", "Bundle-Ether500"
        ),
        "TenGigE0/1/1/0": InterfaceInfo(
            "LINK-06-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/1/1/1": InterfaceInfo(
            "EQ-02-LINK-06-ORANGE-BH-06-10G(COX/TUS/10GE(LAN PHY)/037/M)-EQ-02--EQ-02-Te0/0/0/4",
            "Bundle-Ether500",
        ),
        "TenGigE0/4/0/0": InterfaceInfo(
            "EQ-02-ORANGE-BH-05-10G(COX/TUS/10GE(LAN PHY)/015/M)", "Bundle-Ether500"
        ),
        "TenGigE0/4/0/1": InterfaceInfo(
            "EQ-02-LINK-01 (COX/TUS/10GE/(LAN PHY)/022/M)", "Bundle-Ether500"
        ),
        "TenGigE0/7/1/0": InterfaceInfo(
            "LINK-01-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/7/1/1": InterfaceInfo(
            "LINK-03-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/7/1/2": InterfaceInfo(
            "LINK-04-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/7/1/3": InterfaceInfo(
            "EQ-02-LINK-04-ORANGE-BH-04-LD020854 (COX/TUS/10GE/(LAN PHY)/042/M)",
            "Bundle-Ether500",
        ),
        "TenGigE0/7/1/4": InterfaceInfo(
            "TO-EQ-02-LINK-07-ORANGE-BH-01-10G (COX/TUS/10GE/(LAN PHY)/043/M)",
            "Bundle-Ether500",
        ),
        "TenGigE0/7/1/5": InterfaceInfo(
            "LINK-07-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/7/1/6": InterfaceInfo(
            "LINK-05-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "TenGigE0/7/1/7": InterfaceInfo(
            "LINK-02-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "preconfigure TenGigE0/1/1/2": InterfaceInfo("PEEREX-IIG-COX", None),
        "preconfigure TenGigE0/1/1/3": InterfaceInfo(
            "LINK-02-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "preconfigure TenGigE0/4/1/0": InterfaceInfo(
            "LINK-01-CONNECTED-TO-COX-NEXUS-SW", "Bundle-Ether190"
        ),
        "preconfigure TenGigE0/4/1/3": InterfaceInfo(
            "TO-EQ-02-LINK-09-ORANGE-BH-05-10G(COX/TUS/10GE(LAN PHY)/015/M)-EQ-02-Te0/0/0/3",
            "Bundle-Ether500",
        ),
    },
    "BSCCL-COX-NEXUS-01": {
        "Ethernet1/11": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-02-port-TenGigE0/7/1/5", "port-channel190"
        ),
        "Ethernet1/13": InterfaceInfo("PEEREX", None),
        "Ethernet1/14": InterfaceInfo("GREENMAX-PRI", None),
        "Ethernet1/17": InterfaceInfo("REGO-IIG-COX-01", "port-channel711"),
        "Ethernet1/18": InterfaceInfo("REGO-IIG-COX-02", "port-channel711"),
        "Ethernet1/2": InterfaceInfo("CONNECTED-TO-COX-CORE-02", "port-channel190"),
        "Ethernet1/21": InterfaceInfo("PEEREX-9.5G", None),
        "Ethernet1/24": InterfaceInfo("GFCL-LINK-01", "port-channel705"),
        "Ethernet1/25": InterfaceInfo("GFCL-LINK-02-new", "port-channel705"),
        "Ethernet1/3": InterfaceInfo("CONNECTED-TO-COX-CORE-02", "port-channel190"),
        "Ethernet1/36": InterfaceInfo("CONNECTED-TO-SMW4-L2-1550", None),
        "Ethernet1/37": InterfaceInfo("TO-COX-CGS-NEXUS-01", None),
        "Ethernet1/38": InterfaceInfo("TO-COX-03-Te0/0/0/9", "port-channel171"),
        "Ethernet1/39": InterfaceInfo("TO-COX-03-Te0/0/0/10", "port-channel171"),
        "Ethernet1/40": InterfaceInfo("TO-COX-03-Te0/0/0/11", "port-channel171"),
        "Ethernet1/41": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-01-Gi0/0/1/10", "port-channel200"
        ),
        "Ethernet1/42": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-01-Gi0/0/1/11", "port-channel200"
        ),
        "Ethernet1/5": InterfaceInfo("CONNECTED-TO-COX-CORE-02", "port-channel190"),
        "Ethernet1/6": InterfaceInfo("CONNECTED-TO-COX-CORE-02", "port-channel190"),
        "Ethernet1/7": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-02-TenGigE0/1/1/2", "port-channel190"
        ),
        "Ethernet1/8": InterfaceInfo(
            "CONNECTED-TO-COX-CORE-02-Te0/7/1/6", "port-channel190"
        ),
        "port-channel171": InterfaceInfo("BE-COX-CORE-03", None),
        "port-channel190": InterfaceInfo("BUNDLE-TO-COX-CORE-02", None),
        "port-channel200": InterfaceInfo("BUNDLE-TO-COX-CORE-01", None),
        "port-channel700": InterfaceInfo("WINDSTREAM-COX-MAIN", None),
        "port-channel701": InterfaceInfo("SUMMIT-IIG-COX", None),
        "port-channel704": InterfaceInfo("EXABYTE-COX-PO", None),
        "port-channel705": InterfaceInfo("PO-GFCL", None),
        "port-channel711": InterfaceInfo("PO-REGO", None),
    },
    "BSCCL-DHKCOLO-CGS-01": {
        "Ethernet1/10": InterfaceInfo("ADN GATEWAY-IIG", None),
        "Ethernet1/11": InterfaceInfo("VELOCITY-IIG-PRI", "port-channel418"),
        "Ethernet1/12": InterfaceInfo(
            "EXABYTE-LD-12G-DHKCOLO-PEERING", "port-channel423"
        ),
        "Ethernet1/13": InterfaceInfo(
            "EXABYTE-LD-12G-DHKCOLO-PEERING", "port-channel423"
        ),
        "Ethernet1/14": InterfaceInfo("VELOCITY-IIG-SEC", "port-channel418"),
        "Ethernet1/15": InterfaceInfo("VIRGO-IIG", None),
        "Ethernet1/16": InterfaceInfo("LINK3-ISP", None),
        "Ethernet1/19": InterfaceInfo("ISPAB-NIX-LINK-02", None),
        "Ethernet1/2": InterfaceInfo("SSONLINE-LINK-01", None),
        "Ethernet1/21": InterfaceInfo("ADN-ISP", None),
        "Ethernet1/23": InterfaceInfo("BDLINK", None),
        "Ethernet1/3": InterfaceInfo("FAULTY", None),
        "Ethernet1/32": InterfaceInfo("NOVOCOM-IIG-SEC", None),
        "Ethernet1/33": InterfaceInfo("TELNET", None),
        "Ethernet1/35": InterfaceInfo("EQUITEL-IIG-DHAKACOLO", None),
        "Ethernet1/36": InterfaceInfo("RACEONLINE-1", "port-channel654"),
        "Ethernet1/37": InterfaceInfo("RACEONLINE-2", "port-channel654"),
        "Ethernet1/38": InterfaceInfo("SSONLINE-NIX-LINK", None),
        "Ethernet1/43": InterfaceInfo("PEEREX-DC-LINK-01", "port-channel417"),
        "Ethernet1/44": InterfaceInfo("PEEREX-DC-LINK-02", "port-channel417"),
        "Ethernet1/47": InterfaceInfo(
            "SUMMIT-Link-02-TEJGAO_CGS-Eth1/48-bscl_040124_002_nc", "port-channel570"
        ),
        "Ethernet1/48": InterfaceInfo(
            "SUMMIT-Link-01-TEJGAO_CGS-Eth1/47-bscl_040124_001_nc", "port-channel570"
        ),
        "Ethernet1/5": InterfaceInfo("Faulty-Packet Loss", None),
        "Ethernet1/51": InterfaceInfo("CONNNECTED-TO-RTR-01", "port-channel655"),
        "Ethernet1/53": InterfaceInfo("CONNNECTED-TO-RTR-02", "port-channel655"),
        "Ethernet1/7": InterfaceInfo("SKYTEL-DHKCOLO", None),
        "port-channel414": InterfaceInfo("APPLE-IIG-Secondary-Po", None),
        "port-channel416": InterfaceInfo("OPTIMAX-SEC-AND-BH", None),
        "port-channel417": InterfaceInfo("PEEREX-PO", None),
        "port-channel418": InterfaceInfo("VELOCITY-IIG", None),
        "port-channel423": InterfaceInfo("EXABYTE", None),
        "port-channel570": InterfaceInfo("CONNECTED-TO-AGG-NX", None),
        "port-channel654": InterfaceInfo("PO-RACEONLINE", None),
        "port-channel655": InterfaceInfo("PO-RTR", None),
    },
    "BSCCL-EQ-RTR-01": {
        "Bundle-Ether200": InterfaceInfo("TO-COX-03-BE", None),
        "Bundle-Ether200.104": InterfaceInfo("TO-COX-03-VRF-LEVEL-2-VPN", None),
        "Bundle-Ether200.1333": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-2", None),
        "Bundle-Ether200.2": InterfaceInfo("TO-COX-03-VRF-NETWORK", None),
        "Bundle-Ether200.3": InterfaceInfo("TO-COX-03-VRF-MGMT", None),
        "Bundle-Ether200.4": InterfaceInfo("TO-COX-RTR-03-VRF-PNI", None),
        "Bundle-Ether200.610": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-02", None),
        "Bundle-Ether200.805": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN", None),
        "Bundle-Ether300": InterfaceInfo("TO-KKT-03-BE", None),
        "Bundle-Ether300.1": InterfaceInfo("TO-KKT-03-VRF-NETWORK", None),
        "Bundle-Ether40": InterfaceInfo("BE-TO-EQ-02-80G", None),
        "Bundle-Ether40.5": InterfaceInfo("TO-EQ-01-NETWORK-TO-EQ-02-PNI", None),
        "Bundle-Ether500": InterfaceInfo("TO-KKT-RTR-01", None),
        "Bundle-Ether500.1": InterfaceInfo("TO-KKT-01-VRF-NETWORK-eBGP", None),
        "Bundle-Ether500.104": InterfaceInfo("TO-KKT-01-VRF-LEVEL-2-VPN", None),
        "Bundle-Ether500.1333": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-2", None),
        "Bundle-Ether500.3": InterfaceInfo("TO-KKT-01-VRF-MGMT", None),
        "Bundle-Ether500.4": InterfaceInfo("TO-KKT-01-PNI", None),
        "Bundle-Ether500.610": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-02", None),
        "Bundle-Ether500.805": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN", None),
        "Bundle-Ether510": InterfaceInfo("BE-FACEBOOK", None),
        "Bundle-Ether511": InterfaceInfo("BE-SGIX", None),
        "Bundle-Ether515": InterfaceInfo("BE-EQUINIX-PNI", None),
        "Bundle-Ether520": InterfaceInfo("BE-ZENLAYER", None),
        "Bundle-Ether525": InterfaceInfo("BE-AMAZON-PNI-EQ-01", None),
        "Bundle-Ether526": InterfaceInfo("BE-CLOUDFLARE", None),
        "Bundle-Ether530": InterfaceInfo("GOOGLE-BE", None),
        "Bundle-Ether535": InterfaceInfo("RETN-BE", None),
        "Bundle-Ether540": InterfaceInfo("BE-NTT-20G", None),
        "Bundle-Ether600": InterfaceInfo("CONNTECTED-TO-EQ-RTR-02", None),
        "Bundle-Ether600.1": InterfaceInfo("VRF-NETWORK", None),
        "Bundle-Ether600.3": InterfaceInfo("VRF-MGMT", None),
        "Bundle-Ether600.4": InterfaceInfo("TO-EQ-02-PNI", None),
        "Bundle-Ether600.5": InterfaceInfo("TO-EQ-01-NETWORK-TO-EQ-02-PNI", None),
        "FortyGigE0/0/0/12": InterfaceInfo("TO-EQ-02-Fo0/0/0/12", "Bundle-Ether40"),
        "FortyGigE0/0/0/13": InterfaceInfo("TO-EQ-02-Fo0/0/0/13", "Bundle-Ether40"),
        "FortyGigE0/3/0/12": InterfaceInfo("TO-EQ-02-Fo0/3/0/12", "Bundle-Ether40"),
        "FortyGigE0/3/0/13": InterfaceInfo("TO-EQ-02-Fo0/3/0/13", "Bundle-Ether40"),
        "HundredGigE0/0/1/0": InterfaceInfo(
            "EQUINIX-IX-100G-EIE-01", "Bundle-Ether515"
        ),
        "HundredGigE0/0/1/1": InterfaceInfo("FACEBOOK-100G-PNI", "Bundle-Ether510"),
        "HundredGigE0/0/1/2": InterfaceInfo("BIGO-100G-PNI", None),
        "HundredGigE0/0/1/3": InterfaceInfo("CONNTECTED-TO-EQ-02", "Bundle-Ether600"),
        "HundredGigE0/0/2/0": InterfaceInfo("TO-SGIX-100G-LINK", "Bundle-Ether511"),
        "HundredGigE0/0/2/3": InterfaceInfo("TO-EQ-02-Hu0/3/2/3", "Bundle-Ether600"),
        "HundredGigE0/3/1/0": InterfaceInfo("GOOGLE-2ND-100G-LINK", "Bundle-Ether530"),
        "HundredGigE0/3/1/1": InterfaceInfo("TO-COX-03-100G-01", "Bundle-Ether200"),
        "HundredGigE0/3/1/2": InterfaceInfo("TO-COX-03-100G-02", "Bundle-Ether200"),
        "HundredGigE0/3/1/3": InterfaceInfo(
            "CONNTECTED-TO-EQ-02-LINK-02", "Bundle-Ether600"
        ),
        "Loopback1": InterfaceInfo("LOOPBAK-NETWORK-VRF", None),
        "Loopback3": InterfaceInfo("LOOPBACK-MGMT", None),
        "Loopback4": InterfaceInfo("LOOPBACK-PNI", None),
        "TenGigE0/0/0/0": InterfaceInfo("TO-KKT-01-LINK-01", "Bundle-Ether500"),
        "TenGigE0/0/0/1": InterfaceInfo("TO-KKT-01-LINK-07", "Bundle-Ether500"),
        "TenGigE0/0/0/10": InterfaceInfo("AMAZON-P3", "Bundle-Ether525"),
        "TenGigE0/0/0/11": InterfaceInfo("AMAZON-P4", "Bundle-Ether525"),
        "TenGigE0/0/0/2": InterfaceInfo("TO-KKT-01-LINK-03", "Bundle-Ether500"),
        "TenGigE0/0/0/3": InterfaceInfo("TO-KKT-01-LINK-04", "Bundle-Ether500"),
        "TenGigE0/0/0/4": InterfaceInfo("NTT-NEW-10G-01", "Bundle-Ether540"),
        "TenGigE0/0/0/5": InterfaceInfo("TO-KKT-01-LINK-02", "Bundle-Ether500"),
        "TenGigE0/0/0/6": InterfaceInfo("TO-KKT-01-LINK-05", "Bundle-Ether500"),
        "TenGigE0/0/0/7": InterfaceInfo("TO-KKT-01-LINK-06", "Bundle-Ether500"),
        "TenGigE0/0/0/8": InterfaceInfo("AMAZON-P1", "Bundle-Ether525"),
        "TenGigE0/0/0/9": InterfaceInfo("AMAZON-P2", "Bundle-Ether525"),
        "TenGigE0/3/0/0": InterfaceInfo("RETN-4TH-10G-LINK", "Bundle-Ether535"),
        "TenGigE0/3/0/1": InterfaceInfo("RETN-5TH-10G-LINK", None),
        "TenGigE0/3/0/10": InterfaceInfo("NTT-NEW-10G-02", "Bundle-Ether540"),
        "TenGigE0/3/0/11": InterfaceInfo("BDREN-1G", None),
        "TenGigE0/3/0/11.1333": InterfaceInfo("BDREN-L2-VPN-1333", None),
        "TenGigE0/3/0/11.610": InterfaceInfo("BDREN-TO-SINGREN-VRF-L2-VPN-02", None),
        "TenGigE0/3/0/11.805": InterfaceInfo("BDREN-TO-SINGREN-VRF-L2-VPN", None),
        "TenGigE0/3/0/2": InterfaceInfo(
            "TO-KKT-01-LINK-09-To-TenGigE0/5/1/3", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/3": InterfaceInfo(
            "TO-KKT-01-LINK-08 TenGigE0/0/1/7", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/8": InterfaceInfo(
            "TO-KKT-03-TE0/0/0/3-EQXC-22697434", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/9": InterfaceInfo(
            "TO-KKT-03-Te0/0/0/2-EQXC-22697432", "Bundle-Ether300"
        ),
        "preconfigure TenGigE0/3/0/19": InterfaceInfo("NTT-NEW-10G-02", None),
    },
    "BSCCL-EQ-RTR-02": {
        "Bundle-Ether210": InterfaceInfo("TO-COX-CORE-03", None),
        "Bundle-Ether210.2": InterfaceInfo("TO-COX-03-VRF-NETWORK", None),
        "Bundle-Ether40": InterfaceInfo("BE-TO-EQ-01-120G", None),
        "Bundle-Ether40.5": InterfaceInfo("TO-EQ-02-PNI-TO-EQ-01-NETWORK", None),
        "Bundle-Ether400": InterfaceInfo("TO-COX-RTR-04", None),
        "Bundle-Ether400.2": InterfaceInfo("TO-COX-RTR-04-VRF-NETWORK", None),
        "Bundle-Ether400.3": InterfaceInfo("TO-COX-RTR-04-VRFMGMT", None),
        "Bundle-Ether400.4": InterfaceInfo("TO-COX-RTR-04-VRF-PNI", None),
        "Bundle-Ether500": InterfaceInfo("TO-COX-RTR-02", None),
        "Bundle-Ether505": InterfaceInfo("TO-KKT-01", None),
        "Bundle-Ether505.1": InterfaceInfo("TO-KKT-01-VRF-NETWORK", None),
        "Bundle-Ether505.4": InterfaceInfo("TO-KKT-01-PNI", None),
        "Bundle-Ether515": InterfaceInfo("BE-EQUINIX-PNI", None),
        "Bundle-Ether520": InterfaceInfo("EQ-02-GOOGLE-100G", None),
        "Bundle-Ether521": InterfaceInfo("BE-ZENLAYER", None),
        "Bundle-Ether525": InterfaceInfo("BE-FACEBOOK-EQ-03", None),
        "Bundle-Ether530": InterfaceInfo("BE-AMAZON-PNI-EQ-02", None),
        "Bundle-Ether535": InterfaceInfo("BE-SGIX", None),
        "Bundle-Ether540": InterfaceInfo("BE-FACEBOOK-EQ-02", None),
        "Bundle-Ether541": InterfaceInfo("BE-HE", None),
        "Bundle-Ether542": InterfaceInfo("BE-CLOUDFLARE", None),
        "Bundle-Ether545": InterfaceInfo("BE-CMI-EQN-02", None),
        "Bundle-Ether550": InterfaceInfo("TO-COX-RTR-01", None),
        "Bundle-Ether550.1": InterfaceInfo("TO-COX-RTR-01-VRF-NETWORK", None),
        "Bundle-Ether600": InterfaceInfo("TO-EQ-RTR-01", None),
        "Bundle-Ether600.1": InterfaceInfo("TO-EQ-RTR-01-VRF-NETWORK", None),
        "Bundle-Ether600.3": InterfaceInfo("TO-EQ-RTR-01-VRF-MGMT", None),
        "Bundle-Ether600.4": InterfaceInfo("TO-EQ-RTR-01-PNI", None),
        "Bundle-Ether600.5": InterfaceInfo("TO-EQ-02-PNI-TO-EQ-01-NETWORK", None),
        "FortyGigE0/0/0/12": InterfaceInfo("TO-EQ-01-Fo0/0/0/12", "Bundle-Ether40"),
        "FortyGigE0/0/0/13": InterfaceInfo("TO-EQ-01-Fo0/0/0/13", "Bundle-Ether40"),
        "FortyGigE0/3/0/12": InterfaceInfo("TO-EQ-01-Fo0/3/0/12", "Bundle-Ether40"),
        "FortyGigE0/3/0/13": InterfaceInfo("TO-EQ-01-Fo0/3/0/13", "Bundle-Ether40"),
        "HundredGigE0/0/2/0": InterfaceInfo(
            "EQUINIX-IX-100G-EIE-02", "Bundle-Ether515"
        ),
        "HundredGigE0/0/2/1": InterfaceInfo("TO-KKT-02-100G-01", None),
        "HundredGigE0/0/2/1.101": InterfaceInfo("TO-KKT-02-VRF-NETWORK", None),
        "HundredGigE0/0/2/1.4": InterfaceInfo("TO-KKT-02-PNI", None),
        "HundredGigE0/0/2/2": InterfaceInfo("GOOGLE-100G-PNI-01", "Bundle-Ether520"),
        "HundredGigE0/0/2/3": InterfaceInfo(
            "CONNECTED-TO-EQ-01-LINK-01", "Bundle-Ether600"
        ),
        "HundredGigE0/3/1/0": InterfaceInfo("RETN-3-10G-LINK", None),
        "HundredGigE0/3/1/1": InterfaceInfo("FACEBOOK-2ND-100G-PNI", "Bundle-Ether540"),
        "HundredGigE0/3/1/2": InterfaceInfo("CONNECTED-TO-COX-03", "Bundle-Ether210"),
        "HundredGigE0/3/1/3": InterfaceInfo(
            "CONNECTED-TO-EQ-01-LINK-02", "Bundle-Ether600"
        ),
        "HundredGigE0/3/2/0": InterfaceInfo("TO-CLOUDFLARE", "Bundle-Ether542"),
        "HundredGigE0/3/2/1": InterfaceInfo(
            "TO-FACEBOOK-3RD-100G-FC-207674193", "Bundle-Ether525"
        ),
        "HundredGigE0/3/2/3": InterfaceInfo("TO-EQ-01-Hu0/0/2/3", "Bundle-Ether600"),
        "Loopback4": InterfaceInfo("LOOPBACK-PNI", None),
        "TenGigE0/0/0/1": InterfaceInfo("TO-COX-02-LINK-01", "Bundle-Ether500"),
        "TenGigE0/0/0/2": InterfaceInfo("TO-COX-02-LINK-02", "Bundle-Ether500"),
        "TenGigE0/0/0/3": InterfaceInfo(
            "TO-COX-02-LINK-09-ORANGE-BH-05(LD020855)-10G-Port-Te0/7/1/4",
            "Bundle-Ether500",
        ),
        "TenGigE0/0/0/4": InterfaceInfo(
            "TO-COX-02-LINK-10-ORANGE-BH-06(LD020856)-10G", "Bundle-Ether500"
        ),
        "TenGigE0/0/0/6": InterfaceInfo("TO-KKT-01-LINK-06", "Bundle-Ether505"),
        "TenGigE0/0/0/7": InterfaceInfo("CMI-1st-10G", "Bundle-Ether545"),
        "TenGigE0/0/0/8": InterfaceInfo("HE-7TH-10G", None),
        "TenGigE0/0/0/9": InterfaceInfo("NTT-3RD-10G", None),
        "TenGigE0/0/1/10": InterfaceInfo("TO-KKT-01-LINK-05", "Bundle-Ether505"),
        "TenGigE0/0/1/11": InterfaceInfo("SGIX-10G-01", "Bundle-Ether535"),
        "TenGigE0/0/1/2": InterfaceInfo("AMAZON-P1", "Bundle-Ether530"),
        "TenGigE0/0/1/3": InterfaceInfo("AMAZON-P2", "Bundle-Ether530"),
        "TenGigE0/0/1/4": InterfaceInfo("AMAZON-P3", "Bundle-Ether530"),
        "TenGigE0/0/1/5": InterfaceInfo("AMAZON-P4", "Bundle-Ether530"),
        "TenGigE0/0/1/6": InterfaceInfo("SGIX-10G-02", "Bundle-Ether535"),
        "TenGigE0/0/1/7": InterfaceInfo("TO-KKT-01-LINK-02", "Bundle-Ether505"),
        "TenGigE0/0/1/8": InterfaceInfo("TO-KKT-01-LINK-03", "Bundle-Ether505"),
        "TenGigE0/0/1/9": InterfaceInfo("TO-KKT-01-LINK-04", "Bundle-Ether505"),
        "TenGigE0/3/0/0": InterfaceInfo(
            "TO-COX-02-LINK-09-ORANGE-BH-05(LD020851)-10G-port-te0/5/1/0",
            "Bundle-Ether500",
        ),
        "TenGigE0/3/0/1": InterfaceInfo(
            "TO-COX-01-LINK-01-ORANGE-BH-02(LD020852)-10G", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/2": InterfaceInfo(
            "TO-COX-02-LINK-3-ORANGE-BH-03(LD020853)-10G", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/3": InterfaceInfo(
            "TO-COX-02-LINK-04-ORANGE-BH-04(LD020854)-10G", "Bundle-Ether500"
        ),
        "TenGigE0/3/0/4": InterfaceInfo("HE-184.104.212.92/30-LAG1", "Bundle-Ether541"),
        "TenGigE0/3/0/5": InterfaceInfo("CMI-2nd-10G", "Bundle-Ether545"),
        "TenGigE0/3/0/6": InterfaceInfo("CMI-3RD-10G", "Bundle-Ether545"),
        "TenGigE0/3/0/8": InterfaceInfo("ZENLAYER", "Bundle-Ether521"),
    },
    "BSCCL-KKT-CORE-RTR-01": {
        "Bundle-Ether100": InterfaceInfo("BE-KKT-CORE-RTR-01-TO-KKT-CORE-RTR-02", None),
        "Bundle-Ether100.1": InterfaceInfo("BE-VRF-NETWORK", None),
        "Bundle-Ether100.2": InterfaceInfo("BE-VRF-SUBSCRIBER", None),
        "Bundle-Ether100.3": InterfaceInfo("BE-VRF-MGMT", None),
        "Bundle-Ether150": InterfaceInfo(
            "BE-KKT-CORE-RTR-01-TO-KKT-CORE-RTR-02-VIA-200G", None
        ),
        "Bundle-Ether150.101": InterfaceInfo("BE-VRF-NETWORK", None),
        "Bundle-Ether150.102": InterfaceInfo("BE-VRF-SUBSCRIBER", None),
        "Bundle-Ether150.103": InterfaceInfo("BE-VRF-MGMT", None),
        "Bundle-Ether150.104": InterfaceInfo("TO-KKT-02-ADCN-L2-VPN", None),
        "Bundle-Ether150.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether150.4": InterfaceInfo("TO-KKT-02-PNI", None),
        "Bundle-Ether155": InterfaceInfo("BE-PCCW-LINK", None),
        "Bundle-Ether160": InterfaceInfo("REGO-IIG-BE", None),
        "Bundle-Ether160.1025": InterfaceInfo("REGO-IIG-MAIN", None),
        "Bundle-Ether160.1026": InterfaceInfo("REGO-IIG-BLACKHOLE", None),
        "Bundle-Ether165": InterfaceInfo("BE-RADIANT", None),
        "Bundle-Ether165.510": InterfaceInfo("RADIANT-LD", None),
        "Bundle-Ether170": InterfaceInfo("BE-WINDSTREAM", None),
        "Bundle-Ether170.3509": InterfaceInfo("WINDSTREAM-LD", None),
        "Bundle-Ether170.3511": InterfaceInfo("WINDSTREAM-RTBH", None),
        "Bundle-Ether250": InterfaceInfo("TEST", None),
        "Bundle-Ether400": InterfaceInfo("TO-DHK-CORE-03", None),
        "Bundle-Ether400.1": InterfaceInfo("BE-VRF-NETWORK", None),
        "Bundle-Ether400.104": InterfaceInfo("TO-DHK-03-ADCN-L2-VPN", None),
        "Bundle-Ether400.1333": InterfaceInfo(
            "BDREN-1333-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether400.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether400.2": InterfaceInfo("BE-VRF-SUBSCRIBER", None),
        "Bundle-Ether400.3": InterfaceInfo("BE-VRF-MGMT", None),
        "Bundle-Ether400.4": InterfaceInfo("TO-AGG-01-PNI", None),
        "Bundle-Ether400.610": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN-02", None
        ),
        "Bundle-Ether400.805": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether401": InterfaceInfo("test", None),
        "Bundle-Ether410": InterfaceInfo("KKT-DHK-BTCL-ZET-BE", None),
        "Bundle-Ether500": InterfaceInfo("TO-EQ-01", None),
        "Bundle-Ether500.1": InterfaceInfo("TO-EQ-01-VRF-NETWORK", None),
        "Bundle-Ether500.104": InterfaceInfo("TO-EQ-01-ADCN-L2-VPN", None),
        "Bundle-Ether500.1333": InterfaceInfo(
            "BDREN-1330-FROM-EQ-01-TO-KKT-01-L2-VPN", None
        ),
        "Bundle-Ether500.3": InterfaceInfo("TO-EQ-02-VRF-MGMT", None),
        "Bundle-Ether500.610": InterfaceInfo(
            "BDREN-FROM-EQ-01-TO-KKT-01-L2-VPN-02", None
        ),
        "Bundle-Ether500.805": InterfaceInfo("BDREN-FROM-EQ-01-TO-KKT-01-L2-VPN", None),
        "Bundle-Ether505": InterfaceInfo("TO-EQ-02", None),
        "Bundle-Ether505.1": InterfaceInfo("TO-EQ-02-VRF-NETWORK", None),
        "Bundle-Ether505.4": InterfaceInfo("TO-EQ-02-PNI", None),
        "HundredGigE0/0/0/0": InterfaceInfo("TO-KKT-CORE-02", "Bundle-Ether150"),
        "HundredGigE0/5/0/0": InterfaceInfo(
            "KKT-CORE-RTR-01-TO-KKT-CORE-RTR-02", "Bundle-Ether150"
        ),
        "HundredGigE0/5/0/1": InterfaceInfo(
            "KKT-CORE-RTR-01-TO-KKT-CORE-RTR-02-LINK-02", "Bundle-Ether150"
        ),
        "Loopback3": InterfaceInfo("LO-MGMT", None),
        "Loopback4": InterfaceInfo("LOOPBACK-PNI", None),
        "TenGigE0/0/1/0": InterfaceInfo(
            "EQ-02-LINK-05 (EQ3/KKT/10GLAN/0057)", "Bundle-Ether505"
        ),
        "TenGigE0/0/1/1": InterfaceInfo(
            "EQ-02-LINK-03 (EQ3/KKT/10GLAN/0055)", "Bundle-Ether505"
        ),
        "TenGigE0/0/1/3": InterfaceInfo(
            "KKT-DHK-LINK-03-VIA-BTCL-ZTE-BH-AGG-Te0/0/1/1", "Bundle-Ether400"
        ),
        "TenGigE0/0/1/5": InterfaceInfo(
            "EQ-ROUTER-01-LINK-01 (EQ3/KKT/10GLAN/0102)", "Bundle-Ether500"
        ),
        "TenGigE0/0/1/6": InterfaceInfo("KKT-DHK-PGCB-LINK-01", "Bundle-Ether400"),
        "TenGigE0/0/1/7": InterfaceInfo(
            "EQ-ROUTER-01-LINK-08 (EQ3/KKT/10GLAN/0088)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/0": InterfaceInfo(
            "KKT-DHK-LINK-01-VIA-BTCL-BH-DHK03-Te0/0/0/8-BTCL_MUX_PORT_112_.75", None
        ),
        "TenGigE0/1/0/1": InterfaceInfo(
            "KKT-DHK-LINK-02-VIA-BTCL-BH-DHK03-Te0/0/0/12/0", "Bundle-Ether400"
        ),
        "TenGigE0/1/0/10": InterfaceInfo(
            "EQ-ROUTER-01-LINK-05 (EQ3/KKT/10GLAN/0080)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/11": InterfaceInfo(
            "EQ-ROUTER-01-LINK-06 (EQ3/KKT/10GLAN/0081)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/13": InterfaceInfo(
            "PCCW-LINK-02 [EQ3/KKT/10GLAN/0144]", "Bundle-Ether155"
        ),
        "TenGigE0/1/0/15": InterfaceInfo(
            "KKT-DHK-LINK-VIA-F@H-BH-03-DHK03-Te0/0/0/2", "Bundle-Ether400"
        ),
        "TenGigE0/1/0/16": InterfaceInfo(
            "EQ-ROUTER-01-LINK-02 (EQ3/KKT/10GLAN/0103)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/17": InterfaceInfo(
            "EQ-ROUTER-01-LINK-03 (EQ3/KKT/10GLAN/0104)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/18": InterfaceInfo(
            "EQ-ROUTER-01-LINK-04 (EQ3/KKT/10GLAN/0105)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/2": InterfaceInfo(
            "KKT-DHK-LINK-02-VIA-SUMMIT-BH-DHK03-Te0/0/0/10", "Bundle-Ether400"
        ),
        "TenGigE0/1/0/20": InterfaceInfo(
            "EQ-02-LINK-02 (EQ3/KKT/10GLAN/0050)", "Bundle-Ether505"
        ),
        "TenGigE0/1/0/22": InterfaceInfo(
            "EQ-02-LINK-06 (EQ3/KKT/10GLAN/0033)", "Bundle-Ether505"
        ),
        "TenGigE0/1/0/23": InterfaceInfo(
            "KKT-DHK-LINK-04-VIA-F@H-BH-AGG-TenGigE0/0/0/0", "Bundle-Ether400"
        ),
        "TenGigE0/1/0/3": InterfaceInfo(
            "EQ-02-LINK-04 (EQ3/KKT/10GLAN/0016)", "Bundle-Ether505"
        ),
        "TenGigE0/1/0/4": InterfaceInfo(
            "EQ-ROUTER-01-LINK-07 (EQ3/KKT/10GLAN/0013)", "Bundle-Ether500"
        ),
        "TenGigE0/1/0/9": InterfaceInfo(
            "KKT-DHK-LINK-04-VIA-BTCL-BH-AGG-Te0/0/0/7-BTCL_MUX_PORT_111_.74",
            "Bundle-Ether400",
        ),
        "TenGigE0/5/1/0": InterfaceInfo("REGO-IIG-LINK-01", "Bundle-Ether160"),
        "TenGigE0/5/1/1": InterfaceInfo("REGO-IIG-LINK-02", "Bundle-Ether160"),
        "TenGigE0/5/1/10": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-01", "Bundle-Ether400"),
        "TenGigE0/5/1/11": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-02", "Bundle-Ether400"),
        "TenGigE0/5/1/12": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-03", "Bundle-Ether400"),
        "TenGigE0/5/1/13": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-04", "Bundle-Ether400"),
        "TenGigE0/5/1/15": InterfaceInfo("WINDSTREAM-NEW-01", "Bundle-Ether170"),
        "TenGigE0/5/1/16": InterfaceInfo("WINDSTREAM-NEW-02", "Bundle-Ether170"),
        "TenGigE0/5/1/17": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-05", "Bundle-Ether400"),
        "TenGigE0/5/1/18": InterfaceInfo("INTRAGLOBE-IIG-LINK-01", None),
        "TenGigE0/5/1/18.1320": InterfaceInfo("INTRAGLOBE-IIG-LINK-01", None),
        "TenGigE0/5/1/18.1321": InterfaceInfo("INTRAGLOBE-IIG-LD", None),
        "TenGigE0/5/1/19": InterfaceInfo("KKT-DHK-BTCL-BH-ZTE-06", None),
        "TenGigE0/5/1/2": InterfaceInfo(
            "TO-EQ-01-TE0/3/0/8-EQXC-22697434", "Bundle-Ether500"
        ),
        "TenGigE0/5/1/3": InterfaceInfo(
            "TO-EQ-01-Te0/3/0/2-EQXC-22697431", "Bundle-Ether500"
        ),
        "TenGigE0/5/1/4": InterfaceInfo(
            "PCCW-LINK-01 [EQ3/KKT/10GLAN/0151]", "Bundle-Ether155"
        ),
        "TenGigE0/5/1/6": InterfaceInfo(
            "KKT-DHK-LINK-06-VIA-BTCL-BH-AGG-Te0/0/0/6-BTCL_MUX_PORT_113_.75", None
        ),
        "TenGigE0/5/1/7": InterfaceInfo(
            "KKT-DHK-LINK-05-VIA-BTCL-BH-AGG-Te0/0/0/5-BTCL_MUX_PORT_114_.74",
            "Bundle-Ether400",
        ),
        "TenGigE0/5/1/8": InterfaceInfo(
            "KKT-DHK-LINK-04-VIA-F@H-BH-AGG-0/5/0/8", "Bundle-Ether400"
        ),
        "TenGigE0/5/1/9": InterfaceInfo(
            "KKT-DHK-BH-LINK-01-VIA-BAHON-DHK-Te0/0/0/4", "Bundle-Ether400"
        ),
    },
    "BSCCL-KKT-CORE-RTR-02": {
        "Bundle-Ether100": InterfaceInfo("TO-KKT-10GSW", None),
        "Bundle-Ether100.104": InterfaceInfo("TO-SMW5-L2-OUT", None),
        "Bundle-Ether100.1550": InterfaceInfo("SMW4-ADCN-1550", None),
        "Bundle-Ether100.201": InterfaceInfo("KKT-CLS-INTERNET", None),
        "Bundle-Ether100.202": InterfaceInfo("KKT-MGMT-VLAN", None),
        "Bundle-Ether100.205": InterfaceInfo("KKT-SERVER", None),
        "Bundle-Ether100.206": InterfaceInfo("CONNECTED-TO-NVR-KKT", None),
        "Bundle-Ether100.209": InterfaceInfo("KKT-LS-INTERNET-MICROTIK", None),
        "Bundle-Ether100.210": InterfaceInfo("ADN-MUX-MGMT", None),
        "Bundle-Ether101": InterfaceInfo("TO-KKT-03-PNI", None),
        "Bundle-Ether150": InterfaceInfo(
            "KKT-CORE-RTR-02-TO-KKT-CORE-RTR-01-VIA-200G", None
        ),
        "Bundle-Ether150.101": InterfaceInfo("BE-VRF-NETWORK", None),
        "Bundle-Ether150.102": InterfaceInfo("BE-VRF-SUBSCRIBER", None),
        "Bundle-Ether150.103": InterfaceInfo("BE-VRF-MGMT", None),
        "Bundle-Ether150.104": InterfaceInfo("BE_LEVEL-2-VPN_TO_KKT-01", None),
        "Bundle-Ether150.1550": InterfaceInfo("SMW4-ADCN-1550", None),
        "Bundle-Ether150.4": InterfaceInfo("TO-KKT-01-PNI", None),
        "Bundle-Ether200": InterfaceInfo(
            "KKT-CORE-RTR-02-TO-KKT-CORE-RTR-03-VIA-100G", None
        ),
        "Bundle-Ether200.1": InterfaceInfo("TO-KKT-03-VRF-NETWORK", None),
        "Bundle-Ether200.3": InterfaceInfo("VRF-MGMT-TO-CORE-02", None),
        "Bundle-Ether200.4": InterfaceInfo("TO-KKT-03-PNI", None),
        "Bundle-Ether201": InterfaceInfo("F@H-BE-KUAKATA", None),
        "Bundle-Ether202": InterfaceInfo("BDHUB-IIG-BE", None),
        "Bundle-Ether202.202": InterfaceInfo("LD-BDHUB-PEERING", None),
        "Bundle-Ether202.203": InterfaceInfo("IPT-BDHUB", None),
        "Bundle-Ether310": InterfaceInfo("HE-ETHER-BUNDLE-SMW5", None),
        "HundredGigE0/0/0/0": InterfaceInfo(
            "KKT-CORE-RTR-02-TO-KKT-CORE-RTR-01", "Bundle-Ether150"
        ),
        "HundredGigE0/5/0/0": InterfaceInfo(
            "KKT-CORE-02-TO-KKT-CORE-01-2ND-100G-LINK", "Bundle-Ether150"
        ),
        "HundredGigE0/5/0/1": InterfaceInfo(
            "KKT-CORE-02-TO-KKT-CORE-03-LINK-01", "Bundle-Ether200"
        ),
        "HundredGigE0/7/0/0": InterfaceInfo(
            "TO-EQ-02-100G-01 (EQ3/KKT/100GLAN/0004)", None
        ),
        "HundredGigE0/7/0/0.101": InterfaceInfo("TO-EQ-02-VRF-NETWORK", None),
        "HundredGigE0/7/0/0.4": InterfaceInfo("TO-EQ-02-PNI", None),
        "Loopback0": InterfaceInfo("LOOPBACK-SUBSCRIBER", None),
        "Loopback1": InterfaceInfo("LOOPBACK-NETWORK", None),
        "Loopback10": InterfaceInfo("BGP-WITH-COGENTCO", None),
        "Loopback3": InterfaceInfo("LOOPBACK-MGMT", None),
        "Loopback4": InterfaceInfo("LOOPBACK-PNI", None),
        "Loopback5": InterfaceInfo("ROUTE-TEST", None),
        "TenGigE0/0/1/1": InterfaceInfo(
            "CONNECTED-TO-HE-02-SG-SMW5 (EQ3/KKT/10GLAN/0045)", "Bundle-Ether310"
        ),
        "TenGigE0/0/1/5": InterfaceInfo("SUMMIT-3rd-link", None),
        "TenGigE0/0/1/6": InterfaceInfo("F@H-IPT-01", "Bundle-Ether201"),
        "TenGigE0/0/1/7": InterfaceInfo("F@H-IPT-02", "Bundle-Ether201"),
        "TenGigE0/1/0/0": InterfaceInfo("ORANGE-1ST (KKT/MRS/10GLAN/0006)", None),
        "TenGigE0/1/0/1": InterfaceInfo("LINK-TO-KKT-10G-SW-01", "Bundle-Ether100"),
        "TenGigE0/1/0/12": InterfaceInfo("F@H-IPT-03", "Bundle-Ether201"),
        "TenGigE0/1/0/15": InterfaceInfo("LINK-TO-KKT-10G-SW-01", "Bundle-Ether101"),
        "TenGigE0/1/0/16": InterfaceInfo("SUBSCRIBER-END-VIA-DPI-LINK-01", None),
        "TenGigE0/1/0/17": InterfaceInfo("BDHUB-IIG-LD-LINK-01", "Bundle-Ether202"),
        "TenGigE0/1/0/18": InterfaceInfo("BDHUB-IIG-LD-LINK-02", "Bundle-Ether202"),
        "TenGigE0/1/0/2": InterfaceInfo("SUMMIT-KKT-LINK-02", None),
        "TenGigE0/1/0/3": InterfaceInfo("SUMMIT-KKT-LINK-01", None),
        "TenGigE0/1/0/4": InterfaceInfo("BDHUB-IIG-LINK-03", "Bundle-Ether202"),
        "TenGigE0/1/0/5": InterfaceInfo("BDHUB-IIG-LINK-04", "Bundle-Ether202"),
        "TenGigE0/1/0/6": InterfaceInfo("BDHUB-IIG-LINK-05", "Bundle-Ether202"),
        "TenGigE0/1/0/7": InterfaceInfo("PEEREX-IIG-KKT-02-LINK-01", None),
        "TenGigE0/1/0/8": InterfaceInfo("NETWORK-END-VIA-DPI-LINK-01", None),
        "TenGigE0/5/1/0": InterfaceInfo("CONNECTED-TO-KKT-SW", "Bundle-Ether101"),
        "TenGigE0/5/1/3": InterfaceInfo("TELETALK-1G", None),
        "TenGigE0/7/1/0": InterfaceInfo(
            "SUBSCRIBER-END-VIA-DPI-LINK-02", "Bundle-Ether101"
        ),
        "TenGigE0/7/1/1": InterfaceInfo(
            "NETWORK-END-VIA-DPI-LINK-02", "Bundle-Ether101"
        ),
        "preconfigure GigabitEthernet0/1/0/4": InterfaceInfo(
            "CONNECTED-TO-KKT-MGMT-SW", None
        ),
        "preconfigure GigabitEthernet0/1/0/4.201": InterfaceInfo(
            "KKT-CLS-INTERNET", None
        ),
        "preconfigure GigabitEthernet0/1/0/4.205": InterfaceInfo(
            "CONNECTED-TO-SERVER", None
        ),
        "preconfigure GigabitEthernet0/1/0/4.206": InterfaceInfo(
            "CONNECTED-TO-NVR-KKT", None
        ),
    },
    "BSCCL-KKT-CORE-RTR-03": {
        "Bundle-Ether200": InterfaceInfo("KKT-CORE-03-TO-KKT-CORE-02-Hu0/5/0/1", None),
        "Bundle-Ether200.1": InterfaceInfo("TO-KKT-02-VRF-NETWORK", None),
        "Bundle-Ether200.3": InterfaceInfo("VRF-MGMT", None),
        "Bundle-Ether200.4": InterfaceInfo("TO-KKT-02-PNI", None),
        "Bundle-Ether300": InterfaceInfo("TO-EQ-01-BE", None),
        "Bundle-Ether300.1": InterfaceInfo("TO-EQ-01-VRF-NETWORK", None),
        "Bundle-Ether315": InterfaceInfo("DE-CIX-ETHER-BUNDLE-SMW5", None),
        "Bundle-Ether320": InterfaceInfo("ORANGE-BE", None),
        "Bundle-Ether321": InterfaceInfo("BE-COGENT", None),
        "HundredGigE0/0/1/0": InterfaceInfo("LEVEL3-TEMP", None),
        "HundredGigE0/0/2/0": InterfaceInfo(
            "TO-KKT-CORE-02-HunG0/5/0/1", "Bundle-Ether200"
        ),
        "Loopback0": InterfaceInfo("VRF-SUBSCRIBER", None),
        "Loopback1": InterfaceInfo("VRF-NETWORK", None),
        "Loopback3": InterfaceInfo("VRF-MGMT", None),
        "Loopback4": InterfaceInfo("LOOPBACK-PNI", None),
        "TenGigE0/0/0/0": InterfaceInfo(
            "TO-EQ-01-TE0/3/0/3-EQXC-22697433", "Bundle-Ether300"
        ),
        "TenGigE0/0/0/1": InterfaceInfo(
            "TO-EQ-01-Te0/3/0/2-EQXC-22697431", "Bundle-Ether300"
        ),
        "TenGigE0/0/0/2": InterfaceInfo(
            "TO-EQ-01-Te0/3/0/9-EQXC-22697432", "Bundle-Ether300"
        ),
        "TenGigE0/0/0/3": InterfaceInfo(
            "TO-EQ-01-TE0/3/0/8-EQXC-22697434", "Bundle-Ether300"
        ),
        "TenGigE0/0/0/4": InterfaceInfo(
            "COGENT-1ST-(KKT/MRS/10GLAN/0015)", "Bundle-Ether321"
        ),
        "TenGigE0/0/0/5": InterfaceInfo(
            "ORANGE-1ST-LD020858 (KKT/MRS/10GLAN/0006)", "Bundle-Ether320"
        ),
        "preconfigure TenGigE0/5/1/0": InterfaceInfo(
            "COGENTCO-2ND (KKT /MRS/10GLAN/0015)", None
        ),
    },
    "BSCCL-LAN-SW-01": {
        "GigabitEthernet0/1": InterfaceInfo("Connected to BSCCL-AGG-RTR-01 Mgmt", None),
        "GigabitEthernet0/10": InterfaceInfo("Mngt-Port-Nexus-Sw-01", None),
        "GigabitEthernet0/11": InterfaceInfo("L7-INTERNET", None),
        "GigabitEthernet0/12": InterfaceInfo("BSCCL-L7-SWITCH-TRUNK", None),
        "GigabitEthernet0/13": InterfaceInfo("TO_FIREWALL_PORT_1/2", None),
        "GigabitEthernet0/14": InterfaceInfo("CONNTECTED-TO-DHK-03", None),
        "GigabitEthernet0/15": InterfaceInfo("Connected to BSCCL-UCS-01 ETH1", None),
        "GigabitEthernet0/16": InterfaceInfo(
            "4MB-MONITORING-LINK-TO-F@H-SW-PORT-2", None
        ),
        "GigabitEthernet0/17": InterfaceInfo("CONNEECTED-TO-FIREWALL", None),
        "GigabitEthernet0/18": InterfaceInfo("Connected to BSCCL-UCS-03 ETH1", None),
        "GigabitEthernet0/19": InterfaceInfo("SERVER_SET_1_VLAN103", None),
        "GigabitEthernet0/2": InterfaceInfo(
            "Connected to BSCCL-CORE-RTR-01 Mgmt", None
        ),
        "GigabitEthernet0/20": InterfaceInfo("SERVER_SET_1_VLAN103", None),
        "GigabitEthernet0/21": InterfaceInfo("SERVER_SET_1_VLAN103", None),
        "GigabitEthernet0/22": InterfaceInfo("CONNECTED-TO-DHK-03", None),
        "GigabitEthernet0/23": InterfaceInfo("INTERNET", None),
        "GigabitEthernet0/24": InterfaceInfo("Trunk with BSCCL-LAN-SW-02", None),
        "GigabitEthernet0/3": InterfaceInfo("MONITORING-LINK", None),
        "GigabitEthernet0/4": InterfaceInfo("SERVER_LAN_VLAN200", None),
        "GigabitEthernet0/5": InterfaceInfo("SERVER_LAN_VLAN200", None),
        "GigabitEthernet0/6": InterfaceInfo("SERVER_LAN_VLAN200", None),
        "GigabitEthernet0/7": InterfaceInfo("CONNECTED-TO-L7-mikrotik-WIFI", None),
        "GigabitEthernet0/8": InterfaceInfo("CONNECTED-TO-MUX", None),
        "GigabitEthernet0/9": InterfaceInfo("Trunk with Dlink-3200", None),
    },
    "BSCCL-MOGBAZAR-NEXUS": {
        "Ethernet1/1": InterfaceInfo("TRUNK-CGS-TEJ-02-E1/20", "port-channel560"),
        "Ethernet1/10": InterfaceInfo("TELETALK-LINK-03", "port-channel702"),
        "Ethernet1/2": InterfaceInfo("TRUNK-CGS-TEJ-02-E1/22", "port-channel560"),
        "Ethernet1/3": InterfaceInfo("TRUNK-F@H-LINK-01", "port-channel560"),
        "Ethernet1/4": InterfaceInfo("TRUNK-F@H-LINK-02", "port-channel560"),
        "Ethernet1/5": InterfaceInfo("CONNECTED-TO-BTCL", None),
        "Ethernet1/7": InterfaceInfo("TELETALK-LINK-01", "port-channel702"),
        "Ethernet1/8": InterfaceInfo("TELETALK-LINK-02", "port-channel702"),
        "Ethernet1/9": InterfaceInfo("BDCCL-LINK-01", "port-channel703"),
        "port-channel560": InterfaceInfo("TRUNK-TO-NEXUS-02", None),
        "port-channel702": InterfaceInfo("TELETALK-PO", None),
        "port-channel703": InterfaceInfo("BDCCL-PO", None),
    },
    "BSCPLC-COX-CGS-SW-01": {
        "Ethernet1/37": InterfaceInfo("TO-COX-NEXUS-01", None),
        "Ethernet1/47": InterfaceInfo("SSONLINE-LD-1", "port-channel99"),
        "Ethernet1/48": InterfaceInfo("SSONLINE-LD-2", "port-channel99"),
        "Ethernet1/53": InterfaceInfo("CONNECTED-TO-COX-CORE-03", None),
        "Ethernet1/54": InterfaceInfo("WINDSTREAM-IIG", None),
        "port-channel99": InterfaceInfo("SSONLINE", None),
    },
    "BSCPLC-COX-RTR-03": {
        "Bundle-Ether150": InterfaceInfo("BE-COX-DHK-BACKHAUL", None),
        "Bundle-Ether150.1": InterfaceInfo("COX-DHK-VRF-NETWORK", None),
        "Bundle-Ether150.104": InterfaceInfo("TO-DHK-02-ADCN-L2-VPN", None),
        "Bundle-Ether150.1333": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-2", None),
        "Bundle-Ether150.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether150.3": InterfaceInfo("COX-DHK-VRF-MGMT", None),
        "Bundle-Ether150.4": InterfaceInfo("COX-DHK-VRF-PNI", None),
        "Bundle-Ether150.610": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-02", None),
        "Bundle-Ether150.805": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN", None),
        "Bundle-Ether160": InterfaceInfo("BSCCL-COX-CTG-BH", None),
        "Bundle-Ether160.607": InterfaceInfo("COL-ISP-CTG-BE", None),
        "Bundle-Ether160.608": InterfaceInfo("TELETALK-CTG-PRIMARY", None),
        "Bundle-Ether160.609": InterfaceInfo("TELETALK-CTG-SECONDARY", None),
        "Bundle-Ether160.610": InterfaceInfo("EARTH-LD-TEMP-10Gb", None),
        "Bundle-Ether160.614": InterfaceInfo("CORONET-IIG-CTG", None),
        "Bundle-Ether171": InterfaceInfo("CONNECTED-TO-NEXUS", None),
        "Bundle-Ether172": InterfaceInfo("EXABYTE-IIG-COX", None),
        "Bundle-Ether172.1025": InterfaceInfo("EXABYTE-IIG-COX-IPT", None),
        "Bundle-Ether172.1026": InterfaceInfo("EXABYTE-COX-LD", None),
        "Bundle-Ether174": InterfaceInfo("BE-MAXHUB-IIG", None),
        "Bundle-Ether174.1351": InterfaceInfo("MAXHUB-IPT-COX", None),
        "Bundle-Ether200": InterfaceInfo("TO-EQ-01", None),
        "Bundle-Ether200.104": InterfaceInfo("TO-EQ-RTR-01-VRF-LEVEL-2-VPN", None),
        "Bundle-Ether200.1333": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-2", None),
        "Bundle-Ether200.2": InterfaceInfo("TO-EQ-01-VRF-NETWORK", None),
        "Bundle-Ether200.3": InterfaceInfo("TO-EQ-01-VRF-MGMT", None),
        "Bundle-Ether200.4": InterfaceInfo("TO-EQ-RTR-01-VRF-PNI", None),
        "Bundle-Ether200.610": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN-02", None),
        "Bundle-Ether200.805": InterfaceInfo("BDREN-TO-KKT-01-VRF-L2-VPN", None),
        "Bundle-Ether201": InterfaceInfo("test", None),
        "Bundle-Ether210": InterfaceInfo("TO-EQ-02", None),
        "Bundle-Ether210.2": InterfaceInfo("TO-EQ-02-VRF-NETWORK", None),
        "Bundle-Ether31": InterfaceInfo("TO-COX-RTR-01", None),
        "Bundle-Ether31.104": InterfaceInfo("TO-COX-RTR-01-VRF-LEVEL-2-VPN", None),
        "Bundle-Ether31.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether31.2": InterfaceInfo("TO-COX-RTR-01-VRF-NETWORK", None),
        "Bundle-Ether31.3": InterfaceInfo("TO-COX-RTR-01-VRF-MGMT", None),
        "Bundle-Ether31.4": InterfaceInfo("TO-COX-RTR-01-VRF-PNI", None),
        "Bundle-Ether34": InterfaceInfo("TO-COX-RTR-02", None),
        "Bundle-Ether34.2": InterfaceInfo("TO-COX-RTR-02-VRF-NETWORK", None),
        "Bundle-Ether34.3": InterfaceInfo("TO-COX-RTR-02-VRF-MGMT", None),
        "Bundle-Ether34.4": InterfaceInfo("TO-COX-RTR-02-VRF-PNI", None),
        "Bundle-Ether43": InterfaceInfo("TO-COX-CORE-04", None),
        "Bundle-Ether911": InterfaceInfo("TEMP-COX-BH-SUMMIT", None),
        "FortyGigE0/0/0/12": InterfaceInfo("TEST", None),
        "HundredGigE0/0/1/0": InterfaceInfo("TO-COX-RTR-01-LINK-01", "Bundle-Ether31"),
        "HundredGigE0/0/1/1": InterfaceInfo(
            "TO-EQ-01-HUNG-01-COX/TUS/100GBE/001/M [TIS-10000020701]", "Bundle-Ether200"
        ),
        "HundredGigE0/0/1/2": InterfaceInfo("CORONET-IIG", None),
        "HundredGigE0/0/1/2.1041": InterfaceInfo("CORONET-IPT", None),
        "HundredGigE0/0/1/2.1042": InterfaceInfo("CORONET-LD", None),
        "HundredGigE0/0/1/3": InterfaceInfo("GMAX-IIG", None),
        "HundredGigE0/0/1/3.1043": InterfaceInfo("GMAX-IPT", None),
        "HundredGigE0/0/1/3.1044": InterfaceInfo("GMAX-LD", None),
        "HundredGigE0/0/2/0": InterfaceInfo("CONNECTED-TO-CGS-SW", None),
        "HundredGigE0/0/2/0.1041": InterfaceInfo("CORONET-IPT", None),
        "HundredGigE0/0/2/0.1042": InterfaceInfo("CORONET-LD", None),
        "HundredGigE0/0/2/0.1043": InterfaceInfo("GMAX-IPT", None),
        "HundredGigE0/0/2/0.1044": InterfaceInfo("GMAX-LD", None),
        "HundredGigE0/0/2/0.193": InterfaceInfo("WINDSTREAM-IIG-MAIN", None),
        "HundredGigE0/0/2/0.194": InterfaceInfo("WINDSTREAM-LD", None),
        "HundredGigE0/0/2/0.780": InterfaceInfo("SSONLINE-LD", None),
        "HundredGigE0/0/2/0.784": InterfaceInfo("CONNECTED-TO-COX-04-PNI", None),
        "HundredGigE0/0/2/0.92": InterfaceInfo("WINDSTREAM-RTBH-BLACKHOLE", None),
        "HundredGigE0/0/2/1": InterfaceInfo(
            "TO-EQ-01-HUNG-02-COX/TUS/100GBE/002/M [TIS-10000022019]", "Bundle-Ether200"
        ),
        "HundredGigE0/0/2/2": InterfaceInfo("TO-COX-RTR-02-LINK-01", "Bundle-Ether34"),
        "HundredGigE0/0/2/3": InterfaceInfo("TO-EQ-02-CMI-100G", "Bundle-Ether210"),
        "Loopback0": InterfaceInfo("VRF-SUBSCRIBER", None),
        "Loopback1": InterfaceInfo("VRF-NETWORK", None),
        "Loopback3": InterfaceInfo("VRF-MGMT", None),
        "Loopback4": InterfaceInfo("VRF-PNI", None),
        "TenGigE0/0/0/0": InterfaceInfo("EXABYTE-LINK-04-FatH", "Bundle-Ether172"),
        "TenGigE0/0/0/1": InterfaceInfo("EXABYTE-LINK-05-F@H", "Bundle-Ether172"),
        "TenGigE0/0/0/10": InterfaceInfo("COX-DHK-BAHON-LINK-02", "Bundle-Ether150"),
        "TenGigE0/0/0/11": InterfaceInfo("TO-COX-NEXUS-Eth1/40", "Bundle-Ether171"),
        "TenGigE0/0/0/2": InterfaceInfo("EXABYTE-LINK-06-F@H", "Bundle-Ether172"),
        "TenGigE0/0/0/3": InterfaceInfo(
            "COX-DHK-BACKHAUL-LINK-01-F@H-SCR83665", "Bundle-Ether150"
        ),
        "TenGigE0/0/0/4": InterfaceInfo(
            "COX-DHK-SUMMIT-BH-LINK-2-bscl_020925_060_nb", "Bundle-Ether150"
        ),
        "TenGigE0/0/0/5": InterfaceInfo(
            "FOR-COX-DHK-BH-LINK-03-NEW-SUMMIT-DHK-Te0/3/1/4", "Bundle-Ether150"
        ),
        "TenGigE0/0/0/6": InterfaceInfo("COX-DHK-BAHON-LINK-01", "Bundle-Ether150"),
        "TenGigE0/0/0/7": InterfaceInfo("MAXHUB-LINK-01", "Bundle-Ether174"),
        "TenGigE0/0/0/8": InterfaceInfo("MAXHUB-LINK-02", "Bundle-Ether174"),
        "TenGigE0/0/0/9": InterfaceInfo("COX-DHK-BAHON-LINK-03", "Bundle-Ether150"),
        "TenGigE0/2/0/0": InterfaceInfo("COX-DHK-SCL-01", "Bundle-Ether150"),
        "TenGigE0/2/0/1": InterfaceInfo("COX-DHK-SCL-02", "Bundle-Ether150"),
        "TenGigE0/2/0/2": InterfaceInfo("COX-DHK-SCL-03", "Bundle-Ether150"),
        "TenGigE0/2/0/3": InterfaceInfo("COX-DHK-SCL-04", "Bundle-Ether150"),
        "TenGigE0/2/0/4": InterfaceInfo("COX-DHK-SCL-05", "Bundle-Ether150"),
    },
    "BSCPLC-COX-RTR-04": {
        "Bundle-Ether400": InterfaceInfo("TO-EQ-RTR-02", None),
        "Bundle-Ether400.2": InterfaceInfo("TO-EQ-RTR-02-VRF-NETWORK", None),
        "Bundle-Ether400.3": InterfaceInfo("TO-EQ-RTR-02-VRF-MGMT", None),
        "Bundle-Ether400.4": InterfaceInfo("TO-EQ-RTR-02-VRF-PNI", None),
        "Bundle-Ether42": InterfaceInfo("TO-COX-RTR-02", None),
        "Bundle-Ether42.2": InterfaceInfo("TO-COX-RTR-02-VRF-NETWORK", None),
        "Bundle-Ether43": InterfaceInfo("TO-COX-CORE-03", None),
        "Bundle-Ether43.2": InterfaceInfo("TO-COX-RTR-03-VRF-NETWORK", None),
        "Bundle-Ether43.3": InterfaceInfo("TO-COX-RTR-03-VRF-MGMT", None),
        "Bundle-Ether43.4": InterfaceInfo("TO-COX-RTR-03-VRF-PNI", None),
        "Loopback0": InterfaceInfo("VRF-SUBSCRIBER", None),
        "Loopback1": InterfaceInfo("VRF-NETWORK", None),
        "Loopback3": InterfaceInfo("VRF-MGMT", None),
        "Loopback4": InterfaceInfo("VRF-PNI", None),
        "preconfigure FortyGigE0/0/0/12": InterfaceInfo("TEST", None),
        "preconfigure HundredGigE0/0/1/0": InterfaceInfo(
            "TO-COX-RTR-02-100G", "Bundle-Ether42"
        ),
        "preconfigure HundredGigE0/0/2/2": InterfaceInfo(
            "TO-COX-RTR-03-LINK-01", "Bundle-Ether43"
        ),
        "preconfigure TenGigE0/0/0/10": InterfaceInfo(
            "TO-EQ-02-LINK-07-ORANGE-BH-01-10G (COX/TUS/10GE/(LAN PHY)/043/M)",
            "Bundle-Ether400",
        ),
        "preconfigure TenGigE0/0/0/11": InterfaceInfo(
            "EQ-02-LINK-03 (COX/TUS/10GE/(LAN PHY)/002/M)", "Bundle-Ether400"
        ),
        "preconfigure TenGigE0/0/0/8": InterfaceInfo(
            "TO-EQ-02-LINK-09-ORANGE-BH-05-10G(COX/TUS/10GE(LAN PHY)/015/M)-EQ-02-Te0/0/0/3",
            None,
        ),
        "preconfigure TenGigE0/0/0/9": InterfaceInfo(
            "EQ-02-LINK-04-ORANGE-BH-04-LD020854 (COX/TUS/10GE/(LAN PHY)/042/M)",
            "Bundle-Ether400",
        ),
    },
    "BSCPLC-DHK-RTR-03": {
        "Bundle-Ether100": InterfaceInfo("BE-TO-DHK-CORE-02", None),
        "Bundle-Ether100.1": InterfaceInfo("NETWORK-TO-DHK-02-NETWORK", None),
        "Bundle-Ether100.10": InterfaceInfo("CDN-TO-DHK-02-PNI", None),
        "Bundle-Ether100.104": InterfaceInfo("TO-DHK-02-ADCN-L2-VPN", None),
        "Bundle-Ether100.11": InterfaceInfo("CDN-EDGENEXT-TO-DHK-02-NETWORK", None),
        "Bundle-Ether100.1333": InterfaceInfo(
            "BDREN-1333-DHK-03-TO-DHK-02-L2-VPN", None
        ),
        "Bundle-Ether100.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether100.3": InterfaceInfo("MGMT-TO-DHK-02-MGMT", None),
        "Bundle-Ether100.5": InterfaceInfo("GGC-TO-DHK-02-NETWORK", None),
        "Bundle-Ether100.6": InterfaceInfo("FNA-TO-DHK-02-NETWORK", None),
        "Bundle-Ether100.610": InterfaceInfo("BDREN-DHK-03-TO-DHK-02-L2-VPN-2", None),
        "Bundle-Ether100.7": InterfaceInfo("CDN-TO-DHK-02-NETWORK", None),
        "Bundle-Ether100.8": InterfaceInfo("GGC-TO-DHK-02-PNI", None),
        "Bundle-Ether100.805": InterfaceInfo("BDREN-DHK-03-TO-DHK-02-L2-VPN", None),
        "Bundle-Ether100.9": InterfaceInfo("FNA-TO-DHK-02-PNI", None),
        "Bundle-Ether101": InterfaceInfo("BE-VRF-NETWORK", None),
        "Bundle-Ether101.5": InterfaceInfo("VRF-NETWORK-TO-VRF-CLOUDFLARE-CDN", None),
        "Bundle-Ether102": InterfaceInfo("BE-VRF-CDN", None),
        "Bundle-Ether102.5": InterfaceInfo("VRF-CLOUDFLARE-CDN-TO-VRF-NETWORK", None),
        "Bundle-Ether120": InterfaceInfo("BE-EDGENEXT-CLOUD", None),
        "Bundle-Ether150": InterfaceInfo("DHK-COX-BACKHAUL-BE", None),
        "Bundle-Ether150.1": InterfaceInfo("DHK-COX-VRF-NETWORK", None),
        "Bundle-Ether150.104": InterfaceInfo("TO-COX-01-ADCN-L2-VPN", None),
        "Bundle-Ether150.1333": InterfaceInfo(
            "BDREN-1333-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether150.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether150.3": InterfaceInfo("DHK-COX-VRF-MGMT", None),
        "Bundle-Ether150.4": InterfaceInfo("DHK-COX-VRF-PNI", None),
        "Bundle-Ether150.610": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN-2", None
        ),
        "Bundle-Ether150.805": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether201": InterfaceInfo("test", None),
        "Bundle-Ether30": InterfaceInfo("TO-ACCESS-SW-01", None),
        "Bundle-Ether400": InterfaceInfo("CONNECTED-TO-KKT-CORE-01", None),
        "Bundle-Ether400.1": InterfaceInfo("VRF-NETWORK", None),
        "Bundle-Ether400.104": InterfaceInfo("TO-KKT-01-ADCN-L2-VPN", None),
        "Bundle-Ether400.1333": InterfaceInfo(
            "BDREN-1333-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether400.1550": InterfaceInfo("SMW4-L2-1550", None),
        "Bundle-Ether400.2": InterfaceInfo("VRF-SUBSCRIBER", None),
        "Bundle-Ether400.3": InterfaceInfo("VRF-MANAGEMENT", None),
        "Bundle-Ether400.4": InterfaceInfo("VRF-PNI", None),
        "Bundle-Ether400.610": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN-2", None
        ),
        "Bundle-Ether400.805": InterfaceInfo(
            "BDREN-FROM-KKT-01-TO-DHK-03-L2-VPN", None
        ),
        "Bundle-Ether401": InterfaceInfo("test", None),
        "Bundle-Ether410": InterfaceInfo("DHK-KKT-BTCL-ZTE-BE", None),
        "Bundle-Ether655": InterfaceInfo("BE-CONNECTED-TO-SW", None),
        "Bundle-Ether655.1000": InterfaceInfo("CONNECTING-TO-FIREWALL", None),
        "Bundle-Ether655.1001": InterfaceInfo("TO-FIREWALL-FOR-KKT-MGMT", None),
        "Bundle-Ether655.1010": InterfaceInfo("OOB-CLOUDFLARE", None),
        "Bundle-Ether655.1020": InterfaceInfo("BSCIX-RS-NETWORK", None),
        "Bundle-Ether655.120": InterfaceInfo("BE-EDGENEXT-CLOUD", None),
        "Bundle-Ether655.1333": InterfaceInfo(
            "BDREN-1333-DHK-03-TO-CGS-DHKCOLO-VPN-1333", None
        ),
        "Bundle-Ether655.200": InterfaceInfo("VLAN-200-MGMT", None),
        "Bundle-Ether655.210": InterfaceInfo("SSONLINE-SEC-DC", None),
        "Bundle-Ether655.211": InterfaceInfo("CAMERA-NVR-INTERNET", None),
        "Bundle-Ether655.399": InterfaceInfo("TEJGAON-INTERNET", None),
        "Bundle-Ether655.402": InterfaceInfo("SSONLINE-PRI-TEJ", None),
        "Bundle-Ether655.404": InterfaceInfo("SKYTEL-TEJ-IPT", None),
        "Bundle-Ether655.405": InterfaceInfo("SKYTEL-IIG-SEC-IPT", None),
        "Bundle-Ether655.412": InterfaceInfo("ADN-ISP-NRB", None),
        "Bundle-Ether655.413": InterfaceInfo("VIRGO", None),
        "Bundle-Ether655.416": InterfaceInfo("NOVOCOM-TEJ", None),
        "Bundle-Ether655.418": InterfaceInfo("VELOCITY-DHKCOLO", None),
        "Bundle-Ether655.419": InterfaceInfo("DHKLINK-ISP-SEC", None),
        "Bundle-Ether655.420": InterfaceInfo("TO-CLOUDFLARE-EDGE-TRANSIT", None),
        "Bundle-Ether655.421": InterfaceInfo("TO-CLOUDFLARE-EDGE-LOCAL", None),
        "Bundle-Ether655.422": InterfaceInfo("ADN-GATEWAY-IIG-SEC", None),
        "Bundle-Ether655.423": InterfaceInfo("DHAKALINK-ISP", None),
        "Bundle-Ether655.424": InterfaceInfo("NOVOCOM-IIG-DHAKACOLO", None),
        "Bundle-Ether655.444": InterfaceInfo("TELNET-ISP-PRIMARY", None),
        "Bundle-Ether655.451": InterfaceInfo("VELOCITY-IIG-TEJGAO", None),
        "Bundle-Ether655.502": InterfaceInfo("BDLINK-IIG", None),
        "Bundle-Ether655.519": InterfaceInfo("BDREN-ISP-PRIMARY", None),
        "Bundle-Ether655.520": InterfaceInfo("BDREN-ISP-SECONDARY", None),
        "Bundle-Ether655.530": InterfaceInfo("EQUITEL-IIG", None),
        "Bundle-Ether655.553": InterfaceInfo("ADN-ISP-TEJ-SECONDARY", None),
        "Bundle-Ether655.554": InterfaceInfo("ADN-ISP-TEJ-PRI", None),
        "Bundle-Ether655.610": InterfaceInfo(
            "BDREN-DHK-03-TO-CGS-DHKCOLO-VPN-610", None
        ),
        "Bundle-Ether655.652": InterfaceInfo("LINK3-ISP-TEJ-PRI", None),
        "Bundle-Ether655.653": InterfaceInfo("LINK3-ISP-DHKCOLO-SEC", None),
        "Bundle-Ether655.654": InterfaceInfo("RACEONLINE-ISP", None),
        "Bundle-Ether655.701": InterfaceInfo("PEEREX-DHKCOLO", None),
        "Bundle-Ether655.702": InterfaceInfo("TELETALK-MOGBAZAR-PRI", None),
        "Bundle-Ether655.703": InterfaceInfo("BDCCL-PRI-MOG-POP", None),
        "Bundle-Ether655.805": InterfaceInfo(
            "BDREN-DHK-03-TO-TO-CGS-DHKCOLO-VPN-805", None
        ),
        "Bundle-Ether655.902": InterfaceInfo("EXABYTE-CDN-SECONDARY", None),
        "Bundle-Ether655.903": InterfaceInfo("EXABYTE-CDN-PRIMARY", None),
        "Bundle-Ether655.904": InterfaceInfo("SSONLINE-CLOUDFLARE-CDN", None),
        "Bundle-Ether655.905": InterfaceInfo("FROM-DHK-O2-TO-EDGENEXT", None),
        "Bundle-Ether655.980": InterfaceInfo("TELNET-ICT-TOWER", None),
        "HundredGigE0/0/1/1": InterfaceInfo("VRF-NETWORK-SIDE", "Bundle-Ether101"),
        "HundredGigE0/0/1/2": InterfaceInfo("CONNECTED-TO-SW", "Bundle-Ether655"),
        "HundredGigE0/0/2/0": InterfaceInfo("TO-EDGENEXT-CLOUD", "Bundle-Ether120"),
        "HundredGigE0/0/2/1": InterfaceInfo("VRF-CDN-SIDE", "Bundle-Ether102"),
        "HundredGigE0/0/2/2": InterfaceInfo("CONNECTED-TO-SW", "Bundle-Ether655"),
        "Loopback1": InterfaceInfo("VRF-GGC-PUBLIC-IP", None),
        "Loopback2": InterfaceInfo("LO-VRF-NETWORK", None),
        "Loopback3": InterfaceInfo("LO-MGMT", None),
        "Loopback4": InterfaceInfo("PNI-LO", None),
        "Loopback5": InterfaceInfo("LO-GGC", None),
        "Loopback6": InterfaceInfo("LO-FNA", None),
        "Loopback7": InterfaceInfo("LO-CDN", None),
        "TenGigE0/0/0/0": InterfaceInfo(
            "DHK-KKT-BH-LINK-02-VIA-F@H-KKT-Te0/1/0/23-121492", "Bundle-Ether400"
        ),
        "TenGigE0/0/0/1": InterfaceInfo("DHK-KKT-SUMIIT-LINK-01", "Bundle-Ether400"),
        "TenGigE0/0/0/10": InterfaceInfo("DHK-COX-BAHON-LINK-02", "Bundle-Ether150"),
        "TenGigE0/0/0/11": InterfaceInfo("DHK-COX-BAHON-LINK-03", "Bundle-Ether150"),
        "TenGigE0/0/0/12/0": InterfaceInfo("DHK-COX-SCL-01", "Bundle-Ether150"),
        "TenGigE0/0/0/12/1": InterfaceInfo("DHK-COX-SCL-02", "Bundle-Ether150"),
        "TenGigE0/0/0/12/2": InterfaceInfo("DHK-COX-SCL-03", "Bundle-Ether150"),
        "TenGigE0/0/0/13/0": InterfaceInfo("DHK-COX-SCL-LINK-5", "Bundle-Ether150"),
        "TenGigE0/0/0/13/1": InterfaceInfo("DHK-KKT-BTCL-ZTE-04", None),
        "TenGigE0/0/0/13/2": InterfaceInfo("DHK-COX-SCL-LINK-4", "Bundle-Ether150"),
        "TenGigE0/0/0/13/3": InterfaceInfo("DHK-KKT-BTCL-ZTE-06", None),
        "TenGigE0/0/0/2": InterfaceInfo(
            "DHK-KKT-BH-LINK-03-VIA-F@H-KKT-Te0/1/0/15-121491", "Bundle-Ether400"
        ),
        "TenGigE0/0/0/3": InterfaceInfo("DHK-COX-F@H-1", "Bundle-Ether150"),
        "TenGigE0/0/0/4": InterfaceInfo("DHK-KKT-PGCB-LINK-NEED", "Bundle-Ether400"),
        "TenGigE0/0/0/5": InterfaceInfo("DHK-KKT-F@H-3", "Bundle-Ether400"),
        "TenGigE0/0/0/6": InterfaceInfo("DHK-COX-SUMMIT-LINK-01", "Bundle-Ether150"),
        "TenGigE0/0/0/7": InterfaceInfo("DHK-COX-SUMMIT-LINK-02", "Bundle-Ether150"),
        "TenGigE0/0/0/8": InterfaceInfo("DHK-KKT-BAHON-01", "Bundle-Ether400"),
        "TenGigE0/0/0/9": InterfaceInfo("DHK-COX-BAHON-LINK-01", "Bundle-Ether150"),
        "preconfigure HundredGigE0/0/1/0": InterfaceInfo("TO-CGS-100G-LINK-01", None),
        "preconfigure HundredGigE0/0/1/0.401": InterfaceInfo(
            "FROM-DHK-O2-TO-CLOUDFLARE", None
        ),
        "preconfigure HundredGigE0/0/1/0.418": InterfaceInfo(
            "VELOCITY-IIG-NRB-SECONDARY", None
        ),
        "preconfigure HundredGigE0/0/1/0.422": InterfaceInfo(
            "ADN-GATEWAY-IIG-SEC", None
        ),
        "preconfigure HundredGigE0/0/1/0.423": InterfaceInfo(
            "EXABYTE-CDN-SECONDARY", None
        ),
        "preconfigure HundredGigE0/0/1/0.903": InterfaceInfo(
            "EXABYTE-CDN-PRIMARY", None
        ),
        "preconfigure HundredGigE0/0/1/0.904": InterfaceInfo("SSONLINE-CDN", None),
        "preconfigure HundredGigE0/0/1/0.905": InterfaceInfo(
            "FROM-DHK-O2-TO-EDGENEXT", None
        ),
        "preconfigure HundredGigE0/0/1/0.906": InterfaceInfo(
            "FROM-DHK-O1-TO-CLOUDFLARE", None
        ),
    },
}


def lookup_interface(hostname: str, interface: str) -> InterfaceInfo | None:
    """Resolve device hostname + interface name to description/bundle info.

    Handles underscore-to-slash normalization (e.g. HundredGigE0_3_2_2).
    Returns None for unknown hostname or interface."""
    device_interfaces = INTERFACE_MAP.get(hostname)
    if device_interfaces is None:
        return None
    normalized = _normalize_interface(interface)
    return device_interfaces.get(normalized)
