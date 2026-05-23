"""Static AS number database for BSCCL NetWatch.

Source of truth: docs/PRD-SUPPLEMENT.md Section E6.

Structure
---------
AS_DATABASE: dict[int, ASInfo]
    Maps AS number (int) to an immutable ASInfo record.

lookup_as(asn: int) -> ASInfo | None
    Returns ASInfo for known ASNs, None for unknown ones.
    Unknown ASNs trigger an external lookup in production (PeeringDB / bgpview / RIPE).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ASInfo:
    """Immutable record describing a single Autonomous System."""

    name: str  # e.g. "TCLOUD Computing"
    as_type: str  # e.g. "IX-MLPE", "Transit", "PNI", "ISP-Client", …
    router: str  # e.g. "EQ-RTR-01/02", "DHK-03", "KKT-02"


# ---------------------------------------------------------------------------
# International Transit & PNI (Singapore — EQ-RTR-01/02)
# ---------------------------------------------------------------------------
_TRANSIT_PNI: dict[int, ASInfo] = {
    2914: ASInfo("NTT Communications", "Transit", "EQ-RTR-01/02"),
    9002: ASInfo("RETN", "Transit", "EQ-RTR-01"),
    15169: ASInfo("Google", "PNI", "EQ-RTR-01/02"),
    16509: ASInfo("Amazon/AWS", "PNI", "EQ-RTR-01/02"),
    32934: ASInfo("Facebook/Meta", "PNI", "EQ-RTR-01/02"),
    13335: ASInfo("Cloudflare", "PNI+Transit", "EQ-RTR-01/02, DHK-03"),
    14789: ASInfo("Cloudflare (Transit)", "Transit", "DHK-03"),
    4229: ASInfo("Zenlayer", "PNI", "EQ-RTR-01/02"),
    10122: ASInfo("BIGO Technology", "PNI", "EQ-RTR-01"),
    24115: ASInfo("Equinix Internet Access", "Transit", "EQ-RTR-01/02"),
}

# ---------------------------------------------------------------------------
# Equinix MLPE IX Peers (on EQ-RTR-01 unless noted)
# ---------------------------------------------------------------------------
_IX_MLPE: dict[int, ASInfo] = {
    42: ASInfo("Packet Clearing House", "IX-MLPE", "EQ-RTR-01"),
    714: ASInfo("Apple", "IX-MLPE", "EQ-RTR-01"),
    983: ASInfo("AKARI Networks", "IX-MLPE+SGIX", "EQ-RTR-01"),
    2635: ASInfo("Automattic (WordPress)", "IX-MLPE", "EQ-RTR-01"),
    2906: ASInfo("Netflix", "IX-SGIX", "EQ-RTR-01"),
    4637: ASInfo("Telstra", "IX-MLPE", "EQ-RTR-01"),
    4651: ASInfo("CAT Thailand", "IX-MLPE", "EQ-RTR-01"),
    4761: ASInfo("Indosat Ooredoo", "IX-MLPE", "EQ-RTR-01"),
    4764: ASInfo("Aussie Broadband", "IX-MLPE", "EQ-RTR-01"),
    4775: ASInfo("Globe Telecom", "IX-MLPE", "EQ-RTR-01"),
    4826: ASInfo("Vocus Communications", "IX-MLPE", "EQ-RTR-01"),
    4844: ASInfo("Superinternet SG", "IX-MLPE", "EQ-RTR-01"),
    6507: ASInfo("Riot Games", "IX-MLPE", "EQ-RTR-01"),
    7545: ASInfo("TPG Telecom AU", "IX-MLPE", "EQ-RTR-01"),
    7632: ASInfo("First Media Exchange", "IX-MLPE", "EQ-RTR-01"),
    8075: ASInfo("Microsoft", "IX-MLPE", "EQ-RTR-01"),
    8529: ASInfo("ZAIN Group", "IX-MLPE", "EQ-RTR-01"),
    8849: ASInfo("Melbikomas", "IX-MLPE", "EQ-RTR-01"),
    8966: ASInfo("Etisalat UAE", "IX-MLPE", "EQ-RTR-01"),
    9498: ASInfo("Bharti Airtel", "IX-MLPE", "EQ-RTR-01"),
    9505: ASInfo("Chunghwa Telecom", "IX-MLPE", "EQ-RTR-01"),
    9583: ASInfo("Sify Technologies", "IX-MLPE", "EQ-RTR-01"),
    9930: ASInfo("TIME dotCom Malaysia", "IX-MLPE", "EQ-RTR-01"),
    14061: ASInfo("DigitalOcean", "IX-MLPE", "EQ-RTR-01"),
    15133: ASInfo("Edgio", "IX-MLPE", "EQ-RTR-01"),
    15830: ASInfo("Equinix IX", "IX-MLPE", "EQ-RTR-01"),
    16276: ASInfo("OVHcloud", "IX-MLPE", "EQ-RTR-01"),
    18106: ASInfo("Viewqwest", "IX-MLPE", "EQ-RTR-01"),
    19551: ASInfo("Imperva (Incapsula)", "IX-MLPE", "EQ-RTR-01"),
    20940: ASInfo("Akamai", "IX-MLPE", "EQ-RTR-01"),
    21859: ASInfo("Zenlayer (IX)", "IX-MLPE", "EQ-RTR-01"),
    22697: ASInfo("Roblox", "IX-MLPE", "EQ-RTR-01"),
    23764: ASInfo("China Telecom Global", "IX-MLPE", "EQ-RTR-01"),
    24482: ASInfo("SG.GS", "IX-MLPE", "EQ-RTR-01"),
    29990: ASInfo("AppNexus (Xandr)", "IX-MLPE", "EQ-RTR-01"),
    30081: ASInfo("CacheFly", "IX-MLPE", "EQ-RTR-01"),
    32261: ASInfo("Subspace", "IX-MLPE", "EQ-RTR-01"),
    32590: ASInfo("Valve (Steam)", "IX-MLPE", "EQ-RTR-01"),
    36131: ASInfo("IMO", "IX-MLPE", "EQ-RTR-01"),
    36236: ASInfo("NetAcute", "IX-MLPE", "EQ-RTR-01"),
    36351: ASInfo("IBM/SoftLayer", "IX-MLPE", "EQ-RTR-01"),
    37468: ASInfo("Angola Cables", "IX-MLPE", "EQ-RTR-01"),
    38001: ASInfo("NewMedia Express", "IX-MLPE", "EQ-RTR-01"),
    38466: ASInfo("U Mobile Malaysia", "IX-MLPE", "EQ-RTR-01"),
    43996: ASInfo("Booking.com", "IX-MLPE", "EQ-RTR-01"),
    45102: ASInfo("Alibaba Cloud", "IX-MLPE", "EQ-RTR-01"),
    45437: ASInfo("Realworld", "IX-MLPE", "EQ-RTR-01"),
    45796: ASInfo("BB Connect", "IX-MLPE", "EQ-RTR-01"),
    46489: ASInfo("Twitch (Amazon)", "IX-MLPE", "EQ-RTR-01"),
    48237: ASInfo("Etisalat Misr", "IX-MLPE", "EQ-RTR-01"),
    49544: ASInfo("i3D.net", "IX-MLPE", "EQ-RTR-01"),
    53813: ASInfo("Zscaler", "IX-MLPE", "EQ-RTR-01"),
    54113: ASInfo("Fastly", "IX-MLPE", "EQ-RTR-01"),
    54994: ASInfo("CHINANET", "IX-MLPE", "EQ-RTR-01"),
    55329: ASInfo("Telcotech Cambodia", "IX-MLPE", "EQ-RTR-01"),
    57976: ASInfo("Blizzard Entertainment", "IX-MLPE", "EQ-RTR-01"),
    58511: ASInfo("Anycast Global", "IX-MLPE", "EQ-RTR-01"),
    60068: ASInfo("CDN77", "IX-MLPE", "EQ-RTR-01"),
    62955: ASInfo("eBay", "IX-MLPE", "EQ-RTR-01"),
    63631: ASInfo("Cloudbase", "IX-MLPE", "EQ-RTR-01"),
    63927: ASInfo("RISE.PH", "IX-MLPE", "EQ-RTR-01"),
    63949: ASInfo("Linode (Akamai)", "IX-MLPE", "EQ-RTR-01"),
    63956: ASInfo("COLOAU", "IX-MLPE", "EQ-RTR-01"),
    64050: ASInfo("BGP.NET", "IX-MLPE", "EQ-RTR-01"),
    64096: ASInfo("Beijing Internet Harbor", "IX-MLPE", "EQ-RTR-01"),
    132203: ASInfo("Tencent", "IX-MLPE", "EQ-RTR-01"),
    132337: ASInfo("ALPHA Networks", "IX-MLPE", "EQ-RTR-01"),
    136907: ASInfo("Huawei Cloud", "IX-MLPE", "EQ-RTR-01"),
    137280: ASInfo("Kingsoft Cloud", "IX-MLPE", "EQ-RTR-01"),
    137831: ASInfo("SEAIX", "IX-MLPE", "EQ-RTR-01"),
    137922: ASInfo("iBoss", "IX-MLPE", "EQ-RTR-01"),
    138915: ASInfo("KAOPU Cloud", "IX-MLPE", "EQ-RTR-01"),
    139057: ASInfo("BaishanCloud/EdgeNext", "IX-MLPE", "EQ-RTR-01"),
    139148: ASInfo("Gasatek", "IX-SGIX", "EQ-RTR-01"),
    139341: ASInfo("ACE CDN", "IX-MLPE", "EQ-RTR-01"),
    151326: ASInfo("DCC", "IX-MLPE+SGIX", "EQ-RTR-01"),
    199524: ASInfo("GCore Labs", "IX-MLPE", "EQ-RTR-01"),
    396998: ASInfo("PATH Network", "IX-MLPE", "EQ-RTR-01"),
    399077: ASInfo("TCLOUD Computing", "IX-MLPE", "EQ-RTR-01"),
}

# ---------------------------------------------------------------------------
# Bangladesh Local ISPs (DHK-Core-03)
# ---------------------------------------------------------------------------
_BD_LOCAL: dict[int, ASInfo] = {
    18060: ASInfo("BSCPLX NIX", "IXP-Local", "DHK-03"),
    23688: ASInfo("Link3 Technologies", "ISP-Client", "DHK-03"),
    38203: ASInfo("ADN Telecom", "ISP-Client", "DHK-03"),
    38712: ASInfo("Telnet Communication", "ISP-Client", "DHK-03"),
    45925: ASInfo("Teletalk Bangladesh", "ISP-Client", "DHK-03"),
    58616: ASInfo("Equitel", "ISP-Client", "DHK-03"),
    58655: ASInfo("Skytel Communications", "ISP-Client", "DHK-03, COX-03"),
    58668: ASInfo("BDLink Communication", "ISP-Client", "DHK-03"),
    58717: ASInfo("Summit Communications", "CDN-Peer", "DHK-03"),
    58945: ASInfo("Virgo Connectivity", "ISP-Client", "DHK-03, COX-03"),
    59378: ASInfo("ADN Gateway", "ISP-Client", "DHK-03"),
    63961: ASInfo("BDREN", "Education-Network", "DHK-03"),
    63969: ASInfo("RaceOnline", "ISP-Client", "DHK-03"),
    132267: ASInfo("Novocom", "ISP-Client", "DHK-03"),
    134734: ASInfo("Velocity Online", "ISP-Client", "DHK-03"),
    136014: ASInfo("SS Online / SSONLINE", "CDN-Client", "DHK-03, COX-03"),
    140712: ASInfo("DhakaLink", "ISP-Client", "DHK-03"),
    141773: ASInfo("BDCCL", "ISP-Client", "DHK-03"),
    150178: ASInfo("Exabyte Ltd", "CDN-Client", "DHK-03, COX-03"),
}

# ---------------------------------------------------------------------------
# Kuakata Local (KKT-Core-02)
# ---------------------------------------------------------------------------
_KKT_LOCAL: dict[int, ASInfo] = {
    10075: ASInfo("Fiber@Home (F@H)", "Backhaul-Peer", "KKT-02"),
    58656: ASInfo("BDHUB", "IIG-Peer", "KKT-02, COX-01"),
    137491: ASInfo("Peerex", "IIG-Peer", "KKT-02"),
}

# ---------------------------------------------------------------------------
# Cox's Bazar Local (COX-Core-01/02/03)
# ---------------------------------------------------------------------------
_COX_LOCAL: dict[int, ASInfo] = {
    38592: ASInfo("COL Telecom (Cox)", "ISP-Client", "COX-01"),
    58629: ASInfo("GFCL", "ISP-Client", "COX-01"),
    58715: ASInfo("Earth Telecom", "IIG-Client", "COX-03"),
    58752: ASInfo("Delta Infocom", "IIG-Client", "COX-01"),
    59239: ASInfo("iTel IIG", "IIG-Client", "KKT-02"),
    139009: ASInfo("Windstream", "IIG-Client", "COX-03"),
    141731: ASInfo("Maxhub", "IIG-Client", "COX-03"),
    149765: ASInfo("Coronet Communications", "IIG-Client", "COX-01, COX-03"),
    150748: ASInfo("Greenmax", "IIG-Client", "COX-01, COX-03"),
}

# ---------------------------------------------------------------------------
# BSCCL own ASN
# ---------------------------------------------------------------------------
_OWN: dict[int, ASInfo] = {
    132602: ASInfo("BSCCL", "Self", "All"),
}

# ---------------------------------------------------------------------------
# Merged public constant
# ---------------------------------------------------------------------------
AS_DATABASE: dict[int, ASInfo] = {
    **_TRANSIT_PNI,
    **_IX_MLPE,
    **_BD_LOCAL,
    **_KKT_LOCAL,
    **_COX_LOCAL,
    **_OWN,
}


def lookup_as(asn: int) -> ASInfo | None:
    """Resolve an AS number to name/type info.

    Returns None for unknown ASNs.  Callers that need a definitive answer for
    unknown ASNs should fall back to PeeringDB / bgpview / RIPE STAT (handled
    by the production as_cache layer — NOT in this module).

    Parameters
    ----------
    asn:
        Autonomous System number (integer, e.g. 399077).

    Returns
    -------
    ASInfo | None
        The matching record, or None if the ASN is not in the static database.
    """
    return AS_DATABASE.get(asn)
