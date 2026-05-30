"""Static network dependency tree for BSCCL NetWatch.

Encodes the physical backhaul topology across BSCCL's 5-site backbone:
  - Singapore Equinix (EQ-RTR-01, EQ-RTR-02)
  - Kuakata CLS (KKT-Core-01, KKT-Core-02, KKT-Core-03)
  - Dhaka Tejgaon (DHK-Core-02, DHK-Core-03)
  - Cox's Bazar (COX-Core-01, COX-Core-03)

Source of truth: docs/PRD-SUPPLEMENT.md Section E1.1
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackhaulLink:
    """Describes one backhaul bundle between two devices.

    Attributes:
        description:       Human-readable link description.
        remote_device_ip:  IP of the remote device at the far end of the bundle.
        members:           Physical member interfaces that make up this bundle.
    """

    description: str
    remote_device_ip: str
    members: list[str] = field(default_factory=list)

    def __hash__(self) -> int:  # frozen requires hash for list fields workaround
        return hash((self.description, self.remote_device_ip, tuple(self.members)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BackhaulLink):
            return NotImplemented
        return (
            self.description == other.description
            and self.remote_device_ip == other.remote_device_ip
            and self.members == other.members
        )


@dataclass(frozen=True)
class DeviceTopology:
    """Topology context for a single network device.

    Attributes:
        name:      Human-readable device name.
        upstreams: Mapping of bundle interface name → BackhaulLink.
    """

    name: str
    upstreams: dict[str, BackhaulLink] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.name, tuple(sorted(self.upstreams.items()))))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DeviceTopology):
            return NotImplemented
        return self.name == other.name and self.upstreams == other.upstreams


# ---------------------------------------------------------------------------
# Topology data — keyed by syslog source IP
# ---------------------------------------------------------------------------

NETWORK_TOPOLOGY: dict[str, DeviceTopology] = {
    # ── EQ-RTR-01 (192.168.203.1) ──────────────────────────────────────────
    "192.168.203.1": DeviceTopology(
        name="Equinix-RTR-1",
        upstreams={
            "Bundle-Ether500": BackhaulLink(
                description="EQ-RTR-01 → KKT-Core-01",
                remote_device_ip="192.168.202.2",
                members=[
                    "TenGigE0/0/0/0",
                    "TenGigE0/0/0/1",
                    "TenGigE0/0/0/2",
                    "TenGigE0/0/0/3",
                    "TenGigE0/0/0/5",
                    "TenGigE0/0/0/6",
                    "TenGigE0/0/0/7",
                    "TenGigE0/3/0/2",
                    "TenGigE0/3/0/3",
                ],
            ),
            "Bundle-Ether200": BackhaulLink(
                description="EQ-RTR-01 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "HundredGigE0/3/1/1",
                    "HundredGigE0/3/1/2",
                ],
            ),
            "Bundle-Ether300": BackhaulLink(
                description="EQ-RTR-01 → KKT-Core-03",
                remote_device_ip="192.168.202.153",
                members=[
                    "TenGigE0/3/0/8",
                    "TenGigE0/3/0/9",
                ],
            ),
            "Bundle-Ether600": BackhaulLink(
                description="EQ-RTR-01 → EQ-RTR-02",
                remote_device_ip="192.168.203.3",
                members=[
                    "FortyGigE0/0/0/12",
                    "FortyGigE0/0/0/13",
                    "HundredGigE0/0/1/3",
                    "HundredGigE0/0/2/3",
                    "FortyGigE0/3/0/12",
                    "FortyGigE0/3/0/13",
                    "HundredGigE0/3/1/3",
                ],
            ),
        },
    ),
    # ── KKT-Core-01 (192.168.202.2) ────────────────────────────────────────
    "192.168.202.2": DeviceTopology(
        name="KKT-Core-01",
        upstreams={
            "Bundle-Ether500": BackhaulLink(
                description="KKT-Core-01 → EQ-RTR-01",
                remote_device_ip="192.168.203.1",
                members=[
                    "TenGigE0/0/1/5",
                    "TenGigE0/0/1/7",
                    "TenGigE0/1/0/4",
                    "TenGigE0/1/0/10",
                    "TenGigE0/1/0/11",
                    "TenGigE0/1/0/16",
                    "TenGigE0/1/0/17",
                    "TenGigE0/1/0/18",
                    "TenGigE0/5/1/2",
                    "TenGigE0/5/1/3",
                ],
            ),
            "Bundle-Ether505": BackhaulLink(
                description="KKT-Core-01 → EQ-RTR-02",
                remote_device_ip="192.168.203.3",
                members=[
                    "TenGigE0/0/1/0",
                    "TenGigE0/0/1/1",
                    "TenGigE0/1/0/3",
                    "TenGigE0/1/0/20",
                    "TenGigE0/1/0/22",
                ],
            ),
            "Bundle-Ether400": BackhaulLink(
                description="KKT-Core-01 → DHK-Core-03",
                remote_device_ip="192.168.200.11",
                members=[
                    "TenGigE0/0/1/3",
                    "TenGigE0/0/1/6",
                    "TenGigE0/1/0/0",
                    "TenGigE0/1/0/1",
                    "TenGigE0/1/0/2",
                    "TenGigE0/1/0/9",
                    "TenGigE0/1/0/15",
                    "TenGigE0/1/0/23",
                    "TenGigE0/5/1/6",
                    "TenGigE0/5/1/7",
                    "TenGigE0/5/1/8",
                    "TenGigE0/5/1/9",
                    "TenGigE0/5/1/10",
                    "TenGigE0/5/1/11",
                    "TenGigE0/5/1/12",
                    "TenGigE0/5/1/13",
                    "TenGigE0/5/1/17",
                ],
            ),
        },
    ),
    # ── KKT-Core-02 (192.168.202.130) ──────────────────────────────────────
    "192.168.202.130": DeviceTopology(
        name="KKT-Core-02",
        upstreams={
            "Bundle-Ether150": BackhaulLink(
                description="KKT-Core-02 → KKT-Core-01",
                remote_device_ip="192.168.202.2",
                members=[
                    "HundredGigE0/0/0/0",
                    "HundredGigE0/0/0/1",
                ],
            ),
        },
    ),
    # ── DHK-Core-03 (192.168.200.11) ───────────────────────────────────────
    "192.168.200.11": DeviceTopology(
        name="DHK-Core-03",
        upstreams={
            "Bundle-Ether400": BackhaulLink(
                description="DHK-Core-03 → KKT-Core-01",
                remote_device_ip="192.168.202.2",
                members=[
                    "TenGigE0/0/0/0",
                    "TenGigE0/0/0/1",
                    "TenGigE0/0/0/2",
                    "TenGigE0/0/0/4",
                    "TenGigE0/0/0/5",
                    "TenGigE0/0/0/8",
                ],
            ),
            "Bundle-Ether150": BackhaulLink(
                description="DHK-Core-03 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "TenGigE0/0/0/3",
                    "TenGigE0/0/0/6",
                    "TenGigE0/0/0/7",
                    "TenGigE0/0/0/9",
                    "TenGigE0/0/0/10",
                    "TenGigE0/0/0/11",
                    "TenGigE0/0/0/12/0",
                    "TenGigE0/0/0/12/1",
                    "TenGigE0/0/0/12/2",
                    "TenGigE0/0/0/13/0",
                    "TenGigE0/0/0/13/2",
                ],
            ),
            # Bundle-Ether100 physical members not in extracted running configs
            "Bundle-Ether100": BackhaulLink(
                description="DHK-Core-03 → DHK-Core-02",
                remote_device_ip="192.168.200.4",
                members=[],
            ),
        },
    ),
    # ── COX-Core-01 (192.168.200.8) ────────────────────────────────────────
    "192.168.200.8": DeviceTopology(
        name="COX-Core-01",
        upstreams={
            "Bundle-Ether13": BackhaulLink(
                description="COX-Core-01 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "HundredGigE0/7/0/0",
                ],
            ),
        },
    ),
    # ── EQ-RTR-02 (192.168.203.3) ─────────────────────────────────────────
    "192.168.203.3": DeviceTopology(
        name="Equinix-RTR-2",
        upstreams={
            "Bundle-Ether600": BackhaulLink(
                description="EQ-RTR-02 → EQ-RTR-01",
                remote_device_ip="192.168.203.1",
                members=[
                    "HundredGigE0/0/2/3",
                    "HundredGigE0/3/1/3",
                    "HundredGigE0/3/2/3",
                ],
            ),
            "Bundle-Ether505": BackhaulLink(
                description="EQ-RTR-02 → KKT-Core-01",
                remote_device_ip="192.168.202.2",
                members=[
                    "TenGigE0/0/0/6",
                    "TenGigE0/0/1/7",
                    "TenGigE0/0/1/8",
                    "TenGigE0/0/1/9",
                    "TenGigE0/0/1/10",
                ],
            ),
            "Bundle-Ether500": BackhaulLink(
                description="EQ-RTR-02 → COX-Core-02",
                remote_device_ip="192.168.200.6",
                members=[
                    "TenGigE0/0/0/1",
                    "TenGigE0/0/0/2",
                    "TenGigE0/0/0/3",
                    "TenGigE0/0/0/4",
                    "TenGigE0/3/0/0",
                    "TenGigE0/3/0/1",
                    "TenGigE0/3/0/2",
                    "TenGigE0/3/0/3",
                ],
            ),
            "Bundle-Ether210": BackhaulLink(
                description="EQ-RTR-02 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "HundredGigE0/3/1/2",
                ],
            ),
            "Bundle-Ether400": BackhaulLink(
                description="EQ-RTR-02 → COX-Core-04",
                remote_device_ip="192.168.200.27",
                members=[],
            ),
        },
    ),
    # ── KKT-Core-03 (192.168.202.153) ─────────────────────────────────────
    "192.168.202.153": DeviceTopology(
        name="KKT-Core-3",
        upstreams={
            "Bundle-Ether300": BackhaulLink(
                description="KKT-Core-03 → EQ-RTR-01",
                remote_device_ip="192.168.203.1",
                members=[
                    "TenGigE0/0/0/0",
                    "TenGigE0/0/0/1",
                    "TenGigE0/0/0/2",
                    "TenGigE0/0/0/3",
                ],
            ),
            "Bundle-Ether200": BackhaulLink(
                description="KKT-Core-03 → KKT-Core-02",
                remote_device_ip="192.168.202.130",
                members=[
                    "HundredGigE0/0/2/0",
                ],
            ),
        },
    ),
    # ── COX-Core-03 (192.168.200.26) ──────────────────────────────────────
    "192.168.200.26": DeviceTopology(
        name="COX-Core-3",
        upstreams={
            "Bundle-Ether200": BackhaulLink(
                description="COX-Core-03 → EQ-RTR-01",
                remote_device_ip="192.168.203.1",
                members=[
                    "HundredGigE0/0/1/1",
                    "HundredGigE0/0/2/1",
                ],
            ),
            "Bundle-Ether210": BackhaulLink(
                description="COX-Core-03 → EQ-RTR-02",
                remote_device_ip="192.168.203.3",
                members=[
                    "HundredGigE0/0/2/3",
                ],
            ),
            "Bundle-Ether150": BackhaulLink(
                description="COX-Core-03 → DHK-Core-03",
                remote_device_ip="192.168.200.11",
                members=[
                    "TenGigE0/0/0/3",
                    "TenGigE0/0/0/4",
                    "TenGigE0/0/0/5",
                    "TenGigE0/0/0/6",
                    "TenGigE0/0/0/9",
                    "TenGigE0/0/0/10",
                    "TenGigE0/2/0/0",
                    "TenGigE0/2/0/1",
                    "TenGigE0/2/0/2",
                    "TenGigE0/2/0/3",
                    "TenGigE0/2/0/4",
                ],
            ),
            "Bundle-Ether31": BackhaulLink(
                description="COX-Core-03 → COX-Core-01",
                remote_device_ip="192.168.200.8",
                members=[
                    "HundredGigE0/0/1/0",
                ],
            ),
            "Bundle-Ether34": BackhaulLink(
                description="COX-Core-03 → COX-Core-02",
                remote_device_ip="192.168.200.6",
                members=[
                    "HundredGigE0/0/2/2",
                ],
            ),
            "Bundle-Ether43": BackhaulLink(
                description="COX-Core-03 → COX-Core-04",
                remote_device_ip="192.168.200.27",
                members=[],
            ),
        },
    ),
    # ── DHK-Core-02 (192.168.200.4) ───────────────────────────────────────
    "192.168.200.4": DeviceTopology(
        name="DHK-Core-2-Agg",
        upstreams={
            "Bundle-Ether100": BackhaulLink(
                description="DHK-Core-02 → DHK-Core-03",
                remote_device_ip="192.168.200.11",
                members=[],
            ),
        },
    ),
    # ── COX-Core-02 (192.168.200.6) ───────────────────────────────────────
    "192.168.200.6": DeviceTopology(
        name="COX-Core-2",
        upstreams={
            "Bundle-Ether43": BackhaulLink(
                description="COX-Core-02 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "HundredGigE0/7/0/0",
                ],
            ),
            "Bundle-Ether500": BackhaulLink(
                description="COX-Core-02 → EQ-RTR-02",
                remote_device_ip="192.168.203.3",
                members=[
                    "TenGigE0/1/0/1",
                    "TenGigE0/1/0/2",
                    "TenGigE0/1/0/3",
                    "TenGigE0/1/1/1",
                    "TenGigE0/4/0/0",
                    "TenGigE0/4/0/1",
                    "TenGigE0/7/1/3",
                    "TenGigE0/7/1/4",
                ],
            ),
            "Bundle-Ether24": BackhaulLink(
                description="COX-Core-02 → COX-Core-04",
                remote_device_ip="192.168.200.27",
                members=[],
            ),
        },
    ),
    # ── COX-Core-04 (192.168.200.27) ──────────────────────────────────────
    "192.168.200.27": DeviceTopology(
        name="COX-Core-4",
        upstreams={
            "Bundle-Ether43": BackhaulLink(
                description="COX-Core-04 → COX-Core-03",
                remote_device_ip="192.168.200.26",
                members=[
                    "HundredGigE0/0/2/2",
                ],
            ),
            "Bundle-Ether400": BackhaulLink(
                description="COX-Core-04 → EQ-RTR-02",
                remote_device_ip="192.168.203.3",
                members=[
                    "TenGigE0/0/0/9",
                    "TenGigE0/0/0/10",
                    "TenGigE0/0/0/11",
                ],
            ),
            "Bundle-Ether42": BackhaulLink(
                description="COX-Core-04 → COX-Core-02",
                remote_device_ip="192.168.200.6",
                members=[
                    "HundredGigE0/0/1/0",
                ],
            ),
        },
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_link_remote(device_ip: str, bundle: str) -> str | None:
    """Return the remote-device IP at the far end of *bundle* on *device_ip*.

    Each backbone bundle is a single point-to-point link between exactly two
    devices.  This returns the IP of the device on the other end of *bundle*.

    Correlation is **per physical link** — the network is multi-homed, so a
    single upstream/backhaul failure does not isolate transitively-downstream
    devices.  Only the two endpoints of a failed link are correlated, which is
    why a direct (non-transitive) remote lookup is all that is needed.

    Parameters
    ----------
    device_ip:
        Syslog source IP of the local device.
    bundle:
        Bundle interface name (e.g. ``Bundle-Ether500``).

    Returns
    -------
    str | None
        The remote device IP, or ``None`` if *device_ip* is unknown or has no
        bundle named *bundle*.
    """
    topo = NETWORK_TOPOLOGY.get(device_ip)
    if topo is None:
        return None
    link = topo.upstreams.get(bundle)
    return link.remote_device_ip if link is not None else None


def is_backhaul_member(device_ip: str, interface: str) -> tuple[bool, str]:
    """Check whether *interface* is a member of a backhaul bundle on *device_ip*.

    Parameters
    ----------
    device_ip:
        Syslog source IP of the device.
    interface:
        The physical interface name to check (e.g. ``TenGigE0/0/0/0``).

    Returns
    -------
    tuple[bool, str]
        ``(True, bundle_name)`` if the interface is a bundle member,
        ``(False, '')`` otherwise.
    """
    topo = NETWORK_TOPOLOGY.get(device_ip)
    if topo is None:
        return (False, "")
    for bundle_name, link in topo.upstreams.items():
        if interface in link.members:
            return (True, bundle_name)
    return (False, "")
