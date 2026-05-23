"""Enrichment engine for BSCCL NetWatch.

Takes a ``ParsedLog`` produced by the parser and enriches it with:
  - Device name + location (from device_map)
  - Interface name + description + bundle + client (from interface_map)
  - AS number + AS name (from as_database)
  - BGP neighbor IP
  - VRF name
  - Classification result (from classifier)

The enricher is a *pure data* module — it imports only from the static data
modules and the classifier.  No database, no I/O, no side effects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.core.classifier import classify
from src.data.as_database import lookup_as
from src.data.device_map import lookup_device
from src.data.interface_map import lookup_interface

if TYPE_CHECKING:
    from src.core.parser import ParsedLog


# ---------------------------------------------------------------------------
# Compiled extraction patterns
# ---------------------------------------------------------------------------

# Interface patterns — ordered from most specific to least.
# Each pattern captures the interface name from a different syslog message style:
#   1. Explicit Interface keyword (remote fault, BER, interface up/down)
#   2. Interface type token followed by "is now/no longer Active" (LACP)
#   3. ifname field (port creation failure — uses underscore separators)
#   4. detected-on phrase (duplicate IPv6 address)
#   5. SFP alarm pipe-delimited format Set/Clear
_IFACE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"\bInterface\s+((?:TenGigE|HundredGigE|GigabitEthernet|GigE|Bundle-Ether|FortyGigE|FiftyGigE|TwentyFiveGigE)\S+)"
    ),
    re.compile(
        r"\b((?:TenGigE|HundredGigE|GigabitEthernet|GigE|Bundle-Ether|FortyGigE|FiftyGigE|TwentyFiveGigE)\S+)\s+is\s+(?:now|no\s+longer)\s+Active"
    ),  # noqa: ERA001
    re.compile(r"\bifname:\s+(\S+)"),
    re.compile(r"\bdetected\s+on\s+(Bundle-Ether\d+)"),
    re.compile(
        r"(?:Set|Clear)\|[^|]*\|[^|]*\|((?:GigE|TenGigE|HundredGigE|GigabitEthernet)\S+)"
    ),
]

# BGP neighbour — "neighbor 2001:de8:4::39:9077:1"
_BGP_NEIGHBOR_RE = re.compile(r"\bneighbor\s+(\S+)")

# AS number — "(AS: 399077)" or "(AS 399077)"
_AS_RE = re.compile(r"\(AS[:\s]\s*(\d+)\)")

# VRF — "(VRF: network)"
_VRF_RE = re.compile(r"\(VRF:\s*(\w+)\)")


# ---------------------------------------------------------------------------
# EnrichedLog dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrichedLog:
    """Immutable enriched representation of a single syslog event.

    Combines the raw parsed fields with device, interface, AS, and
    classification data.
    """

    # From parser
    parsed: ParsedLog
    # From classifier
    classification: str  # CRITICAL / WARNING / INFO / NOISE / USER_LOGIN
    rule_id: str  # matched rule ID, or "UNKNOWN"
    event_type: str  # human-readable event type
    notify: bool  # True → send Discord/Telegram notification
    # From device_map
    device_name: str  # e.g. "Equinix-RTR-1" or "UNKNOWN-{ip}"
    device_location: str  # e.g. "Singapore Equinix" or ""
    # From interface_map
    interface_name: str  # e.g. "TenGigE0/0/0/0" or ""
    interface_description: str  # from interface_map or ""
    bundle_parent: str  # from interface_map or ""
    client_name: str  # derived from interface description or ""
    # From AS / BGP extraction
    bgp_neighbor: str  # e.g. "2001:de8:4::39:9077:1" or ""
    as_number: int  # extracted AS number or 0
    as_name: str  # from as_database or ""
    vrf: str  # extracted VRF name or ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_interface(message: str) -> str:
    """Extract the first interface name from a syslog message.

    Returns an empty string when no interface pattern matches.
    Trailing punctuation (commas, periods, semicolons) is stripped.
    """
    for pattern in _IFACE_PATTERNS:
        m = pattern.search(message)
        if m:
            return m.group(1).rstrip(",.;:")
    return ""


def _extract_bgp_neighbor(message: str) -> str:
    """Extract the BGP neighbor IP/address from a syslog message."""
    m = _BGP_NEIGHBOR_RE.search(message)
    return m.group(1) if m else ""


def _extract_as_number(raw: str) -> int:
    """Extract an AS number from the raw syslog line.

    Matches patterns like ``(AS: 399077)`` or ``(AS 399077)``.
    Returns 0 when not found.
    """
    m = _AS_RE.search(raw)
    return int(m.group(1)) if m else 0


def _extract_vrf(raw: str) -> str:
    """Extract the VRF name from the raw syslog line.

    Matches ``(VRF: <name>)``.  Returns an empty string when absent.
    """
    m = _VRF_RE.search(raw)
    return m.group(1) if m else ""


def _derive_client(description: str) -> str:
    """Best-effort derivation of a client name from an interface description.

    Many BSCCL interface descriptions are already the client/circuit name,
    so we return the description as-is if it is short enough to be meaningful.
    For descriptions that are long paths/labels we return the first token.
    """
    if not description:
        return ""
    # If the description is 50 chars or fewer it IS the client label
    if len(description) <= 50:
        return description
    # Otherwise return the first slash- or space-delimited token
    return re.split(r"[\s/]", description, maxsplit=1)[0]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enrich(parsed: ParsedLog) -> EnrichedLog:
    """Enrich a parsed syslog line with device, interface, AS, and classification data.

    Parameters
    ----------
    parsed:
        A :class:`~src.core.parser.ParsedLog` produced by
        :func:`~src.core.parser.parse_syslog`.

    Returns
    -------
    EnrichedLog
        A frozen dataclass combining all enrichment fields.  Unknown / absent
        fields default to empty string or zero rather than ``None`` so that
        callers never need to guard against ``None``.
    """
    # ── Classification ─────────────────────────────────────────────────────
    cls_result = classify(parsed)

    # ── Device lookup ──────────────────────────────────────────────────────
    device_info = lookup_device(parsed.source_ip)
    if device_info is not None:
        device_name = device_info.name
        device_location = device_info.location
        hostname = device_info.hostname
    else:
        device_name = f"UNKNOWN-{parsed.source_ip}"
        device_location = ""
        hostname = ""

    # ── Interface extraction ───────────────────────────────────────────────
    iface_raw = _extract_interface(parsed.message)
    iface_description = ""
    bundle_parent = ""
    client_name = ""

    if iface_raw and hostname:
        iface_info = lookup_interface(hostname, iface_raw)
        if iface_info is not None:
            iface_description = iface_info.description
            bundle_parent = iface_info.bundle or ""
            client_name = _derive_client(iface_info.description)

    # ── AS / BGP / VRF extraction ──────────────────────────────────────────
    bgp_neighbor = _extract_bgp_neighbor(parsed.message)
    as_number = _extract_as_number(parsed.raw)
    vrf = _extract_vrf(parsed.raw)

    as_name = ""
    if as_number:
        as_info = lookup_as(as_number)
        if as_info is not None:
            as_name = as_info.name

    return EnrichedLog(
        parsed=parsed,
        classification=cls_result.classification,
        rule_id=cls_result.rule_id,
        event_type=cls_result.event_type,
        notify=cls_result.notify,
        device_name=device_name,
        device_location=device_location,
        interface_name=iface_raw,
        interface_description=iface_description,
        bundle_parent=bundle_parent,
        client_name=client_name,
        bgp_neighbor=bgp_neighbor,
        as_number=as_number,
        as_name=as_name,
        vrf=vrf,
    )
