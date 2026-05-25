"""Message formatter for BSCCL NetWatch notifications.

Produces Discord embed dicts and Telegram Markdown strings from EnrichedLog
objects.  No I/O — pure data transformation.

All string fields sourced from log content are passed through sanitisation
helpers before being embedded in payload structures.  The payloads are always
serialised to JSON (via ``httpx``'s ``json=`` parameter), so there is no
risk of HTTP-body injection; however, we still scrub control characters and
overly-long strings defensively to avoid payload truncation issues on the
receiving end.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

# ─────────────────────────────────────────────────────────────────────────────
# Injection / sanitisation helpers
# ─────────────────────────────────────────────────────────────────────────────

_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_FIELD_LEN = 1024  # Discord embed field value limit
_MAX_TEXT_LEN = 4096  # Telegram message limit


def _sanitise(value: str, max_len: int = _MAX_FIELD_LEN) -> str:
    """Strip ASCII control characters and truncate *value* to *max_len* chars.

    This is a defence-in-depth measure.  Because all payloads are transmitted
    as JSON (via ``httpx``'s ``json=`` parameter, which uses ``json.dumps``
    internally), there is no string-concatenation path that could allow log
    content to escape the payload structure.  Nevertheless, removing stray
    control characters prevents display artefacts in Discord/Telegram clients.
    """
    cleaned = _CTRL_RE.sub("", value)
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 1] + "…"  # … ellipsis
    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_COLORS: dict[str, int] = {
    "CRITICAL": 0xFF0040,
    "WARNING": 0xFFD700,
    "INFO": 0x00D4FF,
    "USER_LOGIN": 0x00FF88,
    "NOISE": 0x444466,
}

_EMOJIS: dict[str, str] = {
    "CRITICAL": "🔴",
    "WARNING": "🟡",
    "INFO": "🔵",
    "USER_LOGIN": "👤",
    "NOISE": "⚪",
}

_GRAFANA_RANGE_MS = 5 * 60 * 1000  # ±5 minutes in milliseconds


# ─────────────────────────────────────────────────────────────────────────────
# Public helpers
# ─────────────────────────────────────────────────────────────────────────────


def severity_emoji(classification: str) -> str:
    """Return an emoji for the given classification level.

    Parameters
    ----------
    classification:
        One of CRITICAL / WARNING / INFO / USER_LOGIN / NOISE.

    Returns
    -------
    str
        A Unicode emoji string; falls back to ⚪ for unknown values.
    """
    return _EMOJIS.get(classification, "⚪")


def _grafana_deep_link(enriched: EnrichedLog, settings: Settings) -> str:
    """Build a Grafana Explore deep-link scoped ±5 min around the event."""
    ts = enriched.parsed.timestamp
    # Convert to epoch milliseconds
    epoch_ms = int(ts.timestamp() * 1000)
    from_ms = epoch_ms - _GRAFANA_RANGE_MS
    to_ms = epoch_ms + _GRAFANA_RANGE_MS

    base = settings.grafana_url
    uid = settings.grafana_dashboard_uid
    return (
        f"{base}/d/{uid}/log-dashboard"
        f"?orgId=1&from={from_ms}&to={to_ms}"
        f"&var-device={enriched.device_name}"
    )


def _build_discord_fields(enriched: EnrichedLog) -> list[dict[str, Any]]:
    """Build the Discord embed fields list from enriched log data."""
    fields: list[dict[str, Any]] = []

    def _add(name: str, value: str, inline: bool = True) -> None:
        safe_value = _sanitise(value)
        if safe_value:
            fields.append({"name": name, "value": safe_value, "inline": inline})

    _add("Device", enriched.device_name)
    _add("Location", enriched.device_location)
    _add("Event", enriched.event_type)

    if enriched.bgp_neighbor:
        peer_label = _sanitise(enriched.bgp_neighbor)
        if enriched.as_name:
            peer_label += f" (AS{enriched.as_number} {_sanitise(enriched.as_name)})"
        elif enriched.as_number:
            peer_label += f" (AS{enriched.as_number})"
        _add("BGP Peer", peer_label, inline=False)

    if enriched.interface_name:
        iface_label = _sanitise(enriched.interface_name)
        if enriched.interface_description:
            iface_label += f" — {_sanitise(enriched.interface_description)}"
        _add("Interface", iface_label, inline=False)

    if enriched.vrf:
        _add("VRF", enriched.vrf)

    if enriched.client_name:
        _add("Client", enriched.client_name)

    return fields


# ─────────────────────────────────────────────────────────────────────────────
# Discord
# ─────────────────────────────────────────────────────────────────────────────


def format_discord_embed(enriched: EnrichedLog, settings: Settings) -> dict[str, Any]:
    """Format an EnrichedLog as a Discord webhook payload (embed dict).

    Parameters
    ----------
    enriched:
        Fully enriched syslog event.
    settings:
        Application settings (used to build Grafana deep-link URL and
        determine the monitor host).

    Returns
    -------
    dict
        Ready-to-POST Discord webhook payload with a single embed.
    """
    emoji = severity_emoji(enriched.classification)
    color = _COLORS.get(enriched.classification, 0x444466)
    grafana_url = _grafana_deep_link(enriched, settings)

    safe_event_type = _sanitise(enriched.event_type)
    safe_mnemonic = _sanitise(enriched.parsed.mnemonic)
    safe_device = _sanitise(enriched.device_name)

    title = f"{emoji} {enriched.classification} — {safe_event_type}"
    description = (
        f"[View in Grafana]({grafana_url})\n`{safe_mnemonic}` on **{safe_device}**"
    )

    fields = _build_discord_fields(enriched)

    ts_iso = enriched.parsed.timestamp.isoformat()

    embed: dict[str, Any] = {
        "title": title,
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": "BSCCL NetWatch"},
        "timestamp": ts_iso,
    }

    return {"embeds": [embed]}


# ─────────────────────────────────────────────────────────────────────────────
# Telegram
# ─────────────────────────────────────────────────────────────────────────────


def format_telegram_message(enriched: EnrichedLog) -> str:
    """Format an EnrichedLog as a Telegram Markdown message string.

    Parameters
    ----------
    enriched:
        Fully enriched syslog event.

    Returns
    -------
    str
        Telegram Markdown-formatted message text.
    """
    emoji = severity_emoji(enriched.classification)
    lines: list[str] = []

    # Bold severity header — sanitise user-sourced event_type
    safe_event_type = _sanitise(enriched.event_type)
    lines.append(f"*{emoji} {enriched.classification} — {safe_event_type}*")
    lines.append("")

    lines.append(f"*Device:* {_sanitise(enriched.device_name)}")
    if enriched.device_location:
        lines.append(f"*Location:* {_sanitise(enriched.device_location)}")

    if enriched.bgp_neighbor:
        peer = _sanitise(enriched.bgp_neighbor)
        if enriched.as_name:
            peer += f" (AS{enriched.as_number} {_sanitise(enriched.as_name)})"
        elif enriched.as_number:
            peer += f" (AS{enriched.as_number})"
        lines.append(f"*Peer:* `{peer}`")

    if enriched.interface_name:
        iface = _sanitise(enriched.interface_name)
        if enriched.interface_description:
            iface += f" — {_sanitise(enriched.interface_description)}"
        lines.append(f"*Interface:* `{iface}`")

    if enriched.vrf:
        lines.append(f"*VRF:* {_sanitise(enriched.vrf)}")

    if enriched.client_name:
        lines.append(f"*Client:* {_sanitise(enriched.client_name)}")

    lines.append("")
    ts_str = enriched.parsed.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
    lines.append(f"_{ts_str}_")

    raw_msg = "\n".join(lines)
    return _sanitise(raw_msg, max_len=_MAX_TEXT_LEN)


# ─────────────────────────────────────────────────────────────────────────────
# Escalation formatters
# ─────────────────────────────────────────────────────────────────────────────

# Discord escalation embed color: pure red, distinct from regular CRITICAL
# (which uses 0xFF0040) so operators can immediately identify escalations.
ESCALATION_DISCORD_COLOR = 0xFF0000


def format_escalation_discord_embed(
    enriched: EnrichedLog, elapsed_minutes: int
) -> dict[str, Any]:
    """Format an escalation notice as a Discord webhook payload.

    Uses pure red (0xFF0000) to distinguish from regular CRITICAL alerts
    (0xFF0040).  Includes elapsed time and an "UNACKNOWLEDGED" marker so
    operators know this alert has been waiting for more than 15 minutes.

    Parameters
    ----------
    enriched:
        The fully enriched syslog event being escalated.
    elapsed_minutes:
        How many minutes the alert has been unacknowledged.

    Returns
    -------
    dict
        Ready-to-POST Discord webhook payload with a single embed.
    """
    safe_device = _sanitise(enriched.device_name)
    safe_mnemonic = _sanitise(enriched.parsed.mnemonic)
    safe_iface = _sanitise(enriched.interface_name) if enriched.interface_name else ""
    safe_neighbor = _sanitise(enriched.bgp_neighbor) if enriched.bgp_neighbor else ""

    discriminator = safe_iface or safe_neighbor

    title = f"🚨 ESCALATION — {safe_device}"
    mnemonic_part = f"`{safe_mnemonic}`"
    discriminator_part = f" on `{discriminator}`" if discriminator else ""
    escalation_part = (
        f"\n**Unacknowledged for {elapsed_minutes} minutes**"
        " — CRITICAL alert requires attention"
    )
    description = mnemonic_part + discriminator_part + escalation_part

    ts_str = enriched.parsed.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")

    fields: list[dict[str, Any]] = [
        {"name": "Device", "value": safe_device, "inline": True},
    ]
    if enriched.device_location:
        fields.append(
            {
                "name": "Location",
                "value": _sanitise(enriched.device_location),
                "inline": True,
            }
        )
    fields.append(
        {
            "name": "Status",
            "value": f"UNACKNOWLEDGED FOR >{elapsed_minutes} MIN",
            "inline": True,
        }
    )
    fields.append({"name": "Original Alert", "value": ts_str, "inline": False})
    if discriminator:
        fields.append(
            {"name": "Interface / Peer", "value": discriminator, "inline": False}
        )

    embed: dict[str, Any] = {
        "title": title,
        "description": description,
        "color": ESCALATION_DISCORD_COLOR,
        "fields": fields,
        "footer": {"text": "BSCCL NetWatch — Escalation"},
        "timestamp": enriched.parsed.timestamp.isoformat(),
    }

    return {"embeds": [embed]}


def format_escalation_telegram_message(
    enriched: EnrichedLog, elapsed_minutes: int
) -> str:
    """Format an escalation notice as a Telegram Markdown message string.

    Prefixes with bold "⚠️ ESCALATION" to distinguish from regular alerts.

    Parameters
    ----------
    enriched:
        The fully enriched syslog event being escalated.
    elapsed_minutes:
        How many minutes the alert has been unacknowledged.

    Returns
    -------
    str
        Telegram Markdown-formatted escalation text.
    """
    lines: list[str] = []

    lines.append(f"*⚠️ ESCALATION — {_sanitise(enriched.device_name)}*")
    lines.append(f"*{_sanitise(enriched.parsed.mnemonic)}*")
    lines.append("")

    lines.append(f"*Unacknowledged for {elapsed_minutes} minutes*")
    lines.append("CRITICAL alert requires immediate attention")
    lines.append("")

    if enriched.interface_name:
        iface = _sanitise(enriched.interface_name)
        if enriched.interface_description:
            iface += f" — {_sanitise(enriched.interface_description)}"
        lines.append(f"*Interface:* `{iface}`")

    if enriched.bgp_neighbor:
        peer = _sanitise(enriched.bgp_neighbor)
        if enriched.as_name:
            peer += f" (AS{enriched.as_number} {_sanitise(enriched.as_name)})"
        elif enriched.as_number:
            peer += f" (AS{enriched.as_number})"
        lines.append(f"*Peer:* `{peer}`")

    if enriched.device_location:
        lines.append(f"*Location:* {_sanitise(enriched.device_location)}")

    lines.append("")
    ts_str = enriched.parsed.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
    lines.append(f"*Original Alert:* _{ts_str}_")

    raw_msg = "\n".join(lines)
    return _sanitise(raw_msg, max_len=_MAX_TEXT_LEN)
