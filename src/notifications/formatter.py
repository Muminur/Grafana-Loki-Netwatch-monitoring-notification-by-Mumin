"""Message formatter for BSCCL NetWatch notifications.

Produces Discord embed dicts and Telegram Markdown strings from EnrichedLog
objects.  No I/O — pure data transformation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

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
        f"{base}/d/{uid}/bsccl-netwatch"
        f"?orgId=1&from={from_ms}&to={to_ms}"
        f"&var-device={enriched.device_name}"
    )


def _build_discord_fields(enriched: EnrichedLog) -> list[dict[str, Any]]:
    """Build the Discord embed fields list from enriched log data."""
    fields: list[dict[str, Any]] = []

    def _add(name: str, value: str, inline: bool = True) -> None:
        if value:
            fields.append({"name": name, "value": value, "inline": inline})

    _add("Device", enriched.device_name)
    _add("Location", enriched.device_location)
    _add("Event", enriched.event_type)

    if enriched.bgp_neighbor:
        peer_label = enriched.bgp_neighbor
        if enriched.as_name:
            peer_label += f" (AS{enriched.as_number} {enriched.as_name})"
        elif enriched.as_number:
            peer_label += f" (AS{enriched.as_number})"
        _add("BGP Peer", peer_label, inline=False)

    if enriched.interface_name:
        iface_label = enriched.interface_name
        if enriched.interface_description:
            iface_label += f" — {enriched.interface_description}"
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

    title = f"{emoji} {enriched.classification} — {enriched.event_type}"
    description = (
        f"[View in Grafana]({grafana_url})\n"
        f"`{enriched.parsed.mnemonic}` on **{enriched.device_name}**"
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

    # Bold severity header
    lines.append(f"*{emoji} {enriched.classification} — {enriched.event_type}*")
    lines.append("")

    lines.append(f"*Device:* {enriched.device_name}")
    if enriched.device_location:
        lines.append(f"*Location:* {enriched.device_location}")

    if enriched.bgp_neighbor:
        peer = enriched.bgp_neighbor
        if enriched.as_name:
            peer += f" (AS{enriched.as_number} {enriched.as_name})"
        elif enriched.as_number:
            peer += f" (AS{enriched.as_number})"
        lines.append(f"*Peer:* `{peer}`")

    if enriched.interface_name:
        iface = enriched.interface_name
        if enriched.interface_description:
            iface += f" — {enriched.interface_description}"
        lines.append(f"*Interface:* `{iface}`")

    if enriched.vrf:
        lines.append(f"*VRF:* {enriched.vrf}")

    if enriched.client_name:
        lines.append(f"*Client:* {enriched.client_name}")

    lines.append("")
    ts_str = enriched.parsed.timestamp.strftime("%Y-%m-%d %H:%M:%S %Z")
    lines.append(f"_{ts_str}_")

    return "\n".join(lines)
