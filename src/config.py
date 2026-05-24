"""Application configuration loaded from environment variables."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent.parent / ".env"

# ---------------------------------------------------------------------------
# MONITOR_HOST validation
# ---------------------------------------------------------------------------

# Reject anything that looks like a URI scheme (e.g. file://, http://).
_SCHEME_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+\-.]*://")

# Minimal hostname / IPv4 / IPv6-bracket validity check.
# Accepts dotted-decimal IPv4, bracketed IPv6, and RFC-1123 hostnames.
_HOSTNAME_RE = re.compile(
    r"""
    ^
    (
        # IPv4: four octets 0-255
        (?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)
        |
        # IPv6 bracket form: [::1] etc.
        \[[\da-fA-F:]+\]
        |
        # Hostname: labels of alnum + hyphen, no leading/trailing hyphen
        (?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*
        [a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?
    )
    $
    """,
    re.VERBOSE,
)


def _validate_monitor_host(value: str) -> str:
    """Validate *value* as a safe host for outbound connections.

    Raises
    ------
    ValueError
        When *value* is empty, contains a URI scheme, or does not match a
        valid IP address or hostname pattern.  This guards against SSRF via
        mis-configuration (e.g. ``file://...`` or an empty string that would
        produce a malformed URL).
    """
    if not value or not value.strip():
        msg = "MONITOR_HOST must not be empty"
        raise ValueError(msg)
    v = value.strip()
    if _SCHEME_RE.match(v):
        msg = f"MONITOR_HOST must be a hostname or IP address, not a URI: {value!r}"
        raise ValueError(msg)
    # Anything that looks like an IP (dotted-decimal, or contains ':' for IPv6,
    # or a bracketed IPv6 literal) must be a *valid* IP — this rejects malformed
    # values such as "256.0.0.1" or "1.2.3.4.5" that would otherwise slip
    # through the hostname-label pattern.
    bracketed = v.startswith("[") and v.endswith("]")
    candidate = v[1:-1] if bracketed else v
    if bracketed or ":" in candidate or re.fullmatch(r"[0-9.]+", candidate):
        try:
            ipaddress.ip_address(candidate)
        except ValueError as exc:
            msg = f"MONITOR_HOST is not a valid IP address: {value!r}"
            raise ValueError(msg) from exc
        return v
    if not _HOSTNAME_RE.match(v):
        msg = f"MONITOR_HOST is not a valid hostname or IP address: {value!r}"
        raise ValueError(msg)
    return v


# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Settings:
    """Application settings derived from environment variables."""

    monitor_host: str = field(
        default_factory=lambda: _validate_monitor_host(
            os.environ.get("MONITOR_HOST", "192.168.200.230")
        )
    )
    syslog_mode: str = field(
        default_factory=lambda: os.environ.get("SYSLOG_MODE", "loki_ws")
    )
    syslog_udp_port: int = field(
        default_factory=lambda: int(os.environ.get("SYSLOG_UDP_PORT", "1514"))
    )
    database_url: str = field(
        default_factory=lambda: os.environ.get(
            "DATABASE_URL", "sqlite+aiosqlite:///bsccl_netwatch.db"
        )
    )
    web_host: str = field(default_factory=lambda: os.environ.get("WEB_HOST", "0.0.0.0"))
    web_port: int = field(
        default_factory=lambda: int(os.environ.get("WEB_PORT", "8080"))
    )
    discord_webhook_url: str = field(
        default_factory=lambda: os.environ.get("DISCORD_WEBHOOK_URL", ""),
        repr=False,
    )
    discord_enabled: bool = field(
        default_factory=lambda: os.environ.get("DISCORD_ENABLED", "false").lower()
        == "true"
    )
    telegram_bot_token: str = field(
        default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        repr=False,
    )
    telegram_chat_id: str = field(
        default_factory=lambda: os.environ.get("TELEGRAM_CHAT_ID", "")
    )
    telegram_enabled: bool = field(
        default_factory=lambda: os.environ.get("TELEGRAM_ENABLED", "false").lower()
        == "true"
    )
    grafana_api_key: str = field(
        default_factory=lambda: os.environ.get("GRAFANA_API_KEY", ""),
        repr=False,
    )
    grafana_dashboard_uid: str = field(
        default_factory=lambda: os.environ.get("GRAFANA_DASHBOARD_UID", "8sWAY1LMz")
    )
    dedup_window_seconds: int = field(
        default_factory=lambda: int(os.environ.get("DEDUP_WINDOW_SECONDS", "300"))
    )
    bgp_flap_window_seconds: int = field(
        default_factory=lambda: int(os.environ.get("BGP_FLAP_WINDOW_SECONDS", "120"))
    )
    bundle_group_window_seconds: int = field(
        default_factory=lambda: int(os.environ.get("BUNDLE_GROUP_WINDOW_SECONDS", "30"))
    )
    asn_api_key: str = field(
        default_factory=lambda: os.environ.get("ASN_API_KEY", ""),
        repr=False,
    )
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.environ.get(
                "CORS_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080"
            ).split(",")
            if o.strip()
        ]
    )

    @property
    def loki_datasource_id(self) -> int:
        """Grafana Loki datasource ID for proxy access."""
        return int(os.environ.get("LOKI_DATASOURCE_ID", "37"))

    @property
    def loki_query(self) -> str:
        """Loki log query selector."""
        return os.environ.get("LOKI_QUERY", '{job="Router-Logs"}')

    @property
    def loki_ws_url(self) -> str:
        """WebSocket URL for Loki tail via Grafana proxy."""
        return (
            f"ws://{self.monitor_host}:3000"
            f"/api/datasources/proxy/{self.loki_datasource_id}"
            f"/loki/api/v1/tail"
        )

    @property
    def loki_http_url(self) -> str:
        """HTTP URL for Loki query_range via Grafana proxy."""
        return (
            f"http://{self.monitor_host}:3000"
            f"/api/datasources/proxy/{self.loki_datasource_id}"
            f"/loki/api/v1/query_range"
        )

    @property
    def grafana_url(self) -> str:
        """Grafana base URL."""
        return f"http://{self.monitor_host}:3000"


def get_settings() -> Settings:
    """Create settings instance from current environment."""
    load_dotenv(_env_path, override=False)
    return Settings()
