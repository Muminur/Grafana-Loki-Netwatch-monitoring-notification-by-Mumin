"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_env_path = Path(__file__).resolve().parent.parent / ".env"


@dataclass(frozen=True)
class Settings:
    """Application settings derived from environment variables."""

    monitor_host: str = field(
        default_factory=lambda: os.environ.get("MONITOR_HOST", "192.168.200.230")
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
        default_factory=lambda: os.environ.get("DISCORD_WEBHOOK_URL", "")
    )
    discord_enabled: bool = field(
        default_factory=lambda: os.environ.get("DISCORD_ENABLED", "false").lower()
        == "true"
    )
    telegram_bot_token: str = field(
        default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN", "")
    )
    telegram_chat_id: str = field(
        default_factory=lambda: os.environ.get("TELEGRAM_CHAT_ID", "")
    )
    telegram_enabled: bool = field(
        default_factory=lambda: os.environ.get("TELEGRAM_ENABLED", "false").lower()
        == "true"
    )
    grafana_api_key: str = field(
        default_factory=lambda: os.environ.get("GRAFANA_API_KEY", "")
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
