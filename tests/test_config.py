"""Tests for src.config — settings from environment variables."""

import pytest

from src.config import Settings, get_settings


def test_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings has sane defaults when no env vars are set."""
    for var in (
        "MONITOR_HOST",
        "SYSLOG_MODE",
        "SYSLOG_UDP_PORT",
        "DATABASE_URL",
        "WEB_HOST",
        "WEB_PORT",
        "DISCORD_WEBHOOK_URL",
        "DISCORD_ENABLED",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "TELEGRAM_ENABLED",
        "GRAFANA_API_KEY",
        "GRAFANA_DASHBOARD_UID",
        "DEDUP_WINDOW_SECONDS",
        "BGP_FLAP_WINDOW_SECONDS",
        "BUNDLE_GROUP_WINDOW_SECONDS",
        "LOKI_DATASOURCE_ID",
        "LOKI_QUERY",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = Settings()
    assert settings.monitor_host == "192.168.200.230"
    assert settings.web_port == 8080
    assert settings.syslog_udp_port == 1514
    assert settings.syslog_mode == "loki_ws"
    assert settings.discord_enabled is False
    assert settings.telegram_enabled is False
    assert settings.dedup_window_seconds == 300
    assert settings.bgp_flap_window_seconds == 120
    assert settings.bundle_group_window_seconds == 30
    assert settings.grafana_dashboard_uid == "8sWAY1LMz"


def test_loki_ws_url_constructed_from_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loki WS URL derives from monitor_host via Grafana proxy."""
    monkeypatch.delenv("MONITOR_HOST", raising=False)
    settings = Settings()
    assert "192.168.200.230:3000" in settings.loki_ws_url
    assert settings.loki_ws_url.startswith("ws://")
    assert "/api/datasources/proxy/37/" in settings.loki_ws_url
    assert "/loki/api/v1/tail" in settings.loki_ws_url


def test_loki_http_url_constructed_from_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loki HTTP URL derives from monitor_host via Grafana proxy."""
    monkeypatch.delenv("MONITOR_HOST", raising=False)
    settings = Settings()
    assert "192.168.200.230:3000" in settings.loki_http_url
    assert settings.loki_http_url.startswith("http://")
    assert "/api/datasources/proxy/37/" in settings.loki_http_url
    assert "/loki/api/v1/query_range" in settings.loki_http_url


def test_grafana_url_constructed_from_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Grafana URL derives from monitor_host."""
    monkeypatch.delenv("MONITOR_HOST", raising=False)
    settings = Settings()
    assert "192.168.200.230:3000" in settings.grafana_url


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Settings reads from environment variables."""
    monkeypatch.setenv("MONITOR_HOST", "103.16.152.8")
    monkeypatch.setenv("WEB_PORT", "9090")
    monkeypatch.setenv("DISCORD_ENABLED", "true")
    monkeypatch.setenv("TELEGRAM_ENABLED", "TRUE")
    settings = Settings()
    assert settings.monitor_host == "103.16.152.8"
    assert settings.web_port == 9090
    assert settings.discord_enabled is True
    assert settings.telegram_enabled is True
    assert "103.16.152.8" in settings.loki_ws_url
    assert "103.16.152.8" in settings.grafana_url


def test_get_settings_returns_instance() -> None:
    """get_settings() returns a Settings instance."""
    settings = get_settings()
    assert isinstance(settings, Settings)


def test_settings_is_frozen() -> None:
    """Settings is immutable (frozen dataclass)."""
    settings = Settings()
    with pytest.raises(AttributeError):
        settings.monitor_host = "changed"  # type: ignore[misc]
