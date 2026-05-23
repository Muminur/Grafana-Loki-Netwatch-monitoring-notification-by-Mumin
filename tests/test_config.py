"""Tests for src.config — settings from environment variables."""

import pytest

from src.config import Settings, get_settings


def test_settings_defaults() -> None:
    """Settings has sane defaults when no env vars are set."""
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


def test_loki_ws_url_constructed_from_host() -> None:
    """Loki WS URL derives from monitor_host."""
    settings = Settings()
    assert "192.168.200.230:3100" in settings.loki_ws_url
    assert settings.loki_ws_url.startswith("ws://")


def test_loki_http_url_constructed_from_host() -> None:
    """Loki HTTP URL derives from monitor_host."""
    settings = Settings()
    assert "192.168.200.230:3100" in settings.loki_http_url
    assert settings.loki_http_url.startswith("http://")


def test_grafana_url_constructed_from_host() -> None:
    """Grafana URL derives from monitor_host."""
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
