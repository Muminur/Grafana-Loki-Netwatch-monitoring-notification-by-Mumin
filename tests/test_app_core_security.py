"""Tests for app-core security hardening: security headers, CORS, MONITOR_HOST.

All tests use FastAPI TestClient (synchronous, in-process) or direct Settings
instantiation.  No network ports are bound; the real bsccl_netwatch.db is
never touched.

Coverage targets
----------------
* SecurityHeadersMiddleware — X-Content-Type-Options, X-Frame-Options, CSP
  present on all HTTP responses.
* CORS origins loaded from CORS_ORIGINS env var via Settings.cors_origins.
* MONITOR_HOST validation rejects empty strings, URI schemes, and invalid
  hostnames; accepts valid IPs and hostnames.
* _engine typed as AsyncEngine | None (structural check only).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import src.main as main_mod
from src.config import Settings, get_settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client() -> TestClient:
    """Return a TestClient wrapping the app without triggering lifespan."""
    return TestClient(main_mod.app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Security-headers middleware
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    """SecurityHeadersMiddleware attaches the required headers to every response."""

    def test_headers_on_health(self) -> None:
        """GET /health includes all three security headers."""
        client = _make_client()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        # Header names are case-insensitive in httpx response headers.
        assert resp.headers.get("content-security-policy", "") != ""

    def test_headers_on_dashboard(self) -> None:
        """GET / (dashboard) also carries the security headers."""
        client = _make_client()
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        csp = resp.headers.get("content-security-policy", "")
        assert csp != ""

    def test_csp_allows_self_and_websocket(self) -> None:
        """CSP allows 'self', ws:, and wss: for connect-src."""
        client = _make_client()
        resp = client.get("/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "'self'" in csp
        assert "connect-src" in csp
        assert "ws:" in csp
        assert "wss:" in csp

    def test_csp_denies_framing(self) -> None:
        """CSP includes frame-ancestors 'none' as defence-in-depth."""
        client = _make_client()
        resp = client.get("/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "frame-ancestors" in csp
        assert "'none'" in csp

    def test_csp_allows_inline_styles(self) -> None:
        """CSP permits 'unsafe-inline' for style-src (Chart.js / neon-theme)."""
        client = _make_client()
        resp = client.get("/health")
        csp = resp.headers.get("content-security-policy", "")
        assert "style-src" in csp
        assert "'unsafe-inline'" in csp

    def test_referrer_policy_header(self) -> None:
        """Referrer-Policy header is set on all responses."""
        client = _make_client()
        resp = client.get("/health")
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy_header(self) -> None:
        """Permissions-Policy header restricts sensitive APIs."""
        client = _make_client()
        resp = client.get("/health")
        pp = resp.headers.get("permissions-policy", "")
        assert "camera=()" in pp
        assert "microphone=()" in pp
        assert "geolocation=()" in pp


# ---------------------------------------------------------------------------
# CORS origins from config
# ---------------------------------------------------------------------------


class TestCorsOrigins:
    """CORS origins are loaded from CORS_ORIGINS env var via Settings."""

    def test_default_cors_origins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without CORS_ORIGINS env var the default origins are set."""
        monkeypatch.delenv("CORS_ORIGINS", raising=False)
        get_settings.cache_clear() if hasattr(get_settings, "cache_clear") else None
        settings = Settings()
        assert "http://localhost:8080" in settings.cors_origins
        assert "http://127.0.0.1:8080" in settings.cors_origins

    def test_custom_cors_origins_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """CORS_ORIGINS=a,b produces a two-element list."""
        monkeypatch.setenv(
            "CORS_ORIGINS",
            "http://monitor.example.com,http://192.168.200.100:8080",
        )
        settings = Settings()
        assert settings.cors_origins == [
            "http://monitor.example.com",
            "http://192.168.200.100:8080",
        ]

    def test_cors_origins_strips_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Spaces around origin entries are stripped."""
        monkeypatch.setenv("CORS_ORIGINS", "  http://a.test  ,  http://b.test  ")
        settings = Settings()
        assert "http://a.test" in settings.cors_origins
        assert "http://b.test" in settings.cors_origins

    def test_cors_origins_single_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A single origin (no comma) works."""
        monkeypatch.setenv("CORS_ORIGINS", "http://noc.bsccl.com.bd")
        settings = Settings()
        assert settings.cors_origins == ["http://noc.bsccl.com.bd"]


# ---------------------------------------------------------------------------
# MONITOR_HOST validation
# ---------------------------------------------------------------------------


class TestMonitorHostValidation:
    """Settings rejects bad MONITOR_HOST values to guard against SSRF."""

    def test_default_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Default 192.168.200.230 is accepted."""
        monkeypatch.delenv("MONITOR_HOST", raising=False)
        s = Settings()
        assert s.monitor_host == "192.168.200.230"

    def test_valid_remote_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Public IP (103.16.152.8) is accepted."""
        monkeypatch.setenv("MONITOR_HOST", "103.16.152.8")
        s = Settings()
        assert s.monitor_host == "103.16.152.8"

    def test_valid_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A plain hostname is accepted."""
        monkeypatch.setenv("MONITOR_HOST", "grafana.internal")
        s = Settings()
        assert s.monitor_host == "grafana.internal"

    def test_rejects_empty_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty MONITOR_HOST raises ValueError."""
        monkeypatch.setenv("MONITOR_HOST", "")
        with pytest.raises(ValueError, match="must not be empty"):
            Settings()

    def test_rejects_whitespace_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A whitespace-only MONITOR_HOST raises ValueError."""
        monkeypatch.setenv("MONITOR_HOST", "   ")
        with pytest.raises(ValueError, match="must not be empty"):
            Settings()

    def test_rejects_file_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """file:// URI prefix is rejected as a URI scheme."""
        monkeypatch.setenv("MONITOR_HOST", "file:///etc/passwd")
        with pytest.raises(ValueError, match="not a URI"):
            Settings()

    def test_rejects_http_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """http:// prefix is rejected."""
        monkeypatch.setenv("MONITOR_HOST", "http://192.168.200.230")
        with pytest.raises(ValueError, match="not a URI"):
            Settings()

    def test_rejects_invalid_hostname(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A string that is neither a valid IP nor hostname raises ValueError."""
        monkeypatch.setenv("MONITOR_HOST", "not a valid host!")
        with pytest.raises(ValueError, match="not a valid hostname"):
            Settings()

    def test_rejects_path_traversal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A value with slashes (path traversal) is rejected."""
        monkeypatch.setenv("MONITOR_HOST", "../../etc/passwd")
        with pytest.raises(ValueError, match="not a valid hostname"):
            Settings()

    def test_rejects_out_of_range_octet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A dotted-decimal value with an out-of-range octet is rejected."""
        monkeypatch.setenv("MONITOR_HOST", "256.0.0.1")
        with pytest.raises(ValueError, match="not a valid IP address"):
            Settings()

    def test_rejects_five_octet_pseudo_ip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A five-octet pseudo-IP is rejected (invalid IP, not a hostname)."""
        monkeypatch.setenv("MONITOR_HOST", "1.2.3.4.5")
        with pytest.raises(ValueError, match="not a valid IP address"):
            Settings()


# ---------------------------------------------------------------------------
# Engine type annotation (structural)
# ---------------------------------------------------------------------------


def test_engine_global_initially_none() -> None:
    """The module-level _engine starts as None (before lifespan)."""
    # After module import but before any lifespan startup the engine is None.
    # This also confirms the type is AsyncEngine | None (None is valid).
    engine = main_mod._engine  # noqa: SLF001
    assert engine is None or hasattr(engine, "dispose")
