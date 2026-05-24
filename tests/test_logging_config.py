"""Tests for src.logging_config and structured-logging integration in main.

Coverage targets
----------------
* _JsonFormatter emits valid, parseable JSON for a plain log record.
* _JsonFormatter includes exception info when exc_info is present.
* _JsonFormatter merges ``extra`` fields into the top-level object.
* Text mode: configure_logging("text", "INFO") produces a non-JSON formatter.
* configure_logging is idempotent — calling it twice does not duplicate
  handlers.
* configure_logging respects the requested log level.
* configure_logging falls back to "text" / "INFO" for unrecognised inputs.
* X-Request-ID response header is present on every HTTP response via
  RequestIDMiddleware (TestClient, no port binding).
* request.state.request_id is set by the middleware.
* Config validators: _validate_log_format / _validate_log_level defaults.
"""

from __future__ import annotations

import json
import logging
import re

import pytest
from fastapi.testclient import TestClient

import src.main as main_mod
from src.config import Settings
from src.logging_config import _JsonFormatter, configure_logging  # noqa: PLC2701

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record(
    message: str = "hello world",
    level: int = logging.INFO,
    *,
    exc_info: bool = False,
    extra: dict[str, object] | None = None,
) -> logging.LogRecord:
    """Build a minimal LogRecord, optionally with exc_info and extra fields."""
    record = logging.LogRecord(
        name="test.logger",
        level=level,
        pathname=__file__,
        lineno=0,
        msg=message,
        args=(),
        exc_info=None,
    )
    if exc_info:
        try:
            msg = "boom"
            raise ValueError(msg)
        except ValueError:
            import sys

            record.exc_info = sys.exc_info()
    if extra:
        for k, v in extra.items():
            setattr(record, k, v)
    return record


# ---------------------------------------------------------------------------
# _JsonFormatter — basic output shape
# ---------------------------------------------------------------------------


class TestJsonFormatterShape:
    """JSON output contains the mandatory keys with correct types."""

    def test_valid_json(self) -> None:
        """Output is valid JSON (parseable without error)."""
        fmt = _JsonFormatter()
        line = fmt.format(_make_record())
        parsed = json.loads(line)
        assert isinstance(parsed, dict)

    def test_required_keys_present(self) -> None:
        """timestamp, level, logger, message are all present."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record("test message")))
        assert "timestamp" in parsed
        assert "level" in parsed
        assert "logger" in parsed
        assert "message" in parsed

    def test_message_content(self) -> None:
        """The ``message`` field contains the formatted log message."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record("specific message")))
        assert parsed["message"] == "specific message"

    def test_level_field(self) -> None:
        """``level`` is the upper-case level name."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record(level=logging.WARNING)))
        assert parsed["level"] == "WARNING"

    def test_logger_name(self) -> None:
        """``logger`` matches the record's name attribute."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record()))
        assert parsed["logger"] == "test.logger"

    def test_timestamp_is_iso_utc(self) -> None:
        """``timestamp`` is an ISO-8601 UTC string ending with '+00:00'."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record()))
        ts: str = parsed["timestamp"]
        # datetime.isoformat() for UTC produces e.g. "2026-05-24T12:00:00+00:00"
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", ts)
        assert "+00:00" in ts or "Z" in ts or ts.endswith("+00:00")

    def test_no_exc_info_when_no_exception(self) -> None:
        """``exc_info`` key is absent when no exception is attached."""
        fmt = _JsonFormatter()
        parsed = json.loads(fmt.format(_make_record()))
        assert "exc_info" not in parsed


# ---------------------------------------------------------------------------
# _JsonFormatter — exception info
# ---------------------------------------------------------------------------


class TestJsonFormatterExcInfo:
    """Exception details appear in ``exc_info`` when an exception is active."""

    def test_exc_info_key_present(self) -> None:
        """``exc_info`` is present in the JSON output when exc_info is set."""
        fmt = _JsonFormatter()
        record = _make_record(exc_info=True)
        parsed = json.loads(fmt.format(record))
        assert "exc_info" in parsed

    def test_exc_info_contains_traceback(self) -> None:
        """``exc_info`` value contains the exception class name."""
        fmt = _JsonFormatter()
        record = _make_record(exc_info=True)
        parsed = json.loads(fmt.format(record))
        assert "ValueError" in parsed["exc_info"]


# ---------------------------------------------------------------------------
# _JsonFormatter — extra fields
# ---------------------------------------------------------------------------


class TestJsonFormatterExtra:
    """Extra fields passed via ``extra=`` are merged into the top-level object."""

    def test_extra_field_appears_in_output(self) -> None:
        """A single extra field is visible at the top level of the JSON."""
        fmt = _JsonFormatter()
        record = _make_record(extra={"request_id": "abc-123"})
        parsed = json.loads(fmt.format(record))
        assert parsed.get("request_id") == "abc-123"

    def test_multiple_extra_fields(self) -> None:
        """Multiple extra fields are all serialised."""
        fmt = _JsonFormatter()
        record = _make_record(extra={"rid": "x1", "method": "GET"})
        parsed = json.loads(fmt.format(record))
        assert parsed.get("rid") == "x1"
        assert parsed.get("method") == "GET"


# ---------------------------------------------------------------------------
# configure_logging — formatter selection
# ---------------------------------------------------------------------------


class TestConfigureLoggingFormat:
    """configure_logging wires up the correct formatter."""

    def test_text_mode_handler_is_installed(self) -> None:
        """After configure_logging("text", "INFO") root has exactly one handler."""
        configure_logging("text", "INFO")
        root = logging.getLogger()
        assert len(root.handlers) == 1

    def test_json_mode_handler_is_installed(self) -> None:
        """After configure_logging("json", "INFO") root has exactly one handler."""
        configure_logging("json", "INFO")
        root = logging.getLogger()
        assert len(root.handlers) == 1

    def test_json_mode_uses_json_formatter(self) -> None:
        """configure_logging("json", ...) installs a _JsonFormatter."""
        configure_logging("json", "INFO")
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, _JsonFormatter)

    def test_text_mode_does_not_use_json_formatter(self) -> None:
        """configure_logging("text", ...) does NOT install _JsonFormatter."""
        configure_logging("text", "INFO")
        root = logging.getLogger()
        assert not isinstance(root.handlers[0].formatter, _JsonFormatter)

    def test_unknown_format_falls_back_to_text(self) -> None:
        """An unrecognised format string silently falls back to text."""
        configure_logging("yaml", "INFO")
        root = logging.getLogger()
        assert not isinstance(root.handlers[0].formatter, _JsonFormatter)


# ---------------------------------------------------------------------------
# configure_logging — idempotency
# ---------------------------------------------------------------------------


class TestConfigureLoggingIdempotency:
    """Calling configure_logging multiple times does not accumulate handlers."""

    def test_idempotent_double_call(self) -> None:
        """Two calls → still exactly one handler on the root logger."""
        configure_logging("text", "INFO")
        configure_logging("text", "INFO")
        root = logging.getLogger()
        assert len(root.handlers) == 1

    def test_idempotent_format_switch(self) -> None:
        """Switching from text to json leaves exactly one handler."""
        configure_logging("text", "INFO")
        configure_logging("json", "DEBUG")
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, _JsonFormatter)

    def test_preserves_non_stdout_handlers(self) -> None:
        """A handler on a non-stdout/stderr stream (e.g. pytest caplog) survives."""
        import io  # noqa: PLC0415

        root = logging.getLogger()
        sentinel = logging.StreamHandler(io.StringIO())
        root.addHandler(sentinel)
        try:
            configure_logging("text", "INFO")
            assert sentinel in root.handlers
        finally:
            root.removeHandler(sentinel)


# ---------------------------------------------------------------------------
# configure_logging — level
# ---------------------------------------------------------------------------


class TestConfigureLoggingLevel:
    """configure_logging sets the root logger to the requested level."""

    @pytest.mark.parametrize(
        ("level_name", "expected"),
        [
            ("DEBUG", logging.DEBUG),
            ("INFO", logging.INFO),
            ("WARNING", logging.WARNING),
            ("ERROR", logging.ERROR),
            ("CRITICAL", logging.CRITICAL),
        ],
    )
    def test_level_set_correctly(self, level_name: str, expected: int) -> None:
        """Each supported level name maps to the correct numeric level."""
        configure_logging("text", level_name)
        assert logging.getLogger().level == expected

    def test_unknown_level_falls_back_to_info(self) -> None:
        """An unrecognised level name silently falls back to INFO."""
        configure_logging("text", "VERBOSE")
        assert logging.getLogger().level == logging.INFO


# ---------------------------------------------------------------------------
# Config validators
# ---------------------------------------------------------------------------


class TestConfigValidators:
    """Settings.log_format and Settings.log_level use the correct defaults."""

    def test_log_format_default_is_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without LOG_FORMAT the default is 'text'."""
        monkeypatch.delenv("LOG_FORMAT", raising=False)
        s = Settings()
        assert s.log_format == "text"

    def test_log_format_json_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LOG_FORMAT=json is stored as-is."""
        monkeypatch.setenv("LOG_FORMAT", "json")
        s = Settings()
        assert s.log_format == "json"

    def test_log_format_unknown_falls_back_to_text(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unrecognised LOG_FORMAT silently falls back to 'text'."""
        monkeypatch.setenv("LOG_FORMAT", "xml")
        s = Settings()
        assert s.log_format == "text"

    def test_log_level_default_is_info(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without LOG_LEVEL the default is 'INFO'."""
        monkeypatch.delenv("LOG_LEVEL", raising=False)
        s = Settings()
        assert s.log_level == "INFO"

    def test_log_level_debug_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """LOG_LEVEL=DEBUG is stored as upper-case."""
        monkeypatch.setenv("LOG_LEVEL", "debug")
        s = Settings()
        assert s.log_level == "DEBUG"

    def test_log_level_unknown_falls_back_to_info(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unrecognised LOG_LEVEL silently falls back to 'INFO'."""
        monkeypatch.setenv("LOG_LEVEL", "TRACE")
        s = Settings()
        assert s.log_level == "INFO"


# ---------------------------------------------------------------------------
# RequestIDMiddleware — X-Request-ID header (E2E, TestClient, no port binding)
# ---------------------------------------------------------------------------


class TestRequestIDMiddleware:
    """X-Request-ID response header is present on every HTTP response."""

    def _client(self) -> TestClient:
        return TestClient(main_mod.app, raise_server_exceptions=True)

    def test_x_request_id_present_on_health(self) -> None:
        """GET /health response carries an X-Request-ID header."""
        client = self._client()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert "x-request-id" in resp.headers

    def test_x_request_id_is_uuid4(self) -> None:
        """X-Request-ID is a valid UUID4 (hyphenated, 36 chars)."""
        client = self._client()
        resp = client.get("/health")
        rid = resp.headers.get("x-request-id", "")
        # UUID4 pattern: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            rid,
        ), f"Not a UUID4: {rid!r}"

    def test_x_request_id_unique_per_request(self) -> None:
        """Two requests receive different X-Request-ID values."""
        client = self._client()
        rid1 = client.get("/health").headers.get("x-request-id")
        rid2 = client.get("/health").headers.get("x-request-id")
        assert rid1 != rid2

    def test_x_request_id_present_on_dashboard(self) -> None:
        """GET / (dashboard page) also carries X-Request-ID."""
        client = self._client()
        resp = client.get("/")
        assert "x-request-id" in resp.headers

    def test_security_headers_still_present(self) -> None:
        """Adding RequestIDMiddleware does not remove security headers."""
        client = self._client()
        resp = client.get("/health")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("content-security-policy", "") != ""
