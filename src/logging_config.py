"""Logging configuration for BSCCL NetWatch.

Provides ``configure_logging`` which wires up the root logger with either a
human-readable text formatter (default) or a machine-parseable JSON formatter
(when ``LOG_FORMAT=json``).  The JSON formatter is implemented using the
stdlib ``json`` module only — no third-party dependency is required.

Design rules
------------
* Called **once** during application lifespan startup.  Calling it again is
  safe (idempotent): it replaces the existing handler set rather than
  accumulating duplicates.
* Import-time side-effects are absent; importing this module does *not*
  reconfigure any handler.
* The ``json`` output mode emits one JSON object per line (NDJSON) with at
  least: ``timestamp``, ``level``, ``logger``, ``message``, and any *extra*
  fields attached by the caller.  When an exception is active the record also
  contains ``exc_info``.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# Allowed values (used by config.py validator and tests)
# ---------------------------------------------------------------------------

_VALID_LOG_FORMATS: frozenset[str] = frozenset({"text", "json"})
_VALID_LOG_LEVELS: frozenset[str] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)

# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

_TEXT_FORMAT = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
_TEXT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Fields that are always present on every LogRecord and should not be
# duplicated in the JSON ``extra`` payload.
_STDLIB_RECORD_ATTRS: frozenset[str] = frozenset(
    {
        "args",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)

# Canonical output keys emitted unconditionally by _JsonFormatter.format().
# These are excluded from the extra-field merge so that a caller-supplied
# extra field with a colliding name (e.g. ``extra={"level": "custom"}``) does
# not silently overwrite the authoritative value.
_CANONICAL_JSON_KEYS: frozenset[str] = frozenset(
    {"timestamp", "level", "logger", "message"}
)


class _JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record (NDJSON).

    Required output keys
    --------------------
    * ``timestamp`` — ISO-8601, UTC (``YYYY-MM-DDTHH:MM:SS.ffffffZ``)
    * ``level``     — upper-case level name (e.g. ``"INFO"``)
    * ``logger``    — logger name
    * ``message``   — formatted log message
    * ``exc_info``  — formatted traceback string, only when an exception is
                      active on the record

    Any extra fields passed via ``logging.info("…", extra={…})`` are merged
    into the top-level object so callers can attach structured context without
    nesting.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = record.getMessage()
        ts = datetime.fromtimestamp(record.created, tz=UTC).isoformat()

        obj: dict[str, object] = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }

        # Merge caller-supplied extra fields.
        # Skip stdlib record attributes and the canonical output keys so that
        # extra={'level': 'custom'} cannot overwrite authoritative values.
        for key, value in record.__dict__.items():
            if (
                key not in _STDLIB_RECORD_ATTRS
                and key not in _CANONICAL_JSON_KEYS
                and not key.startswith("_")
            ):
                obj[key] = value

        # Attach exception info when present.
        if record.exc_info:
            obj["exc_info"] = self.formatException(record.exc_info)
        elif record.exc_text:
            obj["exc_info"] = record.exc_text

        return json.dumps(obj, default=str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def configure_logging(log_format: str, log_level: str) -> None:
    """Configure the root logger with a text or JSON formatter.

    Calling this function is idempotent: existing handlers on the root logger
    are cleared before the new handler is installed, so calling it multiple
    times will not accumulate duplicate handlers.

    Parameters
    ----------
    log_format:
        ``"text"`` for a human-readable formatter or ``"json"`` for NDJSON.
        Unknown values silently fall back to ``"text"``.
    log_level:
        A standard level name (``"DEBUG"``, ``"INFO"``, ``"WARNING"``,
        ``"ERROR"``, ``"CRITICAL"``).  Unknown values silently fall back to
        ``"INFO"``.
    """
    # Resolve level — fall back to INFO on unrecognised input.
    numeric_level = logging.getLevelName(log_level.upper())
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO

    # Build handler + formatter.
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    if log_format.lower() == "json":
        formatter: logging.Formatter = _JsonFormatter()
    else:
        formatter = logging.Formatter(fmt=_TEXT_FORMAT, datefmt=_TEXT_DATE_FORMAT)

    handler.setFormatter(formatter)

    # Replace all existing root handlers (idempotent).
    #
    # NOTE: this clears ALL root handlers, including a pytest ``caplog``
    # LogCaptureHandler. Do not combine ``caplog`` with code paths that invoke
    # configure_logging() (e.g. FastAPI lifespan startup) within the same test,
    # or captured log records will be silently dropped.
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric_level)
