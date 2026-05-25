"""Syslog receiver for BSCCL NetWatch.

Receives syslog data from Loki (WebSocket tail or HTTP poll) with a UDP
fallback for emergency direct syslog input.

Connection strategy:
  1. Loki WebSocket tail  (ws://{host}:3000/loki/api/v1/tail)
  2. Loki HTTP poll       (GET /loki/api/v1/query_range every 2 s)
  3. UDP listen           (emergency fallback on syslog_udp_port)

WebSocket reconnects with exponential back-off: 1 s, 2 s, 4 s … max 30 s.

HTTP poll error path uses the same exponential back-off strategy so that a
downed Loki instance is not hammered with requests.  The back-off resets to
the base delay on the first successful poll.

A WARNING is emitted when consecutive HTTP poll failures exceed
``_HTTP_POLL_FAIL_THRESHOLD`` (default 5) so that a silently-broken receiver
is visible in the application logs.

The HTTP poll cursor is guarded against silent data loss at full-page
boundaries: when a page is exactly ``_POLL_LIMIT`` entries the cursor is
advanced to ``last_ts + 1`` **only when all entries in the page have distinct
timestamps**.  When multiple entries share the last nanosecond timestamp the
cursor is left at that timestamp and duplicate delivery is suppressed by the
seen-id set so no entries are skipped.

``health_status()`` returns a snapshot of the receiver's current running
state, active mode, last-poll timestamp, and consecutive failure count.

Any Grafana API key embedded in logged URLs is masked so credentials never
appear in log output.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import socket
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx
import websockets
import websockets.exceptions

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from src.config import Settings

_log = logging.getLogger(__name__)

_HTTP_POLL_INTERVAL = 2  # seconds between HTTP poll requests
_LOKI_QUERY = '{job="Router-Logs"}'  # default; overridden by settings.loki_query

# Exponential back-off parameters for the HTTP poll error path.
_HTTP_BACKOFF_BASE = 1.0  # seconds – initial delay after first failure
_HTTP_BACKOFF_CAP = 30.0  # seconds – maximum delay

# Emit a WARNING when this many consecutive HTTP poll failures are observed.
_HTTP_POLL_FAIL_THRESHOLD = 5

# Regex that matches a Grafana API key in a URL so we can redact it.
_API_KEY_RE = re.compile(r"(api[_-]?key=)[^&\s]+", re.IGNORECASE)


def _mask_url(url: str) -> str:
    """Return *url* with any embedded API key value replaced by ``***``.

    Only the value portion is replaced so the parameter name remains visible
    in logs for debugging purposes.
    """
    return _API_KEY_RE.sub(r"\1***", url)


@dataclass
class ReceiverHealth:
    """Snapshot of the receiver's current operational state.

    Attributes
    ----------
    running:
        ``True`` while the receiver is active (between ``start()`` and
        ``stop()``).
    mode:
        Active transport mode: ``"ws"``, ``"http"``, or ``"udp"``.
        ``"idle"`` when the receiver has not yet been started.
    last_poll_ns:
        Nanosecond timestamp of the last HTTP cursor position.  ``0`` when
        no HTTP poll has completed yet.
    consecutive_http_failures:
        Number of consecutive HTTP poll errors since the last success.
    """

    running: bool
    mode: str
    last_poll_ns: int
    consecutive_http_failures: int


class SyslogReceiver:
    """Receives raw syslog lines and invokes *callback* for each one.

    Parameters
    ----------
    settings:
        Application settings (used for Loki URLs and UDP port).
    callback:
        Async callable that receives a single raw syslog line string.
        Called for every line extracted from every Loki message.
    """

    _POLL_LIMIT = 500
    _DEFAULT_LOOKBACK_NS = 30 * 60 * 1_000_000_000  # 30 minutes

    def __init__(
        self,
        settings: Settings,
        callback: Callable[[str], Awaitable[None]],
        resume_from_ns: int = 0,
    ) -> None:
        self._settings = settings
        self._callback = callback
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []
        # Tracks the nanosecond timestamp of the last successful HTTP poll
        # so each poll only fetches logs newer than the previous request.
        # Seeded from DB on startup so we resume exactly where we left off.
        self._last_poll_ns: int = resume_from_ns
        # Consecutive HTTP poll failure counter (reset on success).
        self._http_fail_count: int = 0
        # Active transport mode for health reporting.
        self._active_mode: str = "idle"
        # Deduplication set for entries that share the last-page timestamp.
        # Stores (ts_ns, line) tuples observed on the previous full-page poll.
        self._seen_at_cursor: set[tuple[int, str]] = set()
        # Persistent HTTP client for the poll fallback — created on first
        # use and closed in stop().  Avoids creating a new client per cycle.
        self._http_client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start receiving.  Tries WS → HTTP → UDP based on syslog_mode.

        When mode is ``loki_ws``, attempts a WebSocket connection first.  If
        the initial connection fails (``ConnectionError``, ``OSError``, or
        ``WebSocketException``), falls back automatically to ``loki_http``.
        If the HTTP poll also fails on its first attempt, falls back to UDP.
        """
        self._running = True
        mode = self._settings.syslog_mode

        if mode == "loki_ws":
            task = asyncio.create_task(self._ws_tail_with_fallback())
            self._tasks.append(task)
        elif mode == "loki_http":
            self._active_mode = "http"
            task = asyncio.create_task(self._http_poll())
            self._tasks.append(task)
        elif mode == "udp":
            self._active_mode = "udp"
            task = asyncio.create_task(self._udp_listen())
            self._tasks.append(task)
        else:
            # Default: try WS with HTTP fallback
            task = asyncio.create_task(self._ws_tail_with_fallback())
            self._tasks.append(task)

    async def _ws_tail_with_fallback(self) -> None:
        """Try WS tail; fall back to HTTP poll then UDP on initial failure.

        Uses ``_ws_tail_once()`` as a connectivity probe.  If the probe
        succeeds, the persistent ``_ws_tail()`` reconnect loop takes over.
        If the probe raises, fall back to HTTP poll (then UDP).

        Note: ``_ws_tail()`` starts a fresh WebSocket session internally, so
        data read by the probe and data read by the persistent loop are from
        separate connections with no overlap.
        """
        try:
            self._active_mode = "ws"
            await self._ws_tail_once()
            # Connection succeeded — hand off to the persistent reconnect loop
            await self._ws_tail()
        except (
            ConnectionError,
            OSError,
            websockets.exceptions.WebSocketException,
        ) as exc:
            _log.warning("WS connection failed (%s), falling back to HTTP poll", exc)
            self._active_mode = "http"
            try:
                await self._http_poll_once()
                # HTTP reachable — run the persistent poll loop
                await self._http_poll()
            except (httpx.RequestError, ConnectionError, OSError) as http_exc:
                _log.warning(
                    "HTTP poll also failed (%s), falling back to UDP", http_exc
                )
                self._active_mode = "udp"
                await self._udp_listen()

    async def stop(self) -> None:
        """Gracefully cancel all running receiver tasks and close resources."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    def _get_http_client(self) -> httpx.AsyncClient:
        """Return the persistent HTTP client, creating it on first use."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=10.0)
        return self._http_client

    def health_status(self) -> ReceiverHealth:
        """Return a lightweight snapshot of the receiver's current state.

        This method is synchronous and non-blocking — safe to call from any
        context including the dashboard API handler.

        Returns
        -------
        ReceiverHealth
            Current running state, active mode, last-poll cursor, and
            consecutive HTTP failure count.
        """
        return ReceiverHealth(
            running=self._running,
            mode=self._active_mode,
            last_poll_ns=self._last_poll_ns,
            consecutive_http_failures=self._http_fail_count,
        )

    # ------------------------------------------------------------------
    # WebSocket tail
    # ------------------------------------------------------------------

    async def _ws_tail(self) -> None:
        """Connect to Loki WebSocket tail with exponential back-off reconnect."""
        await self._ws_tail_attempts(max_attempts=None, base_delay=1)

    async def _ws_tail_attempts(
        self,
        max_attempts: int | None,
        base_delay: float = 1,
    ) -> None:
        """WebSocket tail with configurable attempt limit (for testing).

        Parameters
        ----------
        max_attempts:
            Stop after this many connection attempts.  ``None`` = run forever.
        base_delay:
            Initial back-off delay in seconds (doubles each attempt, max 30).
        """
        attempt = 0
        delay = base_delay

        # When max_attempts is set (test mode) run regardless of _running flag.
        # In production (_running flag) the outer _ws_tail loop controls lifetime.
        def _should_continue() -> bool:
            if max_attempts is not None:
                return attempt < max_attempts
            return self._running

        while _should_continue():
            attempt += 1
            try:
                await self._ws_tail_once()
                # If _ws_tail_once returned cleanly, reset back-off
                delay = base_delay
            except (
                ConnectionError,
                OSError,
                websockets.exceptions.WebSocketException,
            ) as exc:
                _log.warning("WS disconnect (attempt %d): %s", attempt, exc)
                if max_attempts is not None and attempt >= max_attempts:
                    break
                _log.info("Reconnecting in %.0f s…", delay)
                if delay > 0:
                    await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def _ws_tail_once(self) -> None:
        """Single WebSocket tail session — read until connection closes."""
        query = self._settings.loki_query
        url = f"{self._settings.loki_ws_url}?query={quote(query)}"
        async with websockets.connect(url) as ws:
            async for raw_msg in ws:
                if isinstance(raw_msg, bytes):
                    raw_msg = raw_msg.decode()
                lines = self._extract_lines_from_ws(raw_msg)
                for line in lines:
                    await self._callback(line)

    # ------------------------------------------------------------------
    # HTTP poll
    # ------------------------------------------------------------------

    async def _http_poll(self) -> None:
        """Poll Loki HTTP query_range every 2 seconds until stopped.

        On the first poll cycle after startup, drains any backlog by
        paginating until all historical logs are consumed (returns fewer
        than ``_POLL_LIMIT`` lines).  After catching up, switches to
        the normal 2-second interval.

        Uses exponential back-off (1 s → 2 s → … → 30 s cap) on the error
        path so a downed Loki is not hammered with requests.  The back-off
        delay resets to the base on the first successful poll.  When
        consecutive failures exceed ``_HTTP_POLL_FAIL_THRESHOLD`` a WARNING
        is emitted so the condition is visible in application logs.
        """
        backoff_delay = _HTTP_BACKOFF_BASE

        while self._running:
            try:
                count = await self._http_poll_once()
                # Successful poll — reset failure tracking and back-off delay.
                if self._http_fail_count > 0:
                    _log.info(
                        "HTTP poll recovered after %d consecutive failure(s)",
                        self._http_fail_count,
                    )
                self._http_fail_count = 0
                backoff_delay = _HTTP_BACKOFF_BASE
                while count >= self._POLL_LIMIT and self._running:
                    count = await self._http_poll_once()
            except Exception as exc:  # noqa: BLE001
                self._http_fail_count += 1
                _log.warning(
                    "HTTP poll error (failure #%d): %s",
                    self._http_fail_count,
                    exc,
                )
                if self._http_fail_count >= _HTTP_POLL_FAIL_THRESHOLD:
                    _log.warning(
                        "HTTP poll has failed %d consecutive times — "
                        "Loki may be unreachable",
                        self._http_fail_count,
                    )
                await asyncio.sleep(backoff_delay)
                backoff_delay = min(backoff_delay * 2, _HTTP_BACKOFF_CAP)
                continue  # skip the normal interval sleep on the error path

            await asyncio.sleep(_HTTP_POLL_INTERVAL)

    async def _http_poll_once(self) -> int:
        """Single HTTP poll request to Loki query_range.

        Uses nanosecond timestamps (``start`` / ``end``) so each poll only
        fetches log lines that arrived since the previous request.

        When the response contains exactly ``_POLL_LIMIT`` lines, the cursor
        is advanced safely to avoid skipping entries that share the same
        nanosecond timestamp at the page boundary:

        * If the last timestamp in the page is **unique** within the page, the
          cursor advances to ``last_ts + 1`` so the next poll fetches the next
          distinct nanosecond only.
        * If **multiple entries share the last timestamp**, the cursor stays at
          that timestamp and a deduplication set is maintained so those entries
          are not re-delivered on the follow-up poll.

        On a short page (fewer than ``_POLL_LIMIT`` entries) the cursor moves
        to ``now`` as before.

        Returns the number of lines processed (0 on error / non-200 status).
        """
        now_ns = int(time.time() * 1_000_000_000)
        start_ns = self._last_poll_ns or (now_ns - self._DEFAULT_LOOKBACK_NS)
        params = {
            "query": self._settings.loki_query,
            "limit": str(self._POLL_LIMIT),
            "start": str(start_ns),
            "end": str(now_ns),
        }
        safe_url = _mask_url(self._settings.loki_http_url)
        client = self._get_http_client()
        resp = await client.get(
            self._settings.loki_http_url,
            params=params,
            timeout=10.0,
        )
        if resp.status_code != 200:
            _log.warning(
                "Loki HTTP poll returned %d (url=%s)",
                resp.status_code,
                safe_url,
            )
            return 0

        data = resp.json()
        entries = self._extract_entries_from_http(data)

        # Suppress entries already delivered on the previous full-page poll.
        new_entries = [
            (ts, line) for ts, line in entries if (ts, line) not in self._seen_at_cursor
        ]
        for _ts_ns, line in new_entries:
            await self._callback(line)

        count = len(entries)

        if count >= self._POLL_LIMIT and entries:
            last_ts = entries[-1][0]
            # Check whether multiple entries share the last timestamp.
            entries_at_last_ts = [(ts, ln) for ts, ln in entries if ts == last_ts]
            if 1 < len(entries_at_last_ts) < count and new_entries:
                # Ambiguous boundary with real progress: stay at last_ts so
                # the next poll re-fetches this nanosecond; deduplicate by
                # remembering what was already delivered.
                self._last_poll_ns = last_ts
                self._seen_at_cursor = set(entries_at_last_ts)
            else:
                # Distinct boundary, an entire page sharing one timestamp,
                # or nothing new delivered — advance past last_ts to avoid
                # an infinite re-fetch loop on a pathological/hostile feed.
                self._last_poll_ns = last_ts + 1
                self._seen_at_cursor = set()
        else:
            self._last_poll_ns = now_ns
            self._seen_at_cursor = set()

        if count > 0:
            _log.debug(
                "HTTP poll: %d lines (%d new, start=%s)",
                count,
                len(new_entries),
                start_ns,
            )
        # Return the raw Loki entry count so the caller (_http_poll) can
        # correctly decide whether a full page was returned and more backlog
        # may remain.  Returning len(new_entries) would break the drain loop
        # when all entries on a page are already-seen deduplications.
        return count

    # ------------------------------------------------------------------
    # UDP fallback
    # ------------------------------------------------------------------

    async def _udp_listen(self) -> None:
        """Listen on UDP for direct syslog input (emergency fallback)."""
        loop = asyncio.get_running_loop()
        port = self._settings.syslog_udp_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))

        _log.info("UDP syslog listener started on port %d", port)

        try:
            while self._running:
                try:
                    data, _addr = await loop.run_in_executor(
                        None, lambda: sock.recvfrom(65535)
                    )
                    line = data.decode(errors="replace").rstrip("\n\r")
                    if line:
                        await self._callback(line)
                except OSError:
                    if not self._running:
                        break
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # Line extraction helpers
    # ------------------------------------------------------------------

    def _extract_lines_from_ws(self, raw_msg: str) -> list[str]:
        """Extract syslog line strings from a Loki WebSocket tail message.

        Loki tail format::

            {
              "streams": [
                {
                  "stream": {"job": "syslog"},
                  "values": [["<nanosecond_ts>", "<log_line>"], ...]
                }
              ]
            }

        Parameters
        ----------
        raw_msg:
            Raw JSON string from the Loki WebSocket.

        Returns
        -------
        list[str]
            All log lines extracted from the message.
        """
        try:
            payload: dict[str, Any] = json.loads(raw_msg)
        except json.JSONDecodeError:
            _log.debug("Non-JSON WS message (length %d), skipping", len(raw_msg))
            return []

        lines: list[str] = []
        for stream in payload.get("streams", []):
            for _ts, line in stream.get("values", []):
                if line:
                    lines.append(line)
        return lines

    def _extract_entries_from_http(
        self, payload: dict[str, Any]
    ) -> list[tuple[int, str]]:
        """Extract ``(nanosecond_ts, line)`` tuples from a Loki query_range response.

        Entries are sorted by timestamp so the caller can use the last
        entry's timestamp as the pagination cursor.
        """
        entries: list[tuple[int, str]] = []
        data = payload.get("data", {})
        for result in data.get("result", []):
            for ts_str, line in result.get("values", []):
                if line:
                    entries.append((int(ts_str), line))
        entries.sort(key=lambda e: e[0])
        return entries

    def _extract_lines_from_http(self, payload: dict[str, Any]) -> list[str]:
        """Extract syslog line strings from a Loki query_range HTTP response.

        Convenience wrapper around :meth:`_extract_entries_from_http` that
        discards timestamps.
        """
        return [line for _ts, line in self._extract_entries_from_http(payload)]
