"""Syslog receiver for BSCCL NetWatch.

Receives syslog data from Loki (WebSocket tail or HTTP poll) with a UDP
fallback for emergency direct syslog input.

Connection strategy:
  1. Loki WebSocket tail  (ws://{host}:3000/loki/api/v1/tail)
  2. Loki HTTP poll       (GET /loki/api/v1/query_range every 2 s)
  3. UDP listen           (emergency fallback on syslog_udp_port)

WebSocket reconnects with exponential back-off: 1 s, 2 s, 4 s … max 30 s.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
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
            task = asyncio.create_task(self._http_poll())
            self._tasks.append(task)
        elif mode == "udp":
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
            await self._ws_tail_once()
            # Connection succeeded — hand off to the persistent reconnect loop
            await self._ws_tail()
        except (
            ConnectionError,
            OSError,
            websockets.exceptions.WebSocketException,
        ) as exc:
            _log.warning("WS connection failed (%s), falling back to HTTP poll", exc)
            try:
                await self._http_poll_once()
                # HTTP reachable — run the persistent poll loop
                await self._http_poll()
            except (httpx.RequestError, ConnectionError, OSError) as http_exc:
                _log.warning(
                    "HTTP poll also failed (%s), falling back to UDP", http_exc
                )
                await self._udp_listen()

    async def stop(self) -> None:
        """Gracefully cancel all running receiver tasks."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

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
        """
        while self._running:
            try:
                count = await self._http_poll_once()
                while count >= self._POLL_LIMIT and self._running:
                    count = await self._http_poll_once()
            except Exception as exc:  # noqa: BLE001
                _log.warning("HTTP poll error: %s", exc)
            await asyncio.sleep(_HTTP_POLL_INTERVAL)

    async def _http_poll_once(self) -> int:
        """Single HTTP poll request to Loki query_range.

        Uses nanosecond timestamps (``start`` / ``end``) so each poll only
        fetches log lines that arrived since the previous request.

        When the response contains exactly ``_POLL_LIMIT`` lines, the cursor
        advances to the last returned timestamp + 1 ns (not ``now``) so the
        caller can immediately poll again to drain the remaining backlog.

        Returns the number of lines processed (0 on error).
        """
        now_ns = int(time.time() * 1_000_000_000)
        start_ns = self._last_poll_ns or (now_ns - self._DEFAULT_LOOKBACK_NS)
        params = {
            "query": self._settings.loki_query,
            "limit": str(self._POLL_LIMIT),
            "start": str(start_ns),
            "end": str(now_ns),
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._settings.loki_http_url,
                params=params,
                timeout=10.0,
            )
            if resp.status_code != 200:
                _log.warning("Loki HTTP poll returned %d", resp.status_code)
                return 0

            data = resp.json()
            entries = self._extract_entries_from_http(data)
            for _ts_ns, line in entries:
                await self._callback(line)

            count = len(entries)
            if count >= self._POLL_LIMIT and entries:
                self._last_poll_ns = entries[-1][0] + 1
            else:
                self._last_poll_ns = now_ns

            if count > 0:
                _log.debug("HTTP poll: %d lines (start=%s)", count, start_ns)
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
