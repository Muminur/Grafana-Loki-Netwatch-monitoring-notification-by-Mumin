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
from typing import TYPE_CHECKING, Any

import httpx
import websockets
import websockets.exceptions

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from src.config import Settings

_log = logging.getLogger(__name__)

_HTTP_POLL_INTERVAL = 2  # seconds between HTTP poll requests
_LOKI_QUERY = '{job="syslog"}'


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

    def __init__(
        self,
        settings: Settings,
        callback: Callable[[str], Awaitable[None]],
    ) -> None:
        self._settings = settings
        self._callback = callback
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []

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
        """Try WS tail; fall back to HTTP poll then UDP on initial failure."""
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
            except Exception as http_exc:  # noqa: BLE001
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
        url = f"{self._settings.loki_ws_url}?query=%7Bjob%3D%22syslog%22%7D"
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
        """Poll Loki HTTP query_range every 2 seconds until stopped."""
        while self._running:
            try:
                await self._http_poll_once()
            except Exception as exc:  # noqa: BLE001
                _log.warning("HTTP poll error: %s", exc)
            await asyncio.sleep(_HTTP_POLL_INTERVAL)

    async def _http_poll_once(self) -> None:
        """Single HTTP poll request to Loki query_range."""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self._settings.loki_http_url,
                params={"query": _LOKI_QUERY, "limit": "100"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                lines = self._extract_lines_from_http(data)
                for line in lines:
                    await self._callback(line)
            else:
                _log.warning("Loki HTTP poll returned %d", resp.status_code)

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
        sock.setblocking(False)

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

    def _extract_lines_from_http(self, payload: dict[str, Any]) -> list[str]:
        """Extract syslog line strings from a Loki query_range HTTP response.

        Loki query_range format::

            {
              "status": "success",
              "data": {
                "resultType": "streams",
                "result": [
                  {
                    "stream": {"job": "syslog"},
                    "values": [["<nanosecond_ts>", "<log_line>"], ...]
                  }
                ]
              }
            }

        Parameters
        ----------
        payload:
            Parsed JSON dict from the Loki HTTP response.

        Returns
        -------
        list[str]
            All log lines extracted from the response.
        """
        lines: list[str] = []
        data = payload.get("data", {})
        for result in data.get("result", []):
            for _ts, line in result.get("values", []):
                if line:
                    lines.append(line)
        return lines
