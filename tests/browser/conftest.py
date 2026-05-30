"""Fixtures for the Playwright browser e2e suite.

These tests launch the real FastAPI app in a separate process and drive it with
a headless browser, so they verify the JavaScript layer (counters, charts) that
the httpx-based e2e tests cannot. They are marked ``browser`` and are excluded
from the default/matrix pytest run; CI runs them in a dedicated job that has
the Playwright browsers installed.

The server runs as a subprocess (not an in-process thread) so its
``routes._db_engine`` global is fully isolated from the test process — the root
conftest's autouse ``_db_engine`` reset must not reach into a live server.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

_BDT = timezone(timedelta(hours=6))


def _bdt_naive(hours_ago: float) -> datetime:
    """A naive BDT timestamp ``hours_ago`` in the past (matches stored face value)."""
    return (datetime.now(_BDT) - timedelta(hours=hours_ago)).replace(tzinfo=None)


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port: int = sock.getsockname()[1]
    sock.close()
    return port


def _seed(db_url: str) -> dict[str, int]:
    """Create the schema and insert a known set of alerts. Returns expected counts."""
    import asyncio

    from sqlalchemy.ext.asyncio import AsyncSession

    from src.database.migrations import create_tables, get_engine
    from src.database.models import AlertLog

    rows = [
        ("EQ-RTR-01", "CRITICAL", "BGP", "ADJCHANGE", 1.0),
        ("EQ-RTR-01", "CRITICAL", "BGP", "ADJCHANGE", 2.0),
        ("EQ-RTR-01", "CRITICAL", "ROUTING", "RX_FAULT", 3.0),
        ("DHK-Core-3", "INFO", "PKT_INFRA", "LINK", 1.5),
        ("DHK-Core-3", "INFO", "PKT_INFRA", "LINK", 4.0),
        ("DHK-Core-3", "INFO", "PLATFORM", "VEEA", 5.0),
        ("KKT-Core-1", "INFO", "L2", "ACTIVE", 2.5),
        ("KKT-Core-1", "INFO", "L2", "ACTIVE", 6.0),
        ("COX-Core-01", "INFO", "MGBL", "DB_COMMIT", 1.0),
        ("COX-Core-01", "USER_LOGIN", "SSH", "LOGIN", 0.5),
        ("EQ-RTR-01", "USER_LOGIN", "SSH", "LOGIN", 7.0),
    ]

    async def _run() -> None:
        engine = await get_engine(db_url)
        await create_tables(engine)
        async with AsyncSession(engine) as session:
            for device, cls, facility, mnemonic, hrs in rows:
                session.add(
                    AlertLog(
                        timestamp=_bdt_naive(hrs),
                        source_ip="192.168.203.1",
                        device_name=device,
                        hostname=device,
                        facility=facility,
                        severity_level=3,
                        mnemonic=mnemonic,
                        message="seed alert",
                        raw="seed raw line",
                        classification=cls,
                    )
                )
            await session.commit()
        await engine.dispose()

    asyncio.run(_run())
    return {
        "CRITICAL": sum(1 for r in rows if r[1] == "CRITICAL"),
        "INFO": sum(1 for r in rows if r[1] == "INFO"),
        "USER_LOGIN": sum(1 for r in rows if r[1] == "USER_LOGIN"),
        "total": len(rows),
    }


@pytest.fixture(scope="session")
def live_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, object]]:
    """Seed a temp DB, run the app as a subprocess, yield base url + counts."""
    db_path = tmp_path_factory.mktemp("browser-db") / "netwatch_test.db"
    db_url = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    expected = _seed(db_url)

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"

    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": db_url,
            "MONITOR_HOST": "127.0.0.1",
            "DISCORD_ENABLED": "false",
            "TELEGRAM_ENABLED": "false",
            "DISCORD_WEBHOOK_URL": "",
            "TELEGRAM_BOT_TOKEN": "",
            "TELEGRAM_CHAT_ID": "",
        }
    )

    # Log to a file, NOT a PIPE: the app logs heavily (repeated Loki-refused
    # messages), and an undrained PIPE buffer fills and deadlocks the server.
    log_path = db_path.parent / "server.log"
    log_fh = log_path.open("wb")
    proc = subprocess.Popen(  # noqa: S603 (fixed args, no shell)
        [
            sys.executable,
            "-m",
            "uvicorn",
            "src.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=str(Path(__file__).resolve().parents[2]),
        env=env,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
    )

    try:
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                log_fh.flush()
                out = log_path.read_text(encoding="utf-8", errors="replace")
                raise RuntimeError(
                    f"server exited early (code {proc.returncode}):\n{out}"
                )
            try:
                if httpx.get(f"{base_url}/health", timeout=1.0).status_code == 200:
                    ready = True
                    break
            except httpx.HTTPError:
                time.sleep(0.4)
        if not ready:
            raise RuntimeError("server did not become ready within 30s")

        yield {"url": base_url, "expected": expected}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_fh.close()
