"""Fire-and-forget DB tasks are tracked and drained on shutdown (audit A2).

``add_alert_to_store`` (sync) spawns recovery/resolution DB writes via
``loop.create_task`` and previously discarded the handle, so a pending write
could run a session against a disposed engine at shutdown and be lost. They are
now tracked and drained before ``engine.dispose()``.
"""

from __future__ import annotations

import asyncio

import pytest

from src.api import routes as routes_mod


@pytest.mark.asyncio
async def test_db_task_tracked_and_drained() -> None:
    """A tracked DB task is awaited by drain_pending_db_tasks, then removed."""
    routes_mod._pending_db_tasks.clear()  # noqa: SLF001
    done: list[bool] = []

    async def _work() -> None:
        await asyncio.sleep(0)
        done.append(True)

    task = asyncio.get_running_loop().create_task(_work())
    routes_mod._track_db_task(task)  # noqa: SLF001
    assert task in routes_mod._pending_db_tasks  # noqa: SLF001

    await routes_mod.drain_pending_db_tasks()

    assert done == [True]  # the task ran to completion before drain returned
    assert not routes_mod._pending_db_tasks  # noqa: SLF001 — done-callback cleared it


@pytest.mark.asyncio
async def test_drain_swallows_task_exceptions() -> None:
    """A failing DB task must not propagate out of drain (return_exceptions)."""
    routes_mod._pending_db_tasks.clear()  # noqa: SLF001

    async def _boom() -> None:
        raise RuntimeError("db down")

    task = asyncio.get_running_loop().create_task(_boom())
    routes_mod._track_db_task(task)  # noqa: SLF001

    await routes_mod.drain_pending_db_tasks()  # must not raise
    assert not routes_mod._pending_db_tasks  # noqa: SLF001
