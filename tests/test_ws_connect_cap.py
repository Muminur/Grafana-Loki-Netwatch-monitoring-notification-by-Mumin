"""WS handlers must bail out when the connection cap rejects them (audit A5).

``WebSocketManager.connect`` returns ``False`` (after closing the socket with
code 1008) once ``MAX_CONNECTIONS`` is reached, and documents that callers
"must check the return value and bail out". The endpoints ignored it and fell
through into ``receive_text()`` on the just-closed socket.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from starlette.websockets import WebSocketDisconnect

import src.main as main_mod


@pytest.mark.asyncio
async def test_ws_all_bails_when_connection_rejected() -> None:
    """A rejected connect() must stop the handler before the receive loop."""
    mock_ws = AsyncMock()
    mock_ws.receive_text = AsyncMock(side_effect=WebSocketDisconnect())
    with (
        patch.object(main_mod, "_ws_authenticate", AsyncMock(return_value=True)),
        patch.object(
            main_mod._ws_manager,  # noqa: SLF001
            "connect",
            AsyncMock(return_value=False),
        ),
    ):
        await main_mod.ws_all(mock_ws)
    mock_ws.receive_text.assert_not_called()


@pytest.mark.asyncio
async def test_ws_filtered_bails_when_connection_rejected() -> None:
    """Same bail-out contract for the filtered endpoint."""
    mock_ws = AsyncMock()
    mock_ws.receive_text = AsyncMock(side_effect=WebSocketDisconnect())
    with (
        patch.object(main_mod, "_ws_authenticate", AsyncMock(return_value=True)),
        patch.object(
            main_mod._ws_manager,  # noqa: SLF001
            "connect",
            AsyncMock(return_value=False),
        ),
    ):
        await main_mod.ws_filtered(mock_ws)
    mock_ws.receive_text.assert_not_called()
