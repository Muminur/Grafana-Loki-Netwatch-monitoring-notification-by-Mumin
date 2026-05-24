"""Optional API-key authentication dependency for BSCCL NetWatch.

When the ``API_KEY`` environment variable is unset or empty (the default),
authentication is DISABLED and all requests are allowed.  This preserves
backward compatibility for deployments that do not configure a key.

When ``API_KEY`` is set to a non-empty value, mutating endpoints require the
``X-API-Key`` header to match using a constant-time comparison, preventing
timing-based key discovery.  Read-only ``GET`` endpoints, ``/health``,
``/metrics``, the dashboard pages, and the WebSocket are never protected.

Usage in routes::

    from fastapi import Depends
    from src.auth import require_api_key

    @router.post("/api/some-action", dependencies=[Depends(require_api_key)])
    async def some_action() -> ...:
        ...
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException

from src.config import get_settings


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency that enforces API-key authentication when configured.

    Behaviour
    ---------
    - If ``API_KEY`` env var is unset / empty → auth is disabled; all callers
      are allowed (backward-compatible default).
    - If ``API_KEY`` is set → the ``X-API-Key`` request header must match
      using :func:`secrets.compare_digest` (constant-time).  A missing or
      incorrect header raises ``HTTP 401``.

    The configured key and the provided value are never echoed in error
    responses or log output.

    Parameters
    ----------
    x_api_key:
        Value of the ``X-API-Key`` request header, injected by FastAPI.

    Raises
    ------
    HTTPException
        ``401 Unauthorized`` when auth is enabled and the header is missing
        or does not match the configured key.
    """
    # Strip surrounding whitespace so a whitespace-only API_KEY (a likely
    # misconfiguration) resolves to "disabled" rather than enabling auth with a
    # trivially guessable key, and so stray .env whitespace can't cause a silent
    # mismatch.
    configured_key = get_settings().api_key.strip()
    if not configured_key:
        # Auth disabled — allow every request (backward-compatible default).
        return
    # Auth enabled: require a matching header using constant-time comparison.
    provided = x_api_key or ""
    if not secrets.compare_digest(provided.encode(), configured_key.encode()):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
