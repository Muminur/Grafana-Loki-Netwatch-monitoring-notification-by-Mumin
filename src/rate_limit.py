"""Rate limiting configuration for BSCCL NetWatch REST API.

Uses slowapi (a Starlette/FastAPI wrapper around limits) to enforce
per-IP request rate limits on API endpoints.

Rate limits:
  - Mutating endpoints (POST, DELETE): 30/minute per IP
  - Expensive read endpoints (/api/alerts, /api/stats/*): 200/minute per IP
  - /health and /metrics: exempt (monitoring needs unlimited access)
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

# Shared limiter instance — imported by both main.py and routes.py.
# The key function extracts the client IP from the request for per-IP limits.
limiter = Limiter(key_func=get_remote_address)

# Rate limit strings (centralised so they can be referenced in tests)
RATE_LIMIT_MUTATING = "30/minute"
RATE_LIMIT_READ = "200/minute"
