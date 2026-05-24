# ── Stage 1: dependency installation ──────────────────────────────────────────
FROM python:3.11.9-slim AS base

WORKDIR /app

# Install dependencies as root before switching to non-root user
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 2: production image ─────────────────────────────────────────────────
FROM base AS production

WORKDIR /app

# Copy application source
COPY src/ ./src/
COPY .env.example ./.env.example

# Create a non-root user and own the working directory
RUN useradd --create-home --shell /bin/bash netwatch \
    && mkdir -p /app/data \
    && chown -R netwatch:netwatch /app

USER netwatch

EXPOSE 8080

# Health check: use the httpx-based one-liner (httpx is in requirements.txt)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD python -c \
    "import httpx, sys; r = httpx.get('http://localhost:8080/health', timeout=8); sys.exit(0 if r.status_code < 400 else 1)"

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
