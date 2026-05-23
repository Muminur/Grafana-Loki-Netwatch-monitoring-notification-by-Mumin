FROM python:3.11-slim AS base

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS production
COPY src/ ./src/
COPY .env.example ./.env.example

RUN useradd --create-home --shell /bin/bash netwatch
USER netwatch

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c \
    "import httpx; r = httpx.get('http://localhost:8080/health'); r.raise_for_status()"

CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8080"]
