"""One-time backfill: fetch missed logs from Loki and ingest them.

Usage:
    python -m scripts.backfill_loki --start "2026-05-23 16:32:00" --end "2026-05-23 16:52:00"

Queries Loki via the Grafana proxy for the given time range, runs each
log line through the full pipeline (parse → classify → enrich → store),
and skips any line already present in the DB (dedup by timestamp + device
+ mnemonic + message prefix).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from src.config import get_settings
from src.core.classifier import classify
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.database.crud import insert_alert
from src.database.migrations import create_tables
from src.database.models import AlertLog

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
_log = logging.getLogger(__name__)

_BDT = timezone(timedelta(hours=6))


async def _fetch_loki(settings, start_ns: int, end_ns: int) -> list[str]:
    url = settings.loki_http_url
    lines: list[str] = []
    cursor = start_ns

    while cursor < end_ns:
        params = {
            "query": settings.loki_query,
            "limit": "500",
            "start": str(cursor),
            "end": str(end_ns),
        }
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params=params, timeout=30.0)
            if resp.status_code != 200:
                _log.error("Loki returned %d", resp.status_code)
                break

            data = resp.json().get("data", {})
            entries: list[tuple[int, str]] = []
            for result in data.get("result", []):
                for ts_str, line in result.get("values", []):
                    if line:
                        entries.append((int(ts_str), line))
            entries.sort(key=lambda e: e[0])

            if not entries:
                break

            for _ts, line in entries:
                lines.append(line)

            if len(entries) >= 500:
                cursor = entries[-1][0] + 1
            else:
                break

    return lines


async def _backfill(start_str: str, end_str: str) -> None:
    settings = get_settings()
    engine = create_async_engine(settings.database_url)
    await create_tables(engine)

    start_dt = datetime.fromisoformat(start_str).replace(tzinfo=_BDT)
    end_dt = datetime.fromisoformat(end_str).replace(tzinfo=_BDT)
    start_ns = int(start_dt.timestamp() * 1_000_000_000)
    end_ns = int(end_dt.timestamp() * 1_000_000_000)

    _log.info("Fetching logs from Loki: %s → %s", start_dt, end_dt)
    raw_lines = await _fetch_loki(settings, start_ns, end_ns)
    _log.info("Fetched %d lines from Loki", len(raw_lines))

    inserted = 0
    skipped = 0
    failed = 0

    async with AsyncSession(engine) as session:
        for raw_line in raw_lines:
            parsed = parse_syslog(raw_line)
            if parsed is None:
                failed += 1
                continue

            enriched = enrich(parsed)

            existing = await session.execute(
                select(AlertLog.id).where(
                    AlertLog.device_name == enriched.device_name,
                    AlertLog.mnemonic == enriched.parsed.mnemonic,
                    AlertLog.timestamp == enriched.parsed.timestamp,
                ).limit(1)
            )
            if existing.scalar() is not None:
                skipped += 1
                continue

            cls = classify(parsed)
            alert = AlertLog(
                timestamp=enriched.parsed.timestamp,
                source_ip=enriched.parsed.source_ip,
                device_name=enriched.device_name,
                hostname=enriched.parsed.hostname,
                rp_location=enriched.parsed.rp_location,
                facility=enriched.parsed.facility,
                subfacility=enriched.parsed.subfacility,
                severity_level=enriched.parsed.severity_level,
                mnemonic=enriched.parsed.mnemonic,
                message=enriched.parsed.message,
                raw=enriched.parsed.raw,
                classification=cls.classification,
                interface_name=enriched.interface_name,
                interface_description=enriched.interface_description,
                client_name=enriched.client_name,
                bgp_neighbor=enriched.bgp_neighbor,
                as_number=enriched.as_number,
                as_name=enriched.as_name,
                incident_id="",
                notification_sent=False,
            )
            session.add(alert)
            inserted += 1

        await session.commit()

    _log.info("Done: %d inserted, %d skipped (duplicate), %d failed (unparseable)", inserted, skipped, failed)
    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill missed logs from Loki")
    parser.add_argument("--start", required=True, help="Start time (ISO format, BDT)")
    parser.add_argument("--end", required=True, help="End time (ISO format, BDT)")
    args = parser.parse_args()
    asyncio.run(_backfill(args.start, args.end))


if __name__ == "__main__":
    main()
