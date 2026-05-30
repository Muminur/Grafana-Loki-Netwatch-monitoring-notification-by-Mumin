"""Repeatable Discord/Telegram notification drill for BSCCL NetWatch.

Drives the REAL pipeline (parse -> enrich -> correlate -> dedup) on sample
CRITICAL syslog lines, then calls the REAL notification senders so you can
confirm end-to-end delivery and see how alerts render in the channel.

Every message is clearly marked "[TEST-DRILL]" in the device and event so
on-call NOC staff immediately see it is not a real outage.

SAFETY: dry-run by default — it only prints what *would* be sent. Pass
``--send`` to actually deliver to the channels enabled in ``.env``.

Usage:
    python -m scripts.test_notifications                  # dry-run, no network
    python -m scripts.test_notifications --send           # send to enabled channels
    python -m scripts.test_notifications --send --channel discord
    python -m scripts.test_notifications --send --channel telegram

The webhook URL / bot token are read from ``.env`` at runtime — never hardcoded.
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import logging
import sys
from typing import TYPE_CHECKING

from src.config import get_settings
from src.core.correlator import CorrelationEngine
from src.core.dedup import DedupEngine
from src.core.enricher import enrich
from src.core.parser import parse_syslog
from src.notifications.discord import (
    send_discord_alert,
    send_discord_escalation,
    send_discord_resolution,
)
from src.notifications.formatter import (
    format_discord_embed,
    format_escalation_discord_embed,
    format_escalation_telegram_message,
    format_resolution_discord_embed,
    format_resolution_telegram_message,
    format_telegram_message,
)
from src.notifications.telegram import (
    send_telegram_alert,
    send_telegram_escalation,
    send_telegram_resolution,
)

if TYPE_CHECKING:
    from src.config import Settings
    from src.core.enricher import EnrichedLog

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
# httpx logs the request line at INFO; quiet it (it never leaks the secret URL).
logging.getLogger("httpx").setLevel(logging.WARNING)
_log = logging.getLogger(__name__)

# ── Sample scenario (real syslog formats; contains NO secrets) ──────────────
# A BGP peer flap on EQ-RTR-01 to AS399077 (TCLOUD): Down, then Up.
_DOWN_LINE = (
    "May 22 21:12:21 192.168.203.1 9238766: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:12:21.651 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Down - BGP Notification received (VRF: network) (AS: 399077)"
)
_UP_LINE = (
    "May 22 21:15:00 192.168.203.1 9238800: BSCCL-EQ-RTR-01 "
    "RP/0/RP0/CPU0:May 22 21:15:00.000 +06: bgp[1097]: "
    "%ROUTING-BGP-5-ADJCHANGE : neighbor 2001:de8:4::39:9077:1 "
    "Up (VRF: network) (AS: 399077)"
)

_ELAPSED_MIN = 15
# Synthetic incident id so the three messages tell one coherent story and the
# alert embed exercises the incident-context fields. A standalone BGP-down does
# not form an incident on its own, so we do not rely on the correlator's id.
_INCIDENT_ID = "INC-TEST-DRILL-001"
_RELATED_COUNT = 3


def _enable_utf8_stdout() -> None:
    """Best-effort UTF-8 console so emoji in embed titles print on Windows."""
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure):
        reconfigure(encoding="utf-8")


def _mark_test(enr: EnrichedLog) -> EnrichedLog:
    """Return a copy with unmistakable TEST-DRILL markers in device + event."""
    return dataclasses.replace(
        enr,
        device_name=f"[TEST-DRILL] {enr.device_name}",
        event_type=f"[TEST DRILL — IGNORE] {enr.event_type}",
    )


def _build_enriched(line: str) -> EnrichedLog:
    """Parse + enrich one line, marked as a test. Exits if the line won't parse."""
    parsed = parse_syslog(line)
    if parsed is None:
        _log.error("Sample line failed to parse — aborting.")
        raise SystemExit(1)
    return _mark_test(enrich(parsed))


def _incident_ctx() -> dict[str, object]:
    return {"incident_id": _INCIDENT_ID, "related_count": _RELATED_COUNT}


def _print_pipeline_status() -> None:
    """Run the real correlate + dedup stages and print their verdicts."""
    parsed = parse_syslog(_DOWN_LINE)
    if parsed is None:
        return
    enr = enrich(parsed)
    corr = CorrelationEngine().correlate(enr)
    should_send, reason = DedupEngine().should_notify(enr)
    print(
        f"[pipeline] class={enr.classification} notify={enr.notify} "
        f"should_send={should_send} ({reason}) "
        f"correlator_incident={corr.incident_id}"
    )


def _preview_discord(
    enr_down: EnrichedLog, enr_up: EnrichedLog, settings: Settings
) -> None:
    ctx = _incident_ctx()
    alert = format_discord_embed(enr_down, settings, incident_context=ctx)
    esc = format_escalation_discord_embed(enr_down, _ELAPSED_MIN)
    res = format_resolution_discord_embed(enr_up, _INCIDENT_ID, settings)
    print("  discord alert      :", alert["embeds"][0]["title"])
    print("  discord escalation :", esc["embeds"][0]["title"])
    print("  discord resolution :", res["embeds"][0]["title"])


def _preview_telegram(enr_down: EnrichedLog, enr_up: EnrichedLog) -> None:
    ctx = _incident_ctx()
    alert = format_telegram_message(enr_down, incident_context=ctx)
    esc = format_escalation_telegram_message(enr_down, _ELAPSED_MIN)
    res = format_resolution_telegram_message(enr_up, _INCIDENT_ID)
    print("  telegram alert      :", alert.splitlines()[0])
    print("  telegram escalation :", esc.splitlines()[0])
    print("  telegram resolution :", res.splitlines()[0])


async def _send_discord(
    enr_down: EnrichedLog, enr_up: EnrichedLog, settings: Settings
) -> bool:
    ctx = _incident_ctx()
    print(">>> discord: sending alert / escalation / resolution ...")
    r1 = await send_discord_alert(enr_down, settings, incident_context=ctx)
    await asyncio.sleep(1.0)
    r2 = await send_discord_escalation(enr_down, _ELAPSED_MIN, settings)
    await asyncio.sleep(1.0)
    r3 = await send_discord_resolution(enr_up, _INCIDENT_ID, settings)
    print(f"    discord results: alert={r1} escalation={r2} resolution={r3}")
    return all((r1, r2, r3))


async def _send_telegram(
    enr_down: EnrichedLog, enr_up: EnrichedLog, settings: Settings
) -> bool:
    ctx = _incident_ctx()
    print(">>> telegram: sending alert / escalation / resolution ...")
    r1 = await send_telegram_alert(enr_down, settings, incident_context=ctx)
    await asyncio.sleep(1.0)
    r2 = await send_telegram_escalation(enr_down, _ELAPSED_MIN, settings)
    await asyncio.sleep(1.0)
    r3 = await send_telegram_resolution(enr_up, _INCIDENT_ID, settings)
    print(f"    telegram results: alert={r1} escalation={r2} resolution={r3}")
    return all((r1, r2, r3))


async def _run(channel: str, do_send: bool) -> int:
    settings = get_settings()
    enr_down = _build_enriched(_DOWN_LINE)
    enr_up = _build_enriched(_UP_LINE)

    want_discord = channel in ("discord", "all")
    want_telegram = channel in ("telegram", "all")

    print(f"channel={channel} mode={'SEND' if do_send else 'DRY-RUN'}")
    print(
        f"discord_enabled={settings.discord_enabled} "
        f"telegram_enabled={settings.telegram_enabled}"
    )
    _print_pipeline_status()

    if not do_send:
        print("\n-- DRY-RUN preview (no network). Pass --send to deliver. --")
        if want_discord:
            _preview_discord(enr_down, enr_up, settings)
        if want_telegram:
            _preview_telegram(enr_down, enr_up)
        return 0

    print("\n-- SEND mode: delivering to a LIVE channel. --")
    results: list[bool] = []
    if want_discord:
        if settings.discord_enabled:
            results.append(await _send_discord(enr_down, enr_up, settings))
        else:
            print(">>> discord: disabled in .env — skipped.")
    if want_telegram:
        if settings.telegram_enabled:
            results.append(await _send_telegram(enr_down, enr_up, settings))
        else:
            print(">>> telegram: disabled in .env — skipped.")

    if not results:
        print("\nNothing sent — no targeted channel is enabled in .env.")
        return 1
    ok = all(results)
    print("\n" + ("ALL OK" if ok else "SOME FAILED"))
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send clearly-marked TEST-DRILL notifications via the real "
        "pipeline. Dry-run by default; use --send to deliver."
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Actually deliver to the channels enabled in .env "
        "(default: dry-run, no network).",
    )
    parser.add_argument(
        "--channel",
        choices=("discord", "telegram", "all"),
        default="all",
        help="Which channel(s) to target (default: all).",
    )
    args = parser.parse_args()
    _enable_utf8_stdout()
    raise SystemExit(asyncio.run(_run(args.channel, args.send)))


if __name__ == "__main__":
    main()
