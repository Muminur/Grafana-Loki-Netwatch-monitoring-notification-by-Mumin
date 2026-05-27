<p align="center">
  <img src="docs/assets/logo-animated.svg" alt="BSCCL NetWatch" width="700"/>
</p>

<p align="center">
  <strong>Mission-Critical Network Operations Center Dashboard</strong><br/>
  <em>Real-time syslog classification, alerting, and incident correlation for Bangladesh's submarine cable backbone</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"/>
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/SQLite-WAL_Mode-003B57?style=for-the-badge&logo=sqlite&logoColor=white" alt="SQLite"/>
  <img src="https://img.shields.io/badge/Loki-WebSocket-F2733C?style=for-the-badge&logo=grafana&logoColor=white" alt="Loki"/>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-995_passing-00ff88?style=flat-square" alt="Tests"/>
  <img src="https://img.shields.io/badge/coverage-96%25-00ff88?style=flat-square" alt="Coverage"/>
  <img src="https://img.shields.io/badge/ruff-clean-00f0ff?style=flat-square" alt="Ruff"/>
  <img src="https://img.shields.io/badge/mypy-strict-8b5cf6?style=flat-square" alt="Mypy"/>
  <img src="https://img.shields.io/badge/license-proprietary-555570?style=flat-square" alt="License"/>
</p>

---

## What is this?

BSCCL (Bangladesh Submarine Cable Company Limited) operates a multi-site ISP/carrier backbone spanning **5 locations across 2 countries** — from Dhaka and Cox's Bazar in Bangladesh to Singapore's Equinix data center. Their existing Grafana syslog dashboard shows thousands of raw, unclassified log lines, making it impossible to distinguish a critical fiber cut from routine noise.

**NetWatch** replaces that chaos with an intelligent, real-time alert classification system that:

- **Parses** 4 distinct Cisco IOS-XR syslog formats from 34 network devices
- **Classifies** every log into 5 severity tiers using 26 regex rules
- **Enriches** each alert with device identity, interface descriptions, client names, and AS numbers from 845+ interface mappings
- **Correlates** cascading failures — a single fiber cut generating 200+ alerts becomes **one incident**
- **Notifies** operators via Discord and Telegram with deduplication and flap detection
- **Displays** everything in a futuristic neon-themed dashboard optimized for 55" 4K NOC wall TVs, with live topology, charts, and sound alerts
- **Auto-resolves** incidents when recovery events arrive (Interface Up, Bundle Active, BGP Up) — only genuinely unresolved faults remain

<p align="center">
  <img src="docs/assets/pipeline-flow.svg" alt="Processing Pipeline" width="800"/>
</p>

---

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="System Architecture" width="800"/>
</p>

### Processing Pipeline

```
Syslog (UDP 514) → Grafana Loki → WebSocket Tail → NetWatch Pipeline
                                                        │
                    ┌───────────────────────────────────┘
                    │
              ┌─────▼──────┐     ┌──────────┐     ┌──────────┐
              │   Parser    │────▶│Classifier│────▶│ Enricher │
              │ 4 IOS-XR   │     │ 26 rules │     │ 845 intf │
              │  formats    │     │ 121 AS   │     │ 33 devs  │
              └─────────────┘     └──────────┘     └────┬─────┘
                                                        │
              ┌─────────────┐     ┌──────────┐     ┌────▼─────┐
              │   Dedup     │◀────│Correlator│◀────│  Store   │
              │ 5m/2m/30s   │     │ Incidents│     │  SQLite  │
              └──────┬──────┘     └──────────┘     └──────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   ┌─────────┐ ┌─────────┐ ┌──────────┐
   │ Discord │ │Telegram │ │Dashboard │
   │ Webhook │ │  Bot    │ │WebSocket │
   └─────────┘ └─────────┘ └──────────┘
```

---

## Network Topology

<p align="center">
  <img src="docs/assets/topology.svg" alt="Network Topology" width="600"/>
</p>

The correlation engine uses the **network dependency tree** to automatically detect root causes. When `Bundle-Ether500` (the 9-link backhaul between Singapore and Kuakata) degrades, NetWatch:

1. Identifies the member link failure as **root cause**
2. Marks all subsequent BGP peer-down alerts as **symptoms**
3. Groups everything into a **single incident** (e.g. `INC-20260523-001`)
4. Suppresses 200+ redundant notifications
5. Lists all **affected clients** from the topology tree

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Network devices monitored | **34** across 5 sites |
| Interface mappings | **845** with descriptions |
| BGP peers tracked | **294** (210 MLPE IX + 84 PNI/transit) |
| AS number database | **121** entries with names and types |
| Classification rules | **26** (14 CRITICAL, 3 WARNING, 6 INFO, 3 LOGIN) |
| Syslog formats parsed | **4** (IOS-XR +06, BDT, ADMIN, bare) |
| Dedup windows | **5 min** standard, **2 min** BGP flap, **30 sec** bundle |
| Test suite | **995 tests**, 96% coverage |

---

## Quick Start

### Prerequisites

- Python 3.11 or 3.12
- Access to Grafana Loki at `192.168.200.230:3100` (office) or `103.16.152.8:3100` (remote)

### Local Development

```bash
# Clone
git clone https://github.com/Muminur/Grafana-Loki-Netwatch-monitoring-notification-by-Mumin.git
cd Grafana-Loki-Netwatch-monitoring-notification-by-Mumin

# Setup
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt -r requirements-dev.txt

# Configure
cp .env.example .env
# Edit .env with your Loki host, Discord webhook, Telegram token

# Run
uvicorn src.main:app --host 0.0.0.0 --port 8080 --reload

# Open http://localhost:8080
```

### Docker

```bash
# Build and run
docker-compose up -d

# Check health
curl http://localhost:8080/health
```

### Run Tests

```bash
# Full test suite
pytest -vv

# With coverage
coverage run -m pytest && coverage report

# Lint + type check
ruff check .
black --check .
mypy src/
```

---

## Configuration

All configuration is via environment variables (`.env` file):

```env
# Network access — choose your location
MONITOR_HOST=192.168.200.230    # BSCCL office
# MONITOR_HOST=103.16.152.8    # Remote / home

# Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_ENABLED=true
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
TELEGRAM_ENABLED=true

# Grafana
GRAFANA_API_KEY=...
GRAFANA_DASHBOARD_UID=8sWAY1LMz

# Dedup windows (seconds)
DEDUP_WINDOW_SECONDS=300
BGP_FLAP_WINDOW_SECONDS=120
BUNDLE_GROUP_WINDOW_SECONDS=30

# ASN organization lookup (BigDataCloud — cached in SQLite)
ASN_API_KEY=...

# Optional API authentication — empty = disabled (default). When set, mutating
# endpoints require a matching X-API-Key header.
API_KEY=

# Data retention — alerts older than this are auto-pruned daily at 03:00 UTC
RETENTION_DAYS=90

# Logging — "text" (default) or "json" for structured logs; standard level names
LOG_FORMAT=text
LOG_LEVEL=INFO
```

---

## Dashboard Features

### NOC Wall Display (55" 4K Optimized)
The dashboard is designed for deployment on a 55-inch 4K TV in the Network Operations Center:
- **Side-by-side layout** — Active Incidents (left 40%) + Alert Stream (right 60%)
- **4K typography scaling** — base font 14px → 24px at `@media (min-width: 2000px)` for distance reading
- **~49 visible alert rows** at 4K resolution, filling the full viewport height
- **CRITICAL tab** is the default view on page load
- Responsive collapse to single column below 1100px for desk/dev use

### Neon-Themed UI
Futuristic "Mission Control" design with:
- **Orbitron** display font for headers
- **JetBrains Mono** for data and numbers
- Glassmorphism cards with neon glow borders
- Pulsing red animation for CRITICAL alerts
- Dark void background (`#080812`)

### 6 Severity Tabs
| Tab | Color | Content |
|-----|-------|---------|
| CRITICAL | `#ff0040` (red glow) | BGP down/up, faults, SFP alarms, interface down/up, bundle active/expired |
| WARNING | `#ffdd00` (yellow) | BGP max-prefix reached, BER clear, SFP clear |
| INFO | `#00f0ff` (cyan) | Known noise, port creation failures, EEM scripts |
| NOISE | `#555570` (dim) | Repeated known issues, hidden by default |
| LOGIN | `#00ff88` (green) | SSH login/logout with session tracking |
| STATS | `#8b5cf6` (purple) | Health score, charts, SLA metrics |

### Active Incidents Panel
- **Rich titles** with shortened interface names and actionable context:
  - Bundle: `Bundle DOWN — KKT-Core-2, TGE0/0/1/7, BE201`
  - BGP: `ADJCHANGE — KKT-Core-3 DOWN - Orange S.A.`
  - Fault: `RXFault-KKT-Core-1 - TGE0/0/0/2 - Local Fault`
- **Client/circuit info** — each incident card shows the client name or circuit ID when available (e.g. `DHK-KKT-BH-LINK-02-VIA-F@H-KKT-Te0/1/0/23-121492`)
- **Acknowledge with audit trail** — ACK button on each incident opens a modal requiring operator name and comment; full audit history stored in SQLite (`/api/incidents/{id}/acks`)
- **Bulk acknowledge** — `Shift+A` acknowledges all active incidents with a single comment
- **Visual/sound alarm** — unacknowledged incidents pulse with red glow border and trigger an alarm sound; configurable "Repeat Incident Alarm" toggle in Settings controls whether the alarm repeats every 30 seconds or plays only once on first detection (pulsing red border always stays visible)
- **Auto-resolution** — DOWN incidents automatically clear when the interface/BGP recovers
- **Device-specific matching** — same interface name on different routers (connecting to different far-end equipment) is correctly treated as separate incidents
- **ASN organization names** — resolved via BigDataCloud API, cached in SQLite (never re-fetched)

### Shift Handoff System
Three shifts aligned to BSCCL NOC operations (BDT timezone):
| Shift | Hours |
|-------|-------|
| Morning | 08:00 — 15:00 |
| Evening | 15:00 — 22:30 |
| Night | 22:30 — 08:00 |

- **Shift banner** at the top of the dashboard showing current shift name, start time, CRITICAL/WARNING counts since shift start, and open incident count
- **Handoff notes** — outgoing operator clicks HANDOFF to submit a free-text note with shift context, persisted in SQLite; incoming operator sees the last 3 notes in a "LAST SHIFT HANDOFF" panel below the topology
- **Toast feedback** — success/error notifications after handoff submission
- **Shift summary API** — `GET /api/shift/current` returns the current shift name, start time, and alert counts since shift start

### Live Features
- **Auto-reconnecting WebSocket** with heartbeat — stale connections detected after 30s of silence; visible reconnection feedback ("Reconnecting...", "Connection lost — check server") after repeated failures
- **Race-safe alert fetching** — WebSocket events are queued during REST fetches to prevent data corruption; API calls are debounced (300ms) to prevent server flooding
- **Loading & error states** — async fetches show loading indicators and surface errors to the operator instead of failing silently
- **Deduplication enforced** — DB storage, WebSocket broadcast, and in-memory store all respect the 5-minute dedup window
- **Client-side dedup safety net** — 5-minute sliding-window check in the browser
- **Web Audio API** sound alerts (critical alarm, warning chime, recovery arpeggio)
- **Browser notifications** for CRITICAL events when the tab is in background (Web Notification API with permission management and dedup via `tag`)
- **Relative timestamps** — every alert card shows "5s ago", "2m ago" alongside the absolute timestamp, updated every 10 seconds without re-rendering the DOM
- **Keyboard shortcuts** — `1-5` switch tabs, `A` acknowledge alert, `Shift+A` bulk-acknowledge incidents, `N` mute, `/` search — with **toast feedback** on each shortcut activation
- **Search filter badge** — persistent visual indicator showing "Filtered: BGP ×" when search is active, with one-click clear
- **Clear alerts undo** — confirmation dialog + 5-second undo bar prevents accidental data loss during live incidents
- **SVG network topology** with live device status colors, click debouncing, and **device detail modal** — click any node to see device name, location, status, and last 10 alerts
### Settings Page (All Toggles Functional)

**Notification Preferences** (server-side, persisted in DB):
- **Discord Notifications** — enable/disable Discord webhook alerts at runtime
- **Telegram Notifications** — enable/disable Telegram bot alerts at runtime
- **Minimum Alert Severity** — set the notification threshold (CRITICAL only, WARNING+, or INFO+)
- **Deduplication Window** — adjust the dedup suppression window (30–3600 seconds)
- All server-side settings save instantly with visual toast feedback and persist across page navigation and server restarts

**Alert Classification:**
- **Hardware Defects as Noise** toggle (default ON) — classifies persistent
  hardware faults (`RX_FAULT` / `SIGNAL` / `RFI`) on backbone P2P bundle members as NOISE
  instead of CRITICAL. Exposed via `GET`/`POST /api/settings/hardware-noise`

**Sound Settings** (client-side, localStorage):
- **Alert Sounds** master toggle — enable/disable all sounds
- **Critical Alarm** — toggle the critical event alarm sound
- **Warning Chime** — toggle the warning event chime
- **Recovery Arpeggio** — toggle the recovery event sound
- **Repeat Incident Alarm** — when ON, alarm repeats every 30s for unacked incidents; when OFF, plays once on first detection (pulsing red border remains visible either way)
- **Test buttons** — preview each sound type

**Maintenance Windows:**
- **Create** maintenance windows per device with start/end time and reason
- **List** active/upcoming windows with delete buttons
- **Auto-suppression** — CRITICAL notifications for a device are suppressed during its maintenance window

---

## Classification Rules

<details>
<summary><strong>14 CRITICAL rules</strong> (trigger Discord + Telegram notifications)</summary>

| Rule | Pattern | Event |
|------|---------|-------|
| `BGP_DOWN` | `ADJCHANGE.*Down` | BGP peer went down |
| `LACP_EXPIRED` | `no longer Active` | Bundle member LACP expired |
| `REMOTE_FAULT` | `RX_FAULT.*Remote Fault` | Remote fault (DPA) |
| `LOCAL_FAULT` | `RX_FAULT.*Local Fault` | Local fault (DPA) |
| `RFI_FAULT` | `RFI.*Detected.*Fault` | Remote/local fault (RFI) |
| `SIGNAL_FAILURE` | `Signal failure` | Signal failure on interface |
| `SFP_ALARM_SET` | `LOW_RX_POWER_ALARM.*Set` | SFP optic failing |
| `DUPLICATE_IPV6` | `ADDRESS_DUPLICATE` | Duplicate IPv6 address |
| `INTF_DOWN` | `UPDOWN.*Down` | Interface went down |
| `LINEPROTO_DOWN` | `LINEPROTO.*Down` | Line protocol went down |
| `BGP_UP` | `ADJCHANGE.*Up` | BGP peer came up (recovery) |
| `INTF_UP` | `UPDOWN.*Up` | Interface came up (recovery) |
| `LINEPROTO_UP` | `LINEPROTO.*Up` | Line protocol came up (recovery) |
| `LACP_ACTIVE` | `BM-6-ACTIVE.*Active` | Bundle member became active (recovery) |
</details>

<details>
<summary><strong>3 WARNING rules</strong></summary>

`BGP_MAXPFX` (max prefix threshold), `BER_CLEAR`, `SFP_ALARM_CLEAR`
</details>

<details>
<summary><strong>6 INFO rules</strong></summary>

`PORT_CREATION_FAIL`, `OPERATION_STALLED`, `HW_EVENT_OK`, `EEM_COMMIT`, `EEM_SCRIPT`, `NSR_DISABLED`
</details>

<details>
<summary><strong>3 USER_LOGIN rules</strong></summary>

`SSH_LOGIN`, `SSH_LOGOUT`, `CONFIG_COMMIT_USER`
</details>

---

## Event Correlation

The correlation engine is what makes NetWatch genuinely useful in production. Without it, a single fiber cut generates 200+ alerts. With it:

```
WITHOUT CORRELATION:                    WITH CORRELATION:
─────────────────────                   ─────────────────
Alert: BE500 member TenGigE0/0/0/0 ↓   Incident: INC-20260523-001
Alert: BE500 member TenGigE0/0/0/1 ↓   Root: Bundle-Ether500 DEGRADED
Alert: BE500 member TenGigE0/0/0/2 ↓   Device: EQ-RTR-01 (Singapore)
Alert: BGP DOWN AS399077 TCLOUD         Affected: 3/9 members down
Alert: BGP DOWN AS24482 SG.GS          Suppressed: 47 symptom alerts
Alert: BGP DOWN AS714 Apple             Clients: KKT-01, DHK-03,
Alert: BGP DOWN AS8075 Microsoft          Skytel, ADN, Velocity,
Alert: BGP DOWN AS15169 Google             Novocom, Link3, ...
Alert: BGP DOWN AS32934 Facebook
... (200+ more alerts)                  1 notification (not 200+)
```

---

## Notification Pipeline

### Channels

| Channel | Transport | Format | When |
|---------|-----------|--------|------|
| **Discord** | Webhook POST | Color-coded embed (red CRITICAL, yellow WARNING) | Every non-suppressed alert with `notify=true` |
| **Telegram** | Bot API `sendMessage` | MarkdownV2 with bold device/mnemonic | Same trigger as Discord (parallel delivery) |
| **Discord Escalation** | Webhook POST | Pure red embed (0xFF0000), distinct from regular alerts | CRITICAL unacknowledged > 15 minutes |
| **Telegram Escalation** | Bot API `sendMessage` | Bold "ESCALATION" prefix with elapsed minutes | Same trigger as Discord escalation |

### Delivery Reliability

Both Discord and Telegram senders implement production-grade delivery:

- **Exponential backoff** — up to 3 retries with doubling wait (1s → 2s → 4s)
- **HTTP 429 Rate Limit** — honours `Retry-After` header (integer seconds or RFC 2822 date); waits the exact duration before retry
- **Webhook/token validation** — format-checks the URL/token before attempting delivery; logs an error and returns early for invalid credentials
- **Field sanitisation** — all user-facing fields (device name, message, interface, AS name) are sanitised before inclusion in payloads
- **Secret redaction** — webhook URLs and bot tokens are never written to log files; only the first/last 4 characters appear in debug logs
- **Timeout** — 10-second connection + read timeout per attempt to prevent blocking the pipeline

### Notification Lifecycle

```
Alert arrives → Classify → Enrich → Correlate → Dedup check
                                                      │
                            ┌─────────────────────────┘
                            │
                     Should notify?
                     ├── Suppressed by dedup window → skip
                     ├── Suppressed by incident (is_symptom) → skip
                     ├── Suppressed by maintenance window → skip
                     └── Yes → send to Discord + Telegram
                                      │
                                      ▼
                              Store in DB → Push to WebSocket
                                      │
                                      ▼ (15 min later, if unacked)
                              Escalation checker fires
                              └── Send escalation to Discord + Telegram
                                  └── Mark as escalated (no re-send)
```

### Dedup Strategies

| Strategy | Window | Key | Trigger |
|----------|--------|-----|---------|
| **Standard dedup** | 5 minutes | `device:mnemonic:interface_or_neighbor` | Same event within window → suppressed |
| **BGP flap detection** | 2 minutes | `device:neighbor` | Down → Up → Down → single "FLAPPING" alert |
| **Bundle member grouping** | 30 seconds | `device:bundle_parent` | Multiple member events → grouped by parent bundle |
| **Incident auto-resolution** | Real-time | `device:interface` or `device:AS` | Recovery event (Up/Active/Clear) removes matching DOWN incident |
| **BGP-UP silent fault clear** | Real-time | `device:bundle_members` | BGP UP on backbone P2P bundle auto-resolves RX_FAULT/SIGNAL/RFI (IOS-XR never sends explicit clears for optical faults) |

Dedup is enforced at every layer: DB storage, WebSocket broadcast, in-memory store, and client-side browser. The dedup engine uses `max(event-time, monotonic-clock)` elapsed so replayed/historical logs and backward clock steps are handled without mis-suppressing real alerts. Stale dedup entries are automatically evicted every 100 calls to prevent unbounded memory growth.

### Escalation Pipeline

1. A background task (`_escalation_checker`) runs every 60 seconds
2. It scans in-memory CRITICAL alerts that have been unacknowledged for > 15 minutes
3. For each pending escalation:
   - Formats a distinct **ESCALATION** notification (pure red Discord embed, bold Telegram prefix)
   - Sends to both Discord and Telegram (if enabled)
   - Marks the alert as escalated to prevent re-sending on subsequent cycles
4. Escalation tracking is persisted to SQLite and restored on restart — no escalation is lost across server restarts

### Statistics Aggregation

A background task (`_hourly_aggregator`) runs every 5 minutes and pre-aggregates alert counts into the `HourlyStats` table by device and hour. This enables fast statistics queries for the Statistics page without scanning the full `AlertLog` table on every request.

---

## Reliability & Security Hardening

Production-hardening applied across the stack:

- **HTTP security headers** on every response — `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. CORS origins configurable via `CORS_ORIGINS`; `allow_headers` restricted to `content-type` and `x-api-key`.
- **SSRF guard** — `MONITOR_HOST` is validated at startup (rejects URI schemes and malformed IP addresses) with descriptive error messages including valid examples.
- **Notification delivery** — Discord webhook URLs validated for HTTPS-only and length (2048 max); Telegram bot tokens validated for format and length (100 max). Sends retry with exponential backoff, honour HTTP 429 `Retry-After`, sanitise message fields; secrets never written to logs.
- **Syslog ingest resilience** — Loki HTTP poll uses exponential backoff with a lag warning and page-boundary cursor de-duplication (no silent data loss); UDP rate limiting (1000 pkt/s default) with token bucket and guaranteed socket cleanup via `try/finally`; per-transport error counters exposed via `health_status()`.
- **Memory-bounded correlation** — incident cache capped at 10,000 entries with LRU eviction; prevents unbounded memory growth during high-volume events.
- **Input limits** — the parser caps line length (ReDoS/DoS guard); the API validates `severity`/`period` filters (HTTP 400) and bounds the in-memory maintenance store; the WebSocket manager caps connections and drops slow clients (backpressure); dedup engine validates `window_seconds > 0`.
- **Database** — `incident_id` and silent-fault-resolution indexes, an idempotent index migration, and connection pre-ping.
- **AS-cache** — tight timeout, bounded retry, timezone-correct TTL, and URL/key redaction in logs.
- **Supply chain & image** — CI runs `pip-audit`; all dependencies pinned with upper bounds; Docker image is pinned and non-root with a `.dockerignore`, resource limits, and `no-new-privileges`.
- **Authentication (opt-in)** — set `API_KEY` to require an `X-API-Key` header (constant-time check, `WWW-Authenticate` challenge on 401) for mutating endpoints; empty = disabled, so existing deployments are unaffected. **WebSocket endpoints** (`/ws`, `/ws/filtered`) also enforce auth via `?token=` query parameter when `API_KEY` is set.
- **REST API rate limiting** — per-IP rate limits via `slowapi`: 30 req/min for mutating endpoints, 200 req/min for reads. `/health` and `/metrics` are exempt.
- **Startup resilience** — server starts successfully even when Loki is unreachable, with automatic reconnection via exponential backoff (1s → 60s). The dashboard serves cached data until Loki comes up.
- **Self-monitoring** — `/health` endpoint reports `loki_connected` and `last_alert_received_at`; a background task sends Discord/Telegram alerts if no syslog data arrives for 10+ minutes (with startup grace period).
- **Database retention** — automated cleanup task prunes alerts older than `RETENTION_DAYS` (default 90) and runs SQLite VACUUM at 03:00 UTC daily.
- **State survives restart** — maintenance windows, the Hardware-Defects-as-Noise toggle, and in-flight CRITICAL escalation tracking are persisted to SQLite and restored on startup; the incident-ID counter is seeded from the DB so IDs never collide across a restart.
- **Observability** — optional structured JSON logs (`LOG_FORMAT=json`) with a per-request `X-Request-ID`, Prometheus `/metrics` endpoint (alerts processed, dedup suppressed, notifications sent, live WebSocket connections), and `/health` endpoint with background task liveness.
- **Dedup correctness** — the window uses `max(event-time, monotonic)` elapsed so replayed/historical logs and backward clock steps are handled without mis-suppressing real alerts. Eviction logging tracks purged entries for operational visibility.
- **Accessibility** — ARIA labels on form hints, chart containers, and emoji icons; keyboard focus indicators (`:focus-visible`) on all interactive elements; acknowledged alert contrast meets WCAG AA (opacity 0.6 + grayscale); responsive tablet breakpoint at 768px.
- **Static asset cache busting** — CSS/JS served with version query params (`?v=2.0`) to ensure clients load updated assets after deployments.

---

## API Reference

> Mutating endpoints (`POST`/`DELETE`) require an `X-API-Key` header **when `API_KEY` is set**. GET endpoints, `/health`, and `/metrics` are open. WebSocket endpoints require `?token=` when `API_KEY` is set. Rate limits: 30 req/min for mutating, 200 req/min for reads.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check — uptime, alert count, DB connectivity, Loki connection status (`loki_connected`, `last_alert_received_at`, `stale_data`), and background task liveness; `status: degraded` when data is stale or DB check fails |
| `/metrics` | GET | Prometheus metrics (alerts processed, dedup suppressed, notifications sent, WebSocket connections) |
| `/api/alerts` | GET | Paginated alerts with severity/device/time filters |
| `/api/alerts/count` | GET | Alert counts by classification for a period |
| `/api/alerts/{id}` | GET | Single alert details |
| `/api/incidents` | GET | Active incidents |
| `/api/incidents/{id}` | GET | Incident details with symptom list |
| `/api/incidents/{id}/acknowledge` | POST | Acknowledge an incident (requires operator name + comment) |
| `/api/incidents/{id}/acks` | GET | Acknowledgement audit trail for an incident |
| `/api/shift/current` | GET | Current shift info (name, start time, alert counts since shift start) |
| `/api/shift/handoffs` | GET | Recent shift handoff notes |
| `/api/shift/handoff` | POST | Create a shift handoff note |
| `/api/stats/daily` | GET | Today's alert statistics |
| `/api/stats/weekly` | GET | 7-day statistics |
| `/api/stats/monthly` | GET | 30-day statistics |
| `/api/stats/yearly` | GET | 12-month statistics |
| `/api/stats/heatmap` | GET | 7×24 alert heatmap (day-of-week × hour-of-day) |
| `/api/alerts/export` | GET | CSV export with period filter (max 50K rows) |
| `/api/settings/hardware-noise` | GET / POST | Read or toggle "Hardware Defects as Noise" |
| `/api/settings/notifications` | GET / POST | Read or update notification preferences (Discord, Telegram, severity threshold, dedup window) |
| `/api/maintenance` | GET / POST | List or create maintenance windows |
| `/api/maintenance/{id}` | DELETE | Delete a maintenance window |
| `/api/devices` | GET | All 34 devices with status |
| `/api/topology` | GET | Network topology (nodes + links) |
| `/api/bgp/peers` | GET | BGP peer status |
| `/ws` | WS | Live alert stream (all classifications) |
| `/ws/filtered` | WS | Filtered alert stream (subscribe per severity) |

---

## Statistics & SLA

### Network Health Score (0-100)

| Factor | Impact |
|--------|--------|
| Active CRITICAL alert | -5 points each |
| Active WARNING alert | -1 point each |
| Active incident | -10 points each |
| Flapping BGP peer | -3 points each |
| No criticals in last hour | +5 bonus |
| All 34 devices reporting | +5 bonus |

### Client SLA Tracking
Per-client metrics: **uptime %**, **MTBF** (hours), **MTTR** (minutes), **incident count** over configurable periods.

### Alert Heatmap
7×24 grid (day-of-week × hour-of-day) visualizing when alerts occur over configurable periods (7d, 30d, 1y). Green → yellow → red color interpolation highlights temporal patterns for staffing decisions.

### CSV Export
`GET /api/alerts/export?period=today&format=csv` — download alerts as CSV for post-incident reports (up to 50,000 rows). Export buttons on both the Dashboard ("Export CSV") and Statistics page ("Export Report"), with period-aware downloads matching the active time filter.

### BGP Prefix Prediction
Monitors prefix counts against configured maximums. Warns at **80%** and **90%** thresholds with estimated days until exhaustion.

---

## Project Structure

```
bsccl-netwatch/
├── src/
│   ├── main.py                    # FastAPI app + lifespan
│   ├── config.py                  # Settings from .env
│   ├── core/
│   │   ├── parser.py              # 4-format IOS-XR syslog parser
│   │   ├── classifier.py          # 26-rule classification engine
│   │   ├── enricher.py            # Device/interface/AS enrichment
│   │   ├── correlator.py          # Event correlation + incidents
│   │   ├── dedup.py               # Notification deduplication
│   │   └── syslog_receiver.py     # Loki WS/HTTP/UDP ingestion
│   ├── data/
│   │   ├── device_map.py          # 33 devices → IP/name/location
│   │   ├── interface_map.py       # 845 interfaces → description
│   │   ├── as_database.py         # 121 AS numbers → name/type
│   │   ├── classification_rules.py # 26 compiled regex rules
│   │   └── topology.py            # Network dependency tree
│   ├── database/
│   │   ├── models.py              # 7 SQLAlchemy models
│   │   ├── crud.py                # DB operations
│   │   ├── migrations.py          # Auto table creation + WAL
│   │   └── as_cache.py            # External AS lookup cache + BigDataCloud API
│   ├── notifications/
│   │   ├── discord.py             # Discord webhook sender
│   │   ├── telegram.py            # Telegram bot sender
│   │   ├── formatter.py           # Message formatting
│   │   ├── escalation.py          # 15-min escalation pipeline
│   │   └── digest.py              # Daily summary generator
│   ├── statistics/
│   │   ├── engine.py              # Stats queries
│   │   ├── aggregator.py          # Hourly aggregation
│   │   ├── health_score.py        # Network health 0-100
│   │   ├── sla.py                 # Client SLA tracking
│   │   └── predictions.py         # Prefix exhaustion forecast
│   ├── api/
│   │   ├── routes.py              # 21 REST endpoints (incl. heatmap + CSV export)
│   │   └── websocket.py           # Live push to browsers
│   └── web/
│       ├── templates/             # Jinja2 (base, dashboard, stats, settings)
│       └── static/
│           ├── css/neon-theme.css  # Full neon design system
│           └── js/                # WebSocket, charts, topology, sounds, shortcuts
├── tests/                         # 995 tests (unit + integration + e2e)
├── Dockerfile                     # Multi-stage, non-root, pinned, healthcheck
├── docker-compose.yml             # Production deployment (limits, no-new-privileges)
└── .github/workflows/ci.yml       # CI: ruff + black + mypy + pytest + coverage + pip-audit
```

---

## CI Pipeline

GitHub Actions runs on every push and PR across a **6-cell matrix**:

| | Ubuntu | macOS | Windows |
|---|---|---|---|
| **Python 3.11** | ruff, black, mypy, pytest, coverage | ruff, black, mypy, pytest, coverage | pytest, coverage |
| **Python 3.12** | ruff, black, mypy, pytest, coverage | ruff, black, mypy, pytest, coverage | pytest, coverage |

**Security gates**: an automated grep over Python sources (no `shell=True`, `os.system(`, `eval(`, `exec(`, or bare `except:`) plus a **`pip-audit`** dependency-vulnerability scan. All dependencies pinned with both lower and upper bounds to prevent unexpected breakage. Runs cancel obsolete in-progress jobs on the same ref (`concurrency`) and cache pip via `setup-python`.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Language | Python 3.11+ | Core application |
| Web Framework | FastAPI + Uvicorn | Async HTTP + WebSocket |
| Templates | Jinja2 | Server-side rendering |
| Database | SQLite (WAL mode) | Alert/incident storage |
| ORM | SQLAlchemy 2.0 + aiosqlite | Async DB operations |
| HTTP Client | httpx | Discord, Telegram, Loki API |
| WebSocket | websockets | Loki tail connection |
| Charts | Chart.js 4.x | Frontend visualizations |
| Fonts | Orbitron + JetBrains Mono + Inter | Neon UI typography |
| Container | Docker + docker-compose | Production deployment |
| CI | GitHub Actions | Automated testing |
| Linter | ruff | Fast Python linting |
| Formatter | black | Code formatting |
| Type Checker | mypy (strict) | Static type analysis |

---

## BSCCL Network Sites

| Site | Location | Devices | Role |
|------|----------|---------|------|
| **Singapore Equinix** | SG1 Data Center | EQ-RTR-01, EQ-RTR-02 | International IX/PNI (294 BGP peers) |
| **Kuakata CLS** | Cable Landing Station | KKT-Core-01/02/03 | SMW4/SMW6 submarine cable termination |
| **Cox's Bazar CLS** | Cable Landing Station | COX-Core-01/02/03/04, switches | Submarine cable landing |
| **Dhaka Tejgaon** | Primary PoP | DHK-Core-01/02/03, CGS, switches | Domestic backbone hub, 22 ISP clients |
| **Dhaka Colo/Others** | Secondary | Mogbazar, DhakaColo, ICT Tower | Edge/access |

---

<p align="center">
  <sub>Built for the Network Operations Center of Bangladesh Submarine Cable Company Limited</sub><br/>
  <sub>Monitoring Bangladesh's gateway to the global internet</sub>
</p>
