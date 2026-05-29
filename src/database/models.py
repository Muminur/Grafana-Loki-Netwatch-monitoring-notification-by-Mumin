"""SQLAlchemy 2.0 ORM models for BSCCL NetWatch.

All models use the declarative style with `Mapped` / `mapped_column`.
The ``Base`` class is shared by migrations and CRUD modules.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from src.database.timeutils import now_bdt_naive


class Base(DeclarativeBase):
    """Shared declarative base for all models."""


class AlertLog(Base):
    """One parsed and classified syslog entry."""

    __tablename__ = "alert_log"
    __table_args__ = (
        Index("ix_alertlog_classification_ts", "classification", "timestamp"),
        Index("ix_alertlog_device_ts", "device_name", "timestamp"),
        Index("ix_alertlog_mnemonic", "mnemonic"),
        # Incident detail lookups: WHERE incident_id = ?
        Index("ix_alertlog_incident_id", "incident_id"),
        # BGP-UP silent-fault resolution query:
        #   WHERE device_name = ? AND mnemonic IN (...)
        #   AND interface_name IN (...) AND resolved_at IS NULL
        #   AND timestamp >= ?
        # Prefix (device_name, mnemonic, resolved_at) covers the equality +
        # IS NULL filter; timestamp range is applied after the prefix scan.
        Index(
            "ix_alertlog_device_mnemonic_resolved",
            "device_name",
            "mnemonic",
            "resolved_at",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime]
    source_ip: Mapped[str] = mapped_column(String(45))
    device_name: Mapped[str] = mapped_column(String(128))
    hostname: Mapped[str] = mapped_column(String(128), default="")
    rp_location: Mapped[str] = mapped_column(String(64), default="")
    facility: Mapped[str] = mapped_column(String(64))
    subfacility: Mapped[str] = mapped_column(String(64), default="")
    severity_level: Mapped[int]
    mnemonic: Mapped[str] = mapped_column(String(64))
    message: Mapped[str] = mapped_column(Text)
    raw: Mapped[str] = mapped_column(Text)
    # CRITICAL / WARNING / INFO / NOISE / USER_LOGIN
    classification: Mapped[str] = mapped_column(String(32), default="INFO")
    interface_name: Mapped[str] = mapped_column(String(128), default="")
    interface_description: Mapped[str] = mapped_column(String(256), default="")
    client_name: Mapped[str] = mapped_column(String(128), default="")
    bgp_neighbor: Mapped[str] = mapped_column(String(64), default="")
    as_number: Mapped[int] = mapped_column(default=0)
    as_name: Mapped[str] = mapped_column(String(128), default="")
    incident_id: Mapped[str | None] = mapped_column(String(32), default=None)
    notification_sent: Mapped[bool] = mapped_column(default=False)
    discord_sent: Mapped[bool] = mapped_column(default=False)
    telegram_sent: Mapped[bool] = mapped_column(default=False)
    discord_error: Mapped[str] = mapped_column(String(256), default="")
    telegram_error: Mapped[str] = mapped_column(String(256), default="")
    # User-facing times: when set by the app they hold naive Bangladesh-local
    # (UTC+6) face values via now_bdt_naive(), matching the dashboard clock.
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    resolution_reason: Mapped[str] = mapped_column(String(64), default="")
    acknowledged_at: Mapped[datetime | None] = mapped_column(default=None)
    # Intentionally UTC: machine/audit timestamp, not a user-facing BDT field.
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))


class Incident(Base):
    """A correlated group of related alerts sharing a common root cause."""

    __tablename__ = "incident"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # INC-YYYYMMDD-NNN
    title: Mapped[str] = mapped_column(String(256))
    root_cause: Mapped[str] = mapped_column(Text, default="")
    affected_devices: Mapped[str] = mapped_column(Text, default="")  # JSON list
    affected_clients: Mapped[str] = mapped_column(Text, default="")  # JSON list
    alert_count: Mapped[int] = mapped_column(default=0)
    symptom_count: Mapped[int] = mapped_column(default=0)
    # active / acknowledged / resolved
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime]
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    acknowledged_by: Mapped[str | None] = mapped_column(String(64), default=None)


class BGPPeerHistory(Base):
    """BGP session state change history per device / neighbor pair."""

    __tablename__ = "bgp_peer_history"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_name: Mapped[str] = mapped_column(String(128))
    neighbor: Mapped[str] = mapped_column(String(64))
    as_number: Mapped[int]
    state: Mapped[str] = mapped_column(String(32))  # Up / Down / FLAPPING
    timestamp: Mapped[datetime]
    vrf: Mapped[str] = mapped_column(String(64), default="")


class HourlyStats(Base):
    """Pre-aggregated per-hour alert counts (one row per device per hour)."""

    __tablename__ = "hourly_stats"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    hour: Mapped[datetime]
    critical_count: Mapped[int] = mapped_column(default=0)
    warning_count: Mapped[int] = mapped_column(default=0)
    info_count: Mapped[int] = mapped_column(default=0)
    noise_count: Mapped[int] = mapped_column(default=0)
    login_count: Mapped[int] = mapped_column(default=0)
    device_name: Mapped[str] = mapped_column(String(128), default="")


class ASCache(Base):
    """Cache of external AS number lookups (PeeringDB / bgpview / RIPE)."""

    __tablename__ = "as_cache"

    asn: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    as_type: Mapped[str] = mapped_column(String(64), default="")
    # peeringdb / bgpview / ripe
    source: Mapped[str] = mapped_column(String(32), default="")
    cached_at: Mapped[datetime]


class MaintenanceWindow(Base):
    """Scheduled maintenance period — suppress notifications during window."""

    __tablename__ = "maintenance_window"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_name: Mapped[str] = mapped_column(String(128))
    start_time: Mapped[datetime]
    end_time: Mapped[datetime]
    reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    # Intentionally UTC: machine/audit timestamp, not a user-facing BDT field.
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))


class AppSetting(Base):
    """Generic key/value table for persisted runtime settings.

    Each row stores one application-level setting as a string value.
    The ``key`` column is the primary key (e.g. ``"hardware_defects_as_noise"``).
    Boolean settings are stored as ``"true"`` or ``"false"``.
    """

    __tablename__ = "app_setting"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(String(1024), default="")
    # Intentionally UTC: machine/audit timestamp, not a user-facing BDT field.
    updated_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))


class UserLogin(Base):
    """SSH login / logout events parsed from syslog."""

    __tablename__ = "user_login"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime]
    device_name: Mapped[str] = mapped_column(String(128))
    username: Mapped[str] = mapped_column(String(64))
    source_ip: Mapped[str] = mapped_column(String(45))
    vty: Mapped[str] = mapped_column(String(32), default="")
    action: Mapped[str] = mapped_column(String(16))  # login / logout
    cipher: Mapped[str] = mapped_column(String(128), default="")


class ShiftHandoff(Base):
    """Shift handoff notes left by outgoing operators."""

    __tablename__ = "shift_handoff"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    shift_name: Mapped[str] = mapped_column(String(16))  # morning/evening/night
    shift_date: Mapped[str] = mapped_column(String(10))  # YYYY-MM-DD
    operator_name: Mapped[str] = mapped_column(String(64))
    notes: Mapped[str] = mapped_column(Text, default="")
    open_incidents: Mapped[int] = mapped_column(default=0)
    critical_count: Mapped[int] = mapped_column(default=0)
    warning_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=now_bdt_naive)


class IncidentAck(Base):
    """Acknowledgement audit trail for incidents."""

    __tablename__ = "incident_ack"
    __table_args__ = (Index("ix_incident_ack_incident_id", "incident_id"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32))
    operator_name: Mapped[str] = mapped_column(String(64))
    comment: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=now_bdt_naive)
