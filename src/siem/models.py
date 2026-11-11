"""Core data models shared by every module.

``Event`` is the normalized shape every input format (Windows Security JSON,
syslog) is converted into. Rules only ever look at ``Event`` fields, which is
what lets a single brute-force rule cover both RDP and SSH failures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(StrEnum):
    """Source-independent meaning of an event."""

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    PRIVILEGE_USE = "privilege_use"
    GROUP_MEMBER_ADDED = "group_member_added"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_LOCKED = "account_locked"
    OTHER = "other"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"


def _ensure_utc(value: datetime) -> datetime:
    """Naive timestamps are assumed to be UTC; aware ones are converted to UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class Event(BaseModel):
    """A normalized security event."""

    timestamp: datetime
    source: str = Field(description="Input format: 'windows' or 'syslog'")
    category: Category
    host: str
    event_id: int | None = Field(default=None, description="Windows EventID, if any")
    user: str | None = None
    src_ip: str | None = None
    target: str | None = Field(default=None, description="Object acted upon, e.g. group name")
    logon_type: int | None = None
    message: str = ""
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _ensure_utc(value)


class Alert(BaseModel):
    """A detection produced by a rule. ``id`` is assigned by the store."""

    id: int | None = None
    rule_id: str
    rule_name: str
    severity: Severity
    title: str
    description: str = ""
    mitre: list[str] = Field(default_factory=list)
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    event_count: int = 1
    first_seen: datetime
    last_seen: datetime
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: AlertStatus = AlertStatus.OPEN

    @field_validator("first_seen", "last_seen", "created_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return _ensure_utc(value)
