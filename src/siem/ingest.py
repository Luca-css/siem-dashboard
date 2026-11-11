"""Parsers that turn raw input into normalized :class:`~siem.models.Event` objects.

Two input formats are supported:

* **Windows Security events as JSON**, in the flat shape produced by
  ``Get-WinEvent`` + ``ConvertTo-Json`` (see ``scripts/simulate.py``)::

      {"EventID": 4625, "TimeCreated": "2026-11-11T13:00:00Z", "Computer": "SRV-AD01",
       "EventData": {"TargetUserName": "admin", "IpAddress": "203.0.113.7", "LogonType": "10"}}

* **syslog lines** (RFC 3164 or ISO-8601 timestamps), with specific parsing for
  ``sshd`` logins and ``sudo``. Anything else is kept as category ``other``.

Every parser raises ``ValueError`` on input it cannot understand, so the API can
report exactly which records were rejected.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from siem.models import Category, Event

# ── Windows ────────────────────────────────────────────────────────────────────

WINDOWS_CATEGORIES: dict[int, Category] = {
    4624: Category.AUTH_SUCCESS,
    4625: Category.AUTH_FAILURE,
    4672: Category.PRIVILEGE_USE,
    4720: Category.ACCOUNT_CREATED,
    4732: Category.GROUP_MEMBER_ADDED,
    4740: Category.ACCOUNT_LOCKED,
}

# Events where the interesting account is the *subject* (who performed the
# action) rather than the *target* (who the action was performed on).
_SUBJECT_IS_USER = {4672, 4720, 4732}

_DOTNET_DATE = re.compile(r"^/Date\((-?\d+)\)/$")
_EMPTY = {"", "-"}


class WindowsEventIn(BaseModel):
    """Input schema for a Windows Security event (field names as Windows emits them)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    event_id: int = Field(alias="EventID")
    time_created: datetime = Field(alias="TimeCreated")
    computer: str = Field(alias="Computer", min_length=1)
    event_data: dict[str, Any] = Field(default_factory=dict, alias="EventData")

    @field_validator("time_created", mode="before")
    @classmethod
    def _parse_dotnet_date(cls, value: Any) -> Any:
        # Windows PowerShell 5.1 serializes DateTime as "/Date(1700000000000)/".
        if isinstance(value, str) and (match := _DOTNET_DATE.match(value)):
            return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=UTC)
        return value


def _clean(value: Any) -> str | None:
    """Windows uses '-' and '' for 'no value'; normalize those to None."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in _EMPTY else text


def normalize_ip(value: Any) -> str | None:
    """Return a canonical IP string, unwrapping IPv4-mapped IPv6 (::ffff:1.2.3.4)."""
    text = _clean(value)
    if text is None:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ip)


def _to_int(value: Any) -> int | None:
    text = _clean(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def parse_windows_event(data: dict[str, Any]) -> Event:
    """Normalize one Windows Security event. Raises ``ValueError`` if invalid."""
    parsed = WindowsEventIn.model_validate(data)
    ed = parsed.event_data
    eid = parsed.event_id
    category = WINDOWS_CATEGORIES.get(eid, Category.OTHER)

    if eid in _SUBJECT_IS_USER:
        user = _clean(ed.get("SubjectUserName"))
        target = _clean(ed.get("TargetUserName"))
    else:
        user = _clean(ed.get("TargetUserName")) or _clean(ed.get("SubjectUserName"))
        target = None

    src_ip = normalize_ip(ed.get("IpAddress"))
    logon_type = _to_int(ed.get("LogonType"))

    match eid:
        case 4624:
            message = f"Logon success for {user} (type {logon_type}) from {src_ip or 'local'}"
        case 4625:
            message = f"Logon failure for {user} from {src_ip or 'local'}"
        case 4672:
            message = f"Special privileges assigned to {user}"
        case 4720:
            message = f"Account {target} created by {user}"
        case 4732:
            member = _clean(ed.get("MemberName")) or _clean(ed.get("MemberSid"))
            message = f"{member} added to local group {target} by {user}"
        case 4740:
            message = f"Account {user} locked out"
        case _:
            message = f"Windows event {eid}"

    return Event(
        timestamp=parsed.time_created,
        source="windows",
        category=category,
        host=parsed.computer,
        event_id=eid,
        user=user,
        src_ip=src_ip,
        target=target,
        logon_type=logon_type,
        message=message,
        raw=data,
    )


# ── syslog ─────────────────────────────────────────────────────────────────────

_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?"  # optional PRI, e.g. <38>
    r"(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}))"
    r" (?P<host>\S+) (?P<app>[^\s:\[]+)(?:\[\d+\])?: (?P<msg>.*)$"
)
_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_SSH_ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
_SUDO_RUNAS = re.compile(r"USER=(?P<runas>[^\s;]+)")


def _parse_bsd_timestamp(text: str, now: datetime) -> datetime:
    """RFC 3164 timestamps have no year or zone: assume UTC and the current year.

    If that puts the event more than a day in the future, it must be from last
    year (e.g. a 'Dec 31' line processed on Jan 1).
    """
    parsed = datetime.strptime(f"{now.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    parsed = parsed.replace(tzinfo=UTC)
    if parsed - now > timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)
    return parsed


def parse_syslog_line(line: str, now: datetime | None = None) -> Event:
    """Normalize one syslog line. Raises ``ValueError`` if the header is malformed."""
    match = _SYSLOG.match(line.strip())
    if match is None:
        raise ValueError("not a recognizable syslog line")

    now = now or datetime.now(UTC)
    if match["iso"]:
        timestamp = datetime.fromisoformat(match["iso"])
    else:
        timestamp = _parse_bsd_timestamp(match["bsd"], now)

    app, msg = match["app"], match["msg"]
    category = Category.OTHER
    user: str | None = None
    src_ip: str | None = None
    target: str | None = None

    if app == "sshd" and (m := _SSH_FAILED.search(msg)):
        category, user, src_ip = Category.AUTH_FAILURE, m["user"], normalize_ip(m["ip"])
    elif app == "sshd" and (m := _SSH_ACCEPTED.search(msg)):
        category, user, src_ip = Category.AUTH_SUCCESS, m["user"], normalize_ip(m["ip"])
    elif app == "sudo" and (m := _SUDO.match(msg)):
        user = m["user"]
        rest = m["rest"]
        if "NOT in sudoers" in rest or "incorrect password" in rest:
            category = Category.AUTH_FAILURE
        elif "COMMAND=" in rest:
            category = Category.PRIVILEGE_USE
            if runas := _SUDO_RUNAS.search(rest):
                target = runas["runas"]

    return Event(
        timestamp=timestamp,
        source="syslog",
        category=category,
        host=match["host"],
        user=user,
        src_ip=src_ip,
        target=target,
        message=f"{app}: {msg}",
        raw={"line": line},
    )
