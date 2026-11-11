"""SQLite persistence for events and alerts (stdlib ``sqlite3``, no ORM).

A single connection guarded by a lock is plenty for a single-process mini-SIEM
and keeps the code easy to follow. Timestamps are stored as fixed-width UTC
ISO-8601 strings, so lexical order equals chronological order and range
filters work with plain string comparison.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from siem.models import Alert, AlertStatus, Event, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    source      TEXT NOT NULL,
    category    TEXT NOT NULL,
    host        TEXT NOT NULL,
    event_id    INTEGER,
    user        TEXT,
    src_ip      TEXT,
    target      TEXT,
    logon_type  INTEGER,
    message     TEXT NOT NULL,
    raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events (timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    mitre        TEXT NOT NULL,
    host         TEXT,
    user         TEXT,
    src_ip       TEXT,
    event_count  INTEGER NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_alerts_last_seen ON alerts (last_seen);
CREATE INDEX IF NOT EXISTS ix_alerts_rule ON alerts (rule_id);
"""


def ts(value: datetime) -> str:
    """Fixed-width UTC timestamp string (always includes microseconds)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class AlertFilter:
    severity: Sequence[Severity] = ()
    rule_id: str | None = None
    host: str | None = None
    src_ip: str | None = None
    status: AlertStatus | None = None
    since: datetime | None = None  # compared with the alert's last_seen (event time)
    until: datetime | None = None


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ping(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1")
        except sqlite3.Error:
            return False
        return True

    # ── events ─────────────────────────────────────────────────────────────────

    def add_event(self, event: Event) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO events (timestamp, source, category, host, event_id, user, src_ip,"
                " target, logon_type, message, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ts(event.timestamp),
                    event.source,
                    event.category.value,
                    event.host,
                    event.event_id,
                    event.user,
                    event.src_ip,
                    event.target,
                    event.logon_type,
                    event.message,
                    json.dumps(event.raw, default=str),
                ),
            )
            return int(cur.lastrowid or 0)

    def recent_events(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Most recently *ingested* events first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, timestamp, source, category, host, event_id, user, src_ip, target,"
                " logon_type, message FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    # ── alerts ─────────────────────────────────────────────────────────────────

    def add_alert(self, alert: Alert) -> Alert:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO alerts (rule_id, rule_name, severity, title, description, mitre, host,"
                " user, src_ip, event_count, first_seen, last_seen, created_at, status)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    alert.rule_id,
                    alert.rule_name,
                    alert.severity.value,
                    alert.title,
                    alert.description,
                    json.dumps(alert.mitre),
                    alert.host,
                    alert.user,
                    alert.src_ip,
                    alert.event_count,
                    ts(alert.first_seen),
                    ts(alert.last_seen),
                    ts(alert.created_at),
                    alert.status.value,
                ),
            )
        return alert.model_copy(update={"id": cur.lastrowid})

    def get_alert(self, alert_id: int) -> Alert | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _row_to_alert(row) if row else None

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> Alert | None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?", (status.value, alert_id)
            )
        return self.get_alert(alert_id)

    def list_alerts(
        self, flt: AlertFilter, limit: int = 50, offset: int = 0
    ) -> tuple[list[Alert], int]:
        """Return one page of alerts (newest first) and the total matching count."""
        clauses: list[str] = []
        params: list[Any] = []
        if flt.severity:
            clauses.append(f"severity IN ({','.join('?' * len(flt.severity))})")
            params.extend(s.value for s in flt.severity)
        for column in ("rule_id", "host", "src_ip"):
            value = getattr(flt, column)
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        if flt.status is not None:
            clauses.append("status = ?")
            params.append(flt.status.value)
        if flt.since is not None:
            clauses.append("last_seen >= ?")
            params.append(ts(flt.since))
        if flt.until is not None:
            clauses.append("last_seen <= ?")
            params.append(ts(flt.until))
        # Only fixed column names are interpolated; every value is a bound parameter.
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) FROM alerts{where}",  # noqa: S608
                params,
            ).fetchone()[0]
            rows = self._conn.execute(
                f"SELECT * FROM alerts{where} ORDER BY id DESC LIMIT ? OFFSET ?",  # noqa: S608
                [*params, limit, offset],
            ).fetchall()
        return [_row_to_alert(r) for r in rows], int(total)

    # ── dashboard stats ────────────────────────────────────────────────────────

    def stats(self, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        since = ts(now - timedelta(hours=24))
        with self._lock:
            total_events = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_category = dict(
                self._conn.execute(
                    "SELECT category, COUNT(*) FROM events GROUP BY category"
                ).fetchall()
            )
            hosts = self._conn.execute("SELECT COUNT(DISTINCT host) FROM events").fetchone()[0]
            open_by_severity = dict(
                self._conn.execute(
                    "SELECT severity, COUNT(*) FROM alerts WHERE status = 'open' GROUP BY severity"
                ).fetchall()
            )
            # Bucket by UTC hour ("YYYY-MM-DDTHH"); the dashboard converts to local time.
            per_hour = self._conn.execute(
                "SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) FROM events"
                " WHERE timestamp >= ? GROUP BY hour ORDER BY hour",
                (since,),
            ).fetchall()
        return {
            "total_events": total_events,
            "events_by_category": by_category,
            "hosts": hosts,
            "open_alerts": sum(open_by_severity.values()),
            "open_alerts_by_severity": open_by_severity,
            "events_per_hour": [{"hour": f"{h}:00:00Z", "count": c} for h, c in per_hour],
        }


def _row_to_alert(row: sqlite3.Row) -> Alert:
    data = dict(row)
    data["mitre"] = json.loads(data["mitre"])
    return Alert.model_validate(data)
