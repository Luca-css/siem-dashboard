"""Detection rules (loaded from YAML) and the engine that evaluates them.

Three rule types exist, selected by the ``type`` key:

``match``
    One alert per event that satisfies the conditions (e.g. "user added to
    Administrators").
``threshold``
    N matching events sharing the same ``group_by`` values within a sliding
    time window (e.g. brute force: N failed logons from one IP in 5 minutes).
``off_hours``
    A matching event whose timestamp, in the configured time zone, falls
    outside business hours/days.

Conditions (``match`` / ``exclude``) map an :class:`~siem.models.Event` field to
a value or a list of values (list = any of). String comparison is
case-insensitive and supports shell-style wildcards (``*``, ``?``). An event
fires a rule when *all* ``match`` conditions hold and *no* ``exclude``
condition holds. A field that is missing on the event never matches.

**All time logic uses event timestamps, never the wall clock**, so replaying
old logs produces the same alerts as processing them live.
"""

from __future__ import annotations

import bisect
import fnmatch
import re
from collections.abc import Iterable
from datetime import datetime, time, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

from siem.models import Alert, Event, Severity

Scalar = str | int | bool
ConditionValue = Scalar | list[Scalar]
Conditions = dict[str, ConditionValue]

_EVENT_FIELDS = frozenset(Event.model_fields) - {"raw"}
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

Weekday = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _default_days() -> list[Weekday]:
    return ["mon", "tue", "wed", "thu", "fri"]


def parse_duration(value: Any) -> Any:
    """Accept '30s', '5m', '1h', '1d' or a plain number of seconds."""
    if isinstance(value, str) and (m := _DURATION.match(value.strip().lower())):
        return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    if isinstance(value, int) and not isinstance(value, bool):
        return timedelta(seconds=value)
    return value  # let pydantic try (e.g. ISO-8601 'PT5M') or fail


Duration = Annotated[timedelta, BeforeValidator(parse_duration)]


def _value_matches(actual: Any, expected: ConditionValue) -> bool:
    if actual is None:
        return False
    if isinstance(expected, list):
        return any(_value_matches(actual, item) for item in expected)
    if isinstance(actual, str) or isinstance(expected, str):
        a, e = str(actual).casefold(), str(expected).casefold()
        return fnmatch.fnmatchcase(a, e) if any(c in e for c in "*?[") else a == e
    return bool(actual == expected)


def conditions_match(event: Event, conditions: Conditions) -> bool:
    """True when every condition holds for the event."""
    return all(_value_matches(getattr(event, f), v) for f, v in conditions.items())


def _any_condition(event: Event, conditions: Conditions) -> bool:
    return any(_value_matches(getattr(event, f), v) for f, v in conditions.items())


class _SafeDict(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def render(template: str, event: Event, **extra: Any) -> str:
    """Fill ``{field}`` placeholders from the event; unknown placeholders are kept."""
    values = {k: ("-" if v is None else v) for k, v in event.model_dump().items()}
    values.update(extra)
    return template.format_map(_SafeDict(values))


# ── Rule definitions ───────────────────────────────────────────────────────────


class BaseRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9_.-]+$")
    name: str
    description: str = ""
    severity: Severity
    enabled: bool = True
    mitre: list[str] = Field(default_factory=list)
    title: str
    match: Conditions = Field(default_factory=dict)
    exclude: Conditions = Field(default_factory=dict)

    @field_validator("match", "exclude")
    @classmethod
    def _known_fields(cls, value: Conditions) -> Conditions:
        unknown = set(value) - _EVENT_FIELDS
        if unknown:
            raise ValueError(f"unknown event field(s): {sorted(unknown)}")
        return value

    def applies_to(self, event: Event) -> bool:
        return conditions_match(event, self.match) and not _any_condition(event, self.exclude)

    def make_alert(self, event: Event, title: str, **fields: Any) -> Alert:
        values: dict[str, Any] = {
            "host": event.host,
            "user": event.user,
            "src_ip": event.src_ip,
            "first_seen": event.timestamp,
            "last_seen": event.timestamp,
            "description": event.message,
        }
        values.update(fields)
        return Alert(
            rule_id=self.id,
            rule_name=self.name,
            severity=self.severity,
            mitre=self.mitre,
            title=title,
            **values,
        )


class MatchRule(BaseRule):
    type: Literal["match"]


class ThresholdRule(BaseRule):
    type: Literal["threshold"]
    group_by: list[str] = Field(min_length=1)
    threshold: int = Field(ge=2)
    window: Duration

    @field_validator("group_by")
    @classmethod
    def _known_group_fields(cls, value: list[str]) -> list[str]:
        unknown = set(value) - _EVENT_FIELDS
        if unknown:
            raise ValueError(f"unknown event field(s): {sorted(unknown)}")
        return value

    @field_validator("window")
    @classmethod
    def _positive(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0):
            raise ValueError("window must be positive")
        return value


class OffHoursRule(BaseRule):
    type: Literal["off_hours"]
    timezone: str = "UTC"
    start: time = time(8, 0)
    end: time = time(18, 0)
    days: list[Weekday] = Field(default_factory=_default_days)

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError(f"unknown time zone {value!r}") from exc
        return value

    @model_validator(mode="after")
    def _start_before_end(self) -> OffHoursRule:
        if self.start >= self.end:
            raise ValueError("start must be before end (overnight shifts are not supported)")
        return self

    def is_off_hours(self, timestamp: datetime) -> bool:
        local = timestamp.astimezone(ZoneInfo(self.timezone))
        if _WEEKDAYS[local.weekday()] not in self.days:
            return True
        return not (self.start <= local.time() < self.end)


Rule = Annotated[MatchRule | ThresholdRule | OffHoursRule, Field(discriminator="type")]
_RULE_ADAPTER: TypeAdapter[MatchRule | ThresholdRule | OffHoursRule] = TypeAdapter(Rule)


def parse_rule(data: dict[str, Any]) -> MatchRule | ThresholdRule | OffHoursRule:
    return _RULE_ADAPTER.validate_python(data)


def load_rules(directory: str | Path) -> list[MatchRule | ThresholdRule | OffHoursRule]:
    """Load every ``*.yml`` / ``*.yaml`` file in ``directory``.

    A file may contain one rule (a mapping) or several (a list). Invalid rules
    raise ``ValueError`` naming the file, so a typo fails at startup instead of
    silently disabling a detection.
    """
    path = Path(directory)
    if not path.is_dir():
        raise ValueError(f"rules directory not found: {path}")

    rules: list[MatchRule | ThresholdRule | OffHoursRule] = []
    seen: set[str] = set()
    files = sorted([*path.glob("*.yml"), *path.glob("*.yaml")])
    for file in files:
        documents = yaml.safe_load(file.read_text(encoding="utf-8")) or []
        if isinstance(documents, dict):
            documents = [documents]
        for doc in documents:
            try:
                rule = parse_rule(doc)
            except ValidationError as exc:
                raise ValueError(f"{file.name}: invalid rule: {exc}") from exc
            if rule.id in seen:
                raise ValueError(f"{file.name}: duplicate rule id {rule.id!r}")
            seen.add(rule.id)
            rules.append(rule)
    return rules


# ── Engine ─────────────────────────────────────────────────────────────────────


class RuleEngine:
    """Evaluates events against rules, keeping sliding-window state in memory.

    Not thread-safe: callers must serialize calls to :meth:`evaluate`
    (see :class:`siem.pipeline.Pipeline`).
    """

    PRUNE_EVERY = 1000  # events between sweeps of idle threshold buckets

    def __init__(self, rules: Iterable[MatchRule | ThresholdRule | OffHoursRule]) -> None:
        self.rules = [r for r in rules if r.enabled]
        # (rule id, group values) -> sorted timestamps of matching events
        self._buckets: dict[tuple[str, tuple[Any, ...]], list[datetime]] = {}
        self._latest: datetime | None = None
        self._since_prune = 0

    def evaluate(self, event: Event) -> list[Alert]:
        if self._latest is None or event.timestamp > self._latest:
            self._latest = event.timestamp

        alerts: list[Alert] = []
        for rule in self.rules:
            if not rule.applies_to(event):
                continue
            alert: Alert | None
            match rule:
                case ThresholdRule():
                    alert = self._threshold(rule, event)
                case OffHoursRule():
                    alert = (
                        rule.make_alert(event, render(rule.title, event))
                        if rule.is_off_hours(event.timestamp)
                        else None
                    )
                case MatchRule():
                    alert = rule.make_alert(event, render(rule.title, event))
            if alert is not None:
                alerts.append(alert)

        self._since_prune += 1
        if self._since_prune >= self.PRUNE_EVERY:
            self.prune()
        return alerts

    def _threshold(self, rule: ThresholdRule, event: Event) -> Alert | None:
        group = tuple(getattr(event, field) for field in rule.group_by)
        if any(value is None for value in group):
            return None  # cannot group an event that lacks the key (e.g. no source IP)

        key = (rule.id, group)
        bucket = self._buckets.setdefault(key, [])
        bisect.insort(bucket, event.timestamp)  # tolerate slightly out-of-order events

        # Drop timestamps that can no longer share a window with the newest one.
        cutoff = bucket[-1] - rule.window
        del bucket[: bisect.bisect_left(bucket, cutoff)]

        # Two pointers: find any run of `threshold` events spanning <= window.
        start = 0
        for end in range(len(bucket)):
            while bucket[end] - bucket[start] > rule.window:
                start += 1
            if end - start + 1 >= rule.threshold:
                hits = bucket[start : end + 1]
                # Consume the events so the same burst does not alert again;
                # a new alert needs `threshold` *new* events.
                del bucket[: end + 1]
                if not bucket:
                    del self._buckets[key]
                group_fields = dict(zip(rule.group_by, group, strict=True))
                fields: dict[str, Any] = {
                    "user": group_fields.get("user"),
                    "src_ip": group_fields.get("src_ip"),
                    "event_count": len(hits),
                    "first_seen": hits[0],
                    "last_seen": hits[-1],
                    "description": (
                        f"{len(hits)} matching events within "
                        f"{int((hits[-1] - hits[0]).total_seconds())}s "
                        f"(threshold {rule.threshold} in {int(rule.window.total_seconds())}s)"
                    ),
                }
                if "host" in group_fields:
                    fields["host"] = group_fields["host"]
                title = render(rule.title, event, count=len(hits), **group_fields)
                return rule.make_alert(event, title, **fields)
        return None

    def prune(self) -> None:
        """Forget buckets whose newest event is older than their rule's window."""
        self._since_prune = 0
        if self._latest is None:
            return
        windows = {r.id: r.window for r in self.rules if isinstance(r, ThresholdRule)}
        stale = [
            key
            for key, bucket in self._buckets.items()
            if not bucket or bucket[-1] < self._latest - windows[key[0]]
        ]
        for key in stale:
            del self._buckets[key]

    @property
    def tracked_buckets(self) -> int:
        return len(self._buckets)
