from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from conftest import REPO_RULES, T0, make_event

from siem.models import Category, Severity
from siem.rules import (
    MatchRule,
    OffHoursRule,
    RuleEngine,
    ThresholdRule,
    load_rules,
    parse_duration,
    parse_rule,
)

US = timedelta(microseconds=1)


def brute_force_rule(threshold: int = 5, window: str = "60s") -> ThresholdRule:
    rule = parse_rule(
        {
            "id": "bf",
            "name": "Brute force",
            "type": "threshold",
            "severity": "critical",
            "match": {"category": "auth_failure"},
            "group_by": ["src_ip"],
            "threshold": threshold,
            "window": window,
            "title": "{count} failures from {src_ip}",
        }
    )
    assert isinstance(rule, ThresholdRule)
    return rule


def feed(engine: RuleEngine, offsets: list[float], **fields: object) -> list[list[object]]:
    """Feed one auth failure per offset (seconds after T0); return alerts per event."""
    return [
        engine.evaluate(make_event(T0 + timedelta(seconds=s), **fields))  # type: ignore[arg-type]
        for s in offsets
    ]


# ── Sliding window (threshold) ─────────────────────────────────────────────────


class TestThresholdWindow:
    def test_fires_on_nth_event_inside_window(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=5)])
        results = feed(engine, [0, 10, 20, 30, 40])
        assert [len(r) for r in results] == [0, 0, 0, 0, 1]
        alert = results[-1][0]
        assert alert.event_count == 5
        assert alert.src_ip == "203.0.113.7"
        assert alert.first_seen == T0
        assert alert.last_seen == T0 + timedelta(seconds=40)
        assert alert.title == "5 failures from 203.0.113.7"
        assert alert.severity is Severity.CRITICAL

    def test_span_exactly_equal_to_window_fires(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3, window="60s")])
        results = feed(engine, [0, 30, 60])
        assert len(results[-1]) == 1

    def test_span_just_over_window_does_not_fire(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3, window="60s")])
        e = [T0, T0 + timedelta(seconds=30), T0 + timedelta(seconds=60) + US]
        alerts = [engine.evaluate(make_event(t)) for t in e]
        assert alerts == [[], [], []]

    def test_window_slides_old_events_expire(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3, window="60s")])
        # 0 and 10 expire by the time 100/110 arrive; 100,110,120 form a new burst.
        results = feed(engine, [0, 10, 100, 110, 120])
        assert [len(r) for r in results] == [0, 0, 0, 0, 1]
        assert results[-1][0].first_seen == T0 + timedelta(seconds=100)  # type: ignore[attr-defined]

    def test_uses_event_time_not_arrival_rate(self) -> None:
        # Five failures delivered "instantly" but spread over 10 minutes of event time.
        engine = RuleEngine([brute_force_rule(threshold=5, window="5m")])
        results = feed(engine, [0, 150, 300, 450, 600])
        assert all(r == [] for r in results)

    def test_burst_is_consumed_and_needs_new_events_to_refire(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3)])
        results = feed(engine, [0, 1, 2, 3, 4, 5])
        assert [len(r) for r in results] == [0, 0, 1, 0, 0, 1]

    def test_groups_are_independent(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3)])
        for s in (0, 1):
            assert (
                engine.evaluate(make_event(T0 + timedelta(seconds=s), src_ip="198.51.100.1")) == []
            )
            assert (
                engine.evaluate(make_event(T0 + timedelta(seconds=s), src_ip="198.51.100.2")) == []
            )
        fired = engine.evaluate(make_event(T0 + timedelta(seconds=2), src_ip="198.51.100.2"))
        assert len(fired) == 1
        assert fired[0].src_ip == "198.51.100.2"

    def test_out_of_order_event_inside_window_is_counted(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=3, window="60s")])
        assert feed(engine, [50, 59]) == [[], []]
        late = engine.evaluate(make_event(T0 + timedelta(seconds=10)))
        assert len(late) == 1
        assert late[0].first_seen == T0 + timedelta(seconds=10)
        assert late[0].last_seen == T0 + timedelta(seconds=59)

    def test_event_without_group_key_is_ignored(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=2)])
        results = feed(engine, [0, 1, 2], src_ip=None)
        assert all(r == [] for r in results)
        assert engine.tracked_buckets == 0

    def test_non_matching_category_is_ignored(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=2)])
        results = feed(engine, [0, 1, 2], category=Category.AUTH_SUCCESS)
        assert all(r == [] for r in results)

    def test_prune_drops_idle_buckets(self) -> None:
        engine = RuleEngine([brute_force_rule(threshold=5, window="60s")])
        engine.evaluate(make_event(T0, src_ip="198.51.100.1"))
        engine.evaluate(make_event(T0 + timedelta(minutes=10), src_ip="198.51.100.2"))
        assert engine.tracked_buckets == 2
        engine.prune()
        assert engine.tracked_buckets == 1  # only the recent IP is still tracked


# ── Off-hours ──────────────────────────────────────────────────────────────────


def off_hours_rule() -> OffHoursRule:
    rule = parse_rule(
        {
            "id": "oh",
            "name": "Off hours",
            "type": "off_hours",
            "severity": "medium",
            "match": {"category": "auth_success"},
            "timezone": "America/Sao_Paulo",  # UTC-3, no DST since 2019
            "start": "08:00",
            "end": "19:00",
            "title": "Off-hours logon by {user}",
        }
    )
    assert isinstance(rule, OffHoursRule)
    return rule


class TestOffHours:
    @pytest.mark.parametrize(
        ("utc_hour", "utc_minute", "expected"),
        [
            (10, 59, True),  # 07:59 local
            (11, 0, False),  # 08:00 local - start is inclusive
            (15, 0, False),  # 12:00 local
            (21, 59, False),  # 18:59 local
            (22, 0, True),  # 19:00 local - end is exclusive
            (5, 0, True),  # 02:00 local
        ],
    )
    def test_business_hour_edges_in_rule_timezone(
        self, utc_hour: int, utc_minute: int, expected: bool
    ) -> None:
        when = T0.replace(hour=utc_hour, minute=utc_minute)  # Wednesday
        assert off_hours_rule().is_off_hours(when) is expected

    def test_weekend_is_always_off_hours(self) -> None:
        saturday_noon_local = T0 + timedelta(days=3)  # Sat 2026-11-14 12:00 local
        assert off_hours_rule().is_off_hours(saturday_noon_local)

    def test_engine_alerts_only_off_hours(self) -> None:
        engine = RuleEngine([off_hours_rule()])
        day = make_event(T0, category=Category.AUTH_SUCCESS, user="lucas")
        night = make_event(T0.replace(hour=5), category=Category.AUTH_SUCCESS, user="lucas")
        assert engine.evaluate(day) == []
        [alert] = engine.evaluate(night)
        assert alert.title == "Off-hours logon by lucas"

    def test_start_must_precede_end(self) -> None:
        with pytest.raises(ValueError, match="start must be before end"):
            parse_rule(
                {
                    "id": "x",
                    "name": "x",
                    "type": "off_hours",
                    "severity": "low",
                    "title": "x",
                    "start": "22:00",
                    "end": "06:00",
                }
            )

    def test_unknown_timezone_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown time zone"):
            parse_rule(
                {
                    "id": "x",
                    "name": "x",
                    "type": "off_hours",
                    "severity": "low",
                    "title": "x",
                    "timezone": "Mars/Olympus",
                }
            )


# ── Match conditions ───────────────────────────────────────────────────────────


def match_rule(**overrides: object) -> MatchRule:
    data: dict[str, object] = {
        "id": "m",
        "name": "m",
        "type": "match",
        "severity": "high",
        "title": "{user} on {host} ({missing})",
        "match": {"event_id": 4672},
        "exclude": {"user": ["Administrator", "*$", "DWM-*"]},
    }
    data.update(overrides)
    rule = parse_rule(data)
    assert isinstance(rule, MatchRule)
    return rule


class TestMatchConditions:
    @pytest.mark.parametrize(
        ("user", "fires"),
        [
            ("jsilva", True),
            ("administrator", False),  # case-insensitive
            ("SRV-AD01$", False),  # wildcard: computer account
            ("DWM-3", False),
            (None, True),  # missing field never matches an exclude
        ],
    )
    def test_exclude_list_wildcards_and_case(self, user: str | None, fires: bool) -> None:
        engine = RuleEngine([match_rule()])
        event = make_event(category=Category.PRIVILEGE_USE, event_id=4672, user=user)
        assert bool(engine.evaluate(event)) is fires

    def test_all_match_conditions_must_hold(self) -> None:
        engine = RuleEngine([match_rule(match={"event_id": 4732, "target": "Administrators"})])
        hit = make_event(
            category=Category.GROUP_MEMBER_ADDED, event_id=4732, target="administrators"
        )
        miss = make_event(category=Category.GROUP_MEMBER_ADDED, event_id=4732, target="Users")
        assert len(engine.evaluate(hit)) == 1
        assert engine.evaluate(miss) == []

    def test_title_keeps_unknown_placeholders(self) -> None:
        engine = RuleEngine([match_rule()])
        [alert] = engine.evaluate(make_event(event_id=4672, user="bob"))
        assert alert.title == "bob on SRV-AD01 ({missing})"

    def test_disabled_rules_are_skipped(self) -> None:
        engine = RuleEngine([match_rule(enabled=False)])
        assert engine.evaluate(make_event(event_id=4672, user="bob")) == []

    def test_unknown_field_in_conditions_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown event field"):
            match_rule(match={"usr": "bob"})


# ── Loading ────────────────────────────────────────────────────────────────────


class TestLoading:
    def test_repo_rules_load(self) -> None:
        ids = {r.id for r in load_rules(REPO_RULES)}
        assert ids == {
            "brute_force_by_ip",
            "logon_off_hours",
            "privilege_use_non_admin",
            "new_local_admin",
        }

    def test_list_document_and_duplicate_ids(self, tmp_path: Path) -> None:
        rule = "- {id: a, name: a, type: match, severity: low, title: a}\n"
        (tmp_path / "one.yml").write_text(rule + rule.replace("id: a", "id: b"))
        assert [r.id for r in load_rules(tmp_path)] == ["a", "b"]
        (tmp_path / "two.yaml").write_text(rule)
        with pytest.raises(ValueError, match="duplicate rule id"):
            load_rules(tmp_path)

    def test_invalid_rule_names_the_file(self, tmp_path: Path) -> None:
        (tmp_path / "bad.yml").write_text("id: a\nname: a\ntype: nope\nseverity: low\ntitle: a\n")
        with pytest.raises(ValueError, match=r"bad\.yml"):
            load_rules(tmp_path)

    def test_missing_directory(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            load_rules(tmp_path / "nope")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("30s", 30), ("5m", 300), ("2h", 7200), ("1d", 86400), (45, 45)],
    )
    def test_parse_duration(self, raw: str | int, expected: int) -> None:
        assert parse_duration(raw) == timedelta(seconds=expected)
