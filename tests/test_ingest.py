from __future__ import annotations

from datetime import UTC, datetime

import pytest
from conftest import T0, win_event

from siem.ingest import normalize_ip, parse_syslog_line, parse_windows_event
from siem.models import Category


class TestWindows:
    def test_failed_logon(self) -> None:
        event = parse_windows_event(
            win_event(4625, TargetUserName="admin", IpAddress="203.0.113.7", LogonType="10")
        )
        assert event.category is Category.AUTH_FAILURE
        assert event.user == "admin"
        assert event.src_ip == "203.0.113.7"
        assert event.logon_type == 10
        assert event.timestamp == T0
        assert event.source == "windows"

    def test_privilege_use_uses_subject_account(self) -> None:
        event = parse_windows_event(
            win_event(4672, SubjectUserName="jsilva", TargetUserName="ignored")
        )
        assert event.category is Category.PRIVILEGE_USE
        assert event.user == "jsilva"

    def test_group_member_added(self) -> None:
        event = parse_windows_event(
            win_event(
                4732,
                SubjectUserName="jsilva",
                TargetUserName="Administrators",
                MemberName="-",
                MemberSid="S-1-5-21-1-2-3-1104",
            )
        )
        assert event.category is Category.GROUP_MEMBER_ADDED
        assert event.user == "jsilva"
        assert event.target == "Administrators"
        assert "S-1-5-21-1-2-3-1104 added to local group Administrators" in event.message

    def test_dash_values_become_none(self) -> None:
        event = parse_windows_event(win_event(4625, TargetUserName="x", IpAddress="-"))
        assert event.src_ip is None

    def test_powershell_dotnet_date(self) -> None:
        raw = win_event(4624, TargetUserName="x")
        raw["TimeCreated"] = "/Date(1794409200000)/"
        assert parse_windows_event(raw).timestamp == datetime(2026, 11, 11, 15, 0, tzinfo=UTC)

    def test_naive_timestamp_is_utc(self) -> None:
        raw = win_event(4624, TargetUserName="x")
        raw["TimeCreated"] = "2026-11-11 15:00:00"
        assert parse_windows_event(raw).timestamp == T0

    def test_unknown_event_id_is_other(self) -> None:
        assert parse_windows_event(win_event(4688)).category is Category.OTHER

    @pytest.mark.parametrize(
        "raw",
        [
            {"TimeCreated": "2026-11-11T15:00:00Z", "Computer": "a"},  # no EventID
            {"EventID": "abc", "TimeCreated": "2026-11-11T15:00:00Z", "Computer": "a"},
            {"EventID": 4625, "TimeCreated": "not a date", "Computer": "a"},
            {"EventID": 4625, "TimeCreated": "2026-11-11T15:00:00Z", "Computer": ""},
        ],
    )
    def test_invalid_records_raise_value_error(self, raw: dict[str, object]) -> None:
        with pytest.raises(ValueError):
            parse_windows_event(raw)


class TestSyslog:
    NOW = datetime(2026, 11, 11, 23, 0, tzinfo=UTC)

    def test_ssh_failed_password_invalid_user(self) -> None:
        line = (
            "Nov 11 14:02:11 web01 sshd[2211]: Failed password for invalid user oracle "
            "from 198.51.100.23 port 52211 ssh2"
        )
        event = parse_syslog_line(line, now=self.NOW)
        assert event.category is Category.AUTH_FAILURE
        assert event.user == "oracle"
        assert event.src_ip == "198.51.100.23"
        assert event.host == "web01"
        assert event.timestamp == datetime(2026, 11, 11, 14, 2, 11, tzinfo=UTC)

    def test_ssh_accepted_with_iso_timestamp_and_pri(self) -> None:
        line = (
            "<38>2026-11-11T02:15:00-03:00 web01 sshd[1]: Accepted publickey for deploy "
            "from 192.0.2.10 port 4000 ssh2"
        )
        event = parse_syslog_line(line)
        assert event.category is Category.AUTH_SUCCESS
        assert event.user == "deploy"
        assert event.timestamp == datetime(2026, 11, 11, 5, 15, tzinfo=UTC)

    def test_sudo_command_is_privilege_use(self) -> None:
        line = (
            "Nov  9 10:00:00 web01 sudo:   lucas : TTY=pts/0 ; PWD=/home/lucas ; "
            "USER=root ; COMMAND=/bin/bash"
        )
        event = parse_syslog_line(line, now=self.NOW)
        assert event.category is Category.PRIVILEGE_USE
        assert event.user == "lucas"
        assert event.target == "root"

    def test_sudo_not_in_sudoers_is_auth_failure(self) -> None:
        line = (
            "Nov 11 10:00:00 web01 sudo: guest : user NOT in sudoers ; TTY=pts/1 ; "
            "PWD=/tmp ; USER=root ; COMMAND=/bin/sh"
        )
        assert parse_syslog_line(line, now=self.NOW).category is Category.AUTH_FAILURE

    def test_year_rollover(self) -> None:
        line = "Dec 31 23:59:00 web01 cron[1]: job done"
        event = parse_syslog_line(line, now=datetime(2027, 1, 1, 0, 5, tzinfo=UTC))
        assert event.timestamp.year == 2026
        assert event.category is Category.OTHER

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_syslog_line("this is not syslog")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("::ffff:10.0.0.5", "10.0.0.5"),
        (" 203.0.113.7 ", "203.0.113.7"),
        ("2001:db8::1", "2001:db8::1"),
        ("-", None),
        ("", None),
        ("not-an-ip", None),
        (None, None),
    ],
)
def test_normalize_ip(raw: str | None, expected: str | None) -> None:
    assert normalize_ip(raw) == expected
