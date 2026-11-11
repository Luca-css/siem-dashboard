from __future__ import annotations

from datetime import timedelta
from typing import Any

from conftest import T0, win_event
from fastapi.testclient import TestClient


def brute_force_batch(ip: str = "203.0.113.7", n: int = 5) -> list[dict[str, Any]]:
    return [
        win_event(4625, T0 + timedelta(seconds=i * 10), TargetUserName="admin", IpAddress=ip)
        for i in range(n)
    ]


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] is True
    assert body["rules_loaded"] == 4


def test_dashboard_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "/ws/alerts" in response.text


def test_ingest_single_object(client: TestClient) -> None:
    response = client.post("/events", json=win_event(4624, TargetUserName="lucas", LogonType="2"))
    assert response.status_code == 200
    assert response.json() == {"accepted": 1, "rejected": [], "alerts": []}
    [event] = client.get("/events").json()
    assert event["user"] == "lucas"
    assert event["category"] == "auth_success"


def test_ingest_brute_force_creates_alert(client: TestClient) -> None:
    body = client.post("/events", json=brute_force_batch()).json()
    assert body["accepted"] == 5
    [alert] = body["alerts"]
    assert alert["rule_id"] == "brute_force_by_ip"
    assert alert["severity"] == "critical"
    assert alert["event_count"] == 5
    assert alert["id"] == 1
    assert alert["mitre"] == ["T1110"]


def test_partial_rejection_reports_index(client: TestClient) -> None:
    batch = [win_event(4624, TargetUserName="a"), {"EventID": 4625}, win_event(4688)]
    response = client.post("/events", json=batch)
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2
    assert [r["index"] for r in body["rejected"]] == [1]
    assert "TimeCreated" in body["rejected"][0]["error"]


def test_all_rejected_is_422(client: TestClient) -> None:
    response = client.post("/events", json=[{"foo": "bar"}])
    assert response.status_code == 422
    assert response.json()["accepted"] == 0


def test_non_json_body_is_422(client: TestClient) -> None:
    response = client.post("/events", content=b"nope", headers={"content-type": "application/json"})
    assert response.status_code == 422


def test_syslog_ingest_triggers_brute_force(client: TestClient) -> None:
    lines = "\n".join(
        f"Nov 11 14:00:0{i} web01 sshd[99]: Failed password for root from 198.51.100.9 port 1 ssh2"
        for i in range(5)
    )
    response = client.post(
        "/events/syslog",
        content=lines + "\n\ngarbage line\n",
        headers={"content-type": "text/plain"},
    )
    body = response.json()
    assert response.status_code == 200
    assert body["accepted"] == 5
    assert [r["index"] for r in body["rejected"]] == [5]
    assert body["alerts"][0]["src_ip"] == "198.51.100.9"


def test_alert_filters_and_pagination(client: TestClient) -> None:
    # 2 critical brute-force alerts + 1 high new-local-admin alert
    client.post("/events", json=brute_force_batch("203.0.113.1"))
    client.post("/events", json=brute_force_batch("203.0.113.2"))
    client.post(
        "/events",
        json=win_event(
            4732, host="WS-042", SubjectUserName="jsilva", TargetUserName="Administrators"
        ),
    )

    page = client.get("/alerts").json()
    assert page["total"] == 3
    assert [a["id"] for a in page["items"]] == [3, 2, 1]  # newest first

    page = client.get("/alerts", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 3
    assert [a["id"] for a in page["items"]] == [2]

    crit = client.get("/alerts", params={"severity": "critical"}).json()
    assert crit["total"] == 2
    both = client.get("/alerts", params=[("severity", "critical"), ("severity", "high")]).json()
    assert both["total"] == 3

    assert client.get("/alerts", params={"src_ip": "203.0.113.2"}).json()["total"] == 1
    assert client.get("/alerts", params={"host": "WS-042"}).json()["items"][0]["rule_id"] == (
        "new_local_admin"
    )
    assert client.get("/alerts", params={"rule_id": "nope"}).json()["total"] == 0

    since = (T0 + timedelta(seconds=41)).isoformat()
    assert client.get("/alerts", params={"since": since}).json()["total"] == 0
    assert client.get("/alerts", params={"until": since}).json()["total"] == 3


def test_alert_query_validation(client: TestClient) -> None:
    assert client.get("/alerts", params={"limit": 0}).status_code == 422
    assert client.get("/alerts", params={"limit": 501}).status_code == 422
    assert client.get("/alerts", params={"severity": "apocalyptic"}).status_code == 422


def test_get_and_ack_alert(client: TestClient) -> None:
    client.post("/events", json=brute_force_batch())
    assert client.get("/alerts/1").json()["status"] == "open"
    assert client.post("/alerts/1/ack").json()["status"] == "acknowledged"
    assert client.get("/alerts", params={"status": "open"}).json()["total"] == 0
    assert client.get("/alerts/999").status_code == 404
    assert client.post("/alerts/999/ack").status_code == 404


def test_stats(client: TestClient) -> None:
    client.post("/events", json=brute_force_batch())
    client.post("/events", json=win_event(4624, host="WS-001", TargetUserName="a", LogonType="3"))
    stats = client.get("/stats").json()
    assert stats["total_events"] == 6
    assert stats["events_by_category"] == {"auth_failure": 5, "auth_success": 1}
    assert stats["hosts"] == 2
    assert stats["open_alerts"] == 1
    assert stats["open_alerts_by_severity"] == {"critical": 1}


def test_rules_endpoint(client: TestClient) -> None:
    rules = {r["id"]: r for r in client.get("/rules").json()}
    assert rules["brute_force_by_ip"]["threshold"] == 5
    assert rules["brute_force_by_ip"]["window"] == "PT5M"


def test_data_survives_restart(tmp_path: Any) -> None:
    from conftest import REPO_RULES

    from siem.api import create_app
    from siem.config import Settings

    settings = Settings(db_path=str(tmp_path / "persist.db"), rules_dir=str(REPO_RULES))
    with TestClient(create_app(settings)) as c:
        c.post("/events", json=brute_force_batch())
    with TestClient(create_app(settings)) as c:
        assert c.get("/alerts").json()["total"] == 1
