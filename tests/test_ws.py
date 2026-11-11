from __future__ import annotations

from datetime import timedelta

from conftest import T0, win_event
from fastapi.testclient import TestClient


def test_new_alerts_are_pushed_to_all_clients(client: TestClient) -> None:
    with (
        client.websocket_connect("/ws/alerts") as ws1,
        client.websocket_connect("/ws/alerts") as ws2,
    ):
        assert client.get("/health").json()["ws_clients"] == 2

        events = [
            win_event(
                4625, T0 + timedelta(seconds=i), TargetUserName="admin", IpAddress="203.0.113.7"
            )
            for i in range(5)
        ]
        response = client.post("/events", json=events)
        assert len(response.json()["alerts"]) == 1

        for ws in (ws1, ws2):
            message = ws.receive_json()
            assert message["type"] == "alert"
            assert message["data"]["rule_id"] == "brute_force_by_ip"
            assert message["data"]["id"] == 1


def test_events_without_alerts_push_nothing(client: TestClient) -> None:
    with client.websocket_connect("/ws/alerts") as ws:
        client.post("/events", json=win_event(4624, TargetUserName="lucas", LogonType="3"))
        # A follow-up alert must be the *first* message received: nothing was sent before it.
        client.post(
            "/events",
            json=win_event(4732, SubjectUserName="x", TargetUserName="Administrators"),
        )
        assert ws.receive_json()["data"]["rule_id"] == "new_local_admin"


def test_disconnected_client_is_removed(client: TestClient) -> None:
    with client.websocket_connect("/ws/alerts"):
        assert client.get("/health").json()["ws_clients"] == 1
    # After the context exits the server sees the disconnect and forgets the client.
    for _ in range(50):
        if client.get("/health").json()["ws_clients"] == 0:
            break
    assert client.get("/health").json()["ws_clients"] == 0
