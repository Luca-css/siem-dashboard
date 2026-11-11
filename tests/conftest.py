from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from siem.api import create_app
from siem.config import Settings
from siem.models import Category, Event

REPO_RULES = Path(__file__).resolve().parent.parent / "rules"

# Wednesday 2026-11-11 15:00 UTC == 12:00 in America/Sao_Paulo (business hours).
T0 = datetime(2026, 11, 11, 15, 0, tzinfo=UTC)


def win_event(
    event_id: int, when: datetime = T0, host: str = "SRV-AD01", **data: Any
) -> dict[str, Any]:
    """Raw Windows Security event in the shape accepted by POST /events."""
    return {
        "EventID": event_id,
        "TimeCreated": when.isoformat(),
        "Computer": host,
        "EventData": data,
    }


def make_event(
    when: datetime = T0,
    category: Category = Category.AUTH_FAILURE,
    **fields: Any,
) -> Event:
    """Normalized Event for rule-engine unit tests."""
    defaults: dict[str, Any] = {"source": "windows", "host": "SRV-AD01", "src_ip": "203.0.113.7"}
    defaults.update(fields)
    return Event(timestamp=when, category=category, **defaults)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(db_path=str(tmp_path / "test.db"), rules_dir=str(REPO_RULES))
    with TestClient(create_app(settings)) as test_client:
        yield test_client
