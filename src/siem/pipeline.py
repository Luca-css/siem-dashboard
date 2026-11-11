"""Glue between parsing, detection and storage: event in -> stored event + alerts out."""

from __future__ import annotations

import threading
from collections.abc import Iterable

from siem.models import Alert, Event
from siem.rules import RuleEngine
from siem.store import Store


class Pipeline:
    def __init__(self, store: Store, engine: RuleEngine) -> None:
        self.store = store
        self.engine = engine
        # The rule engine keeps mutable window state; process one batch at a time.
        self._lock = threading.Lock()

    def process(self, events: Iterable[Event]) -> list[Alert]:
        """Persist events, evaluate rules and persist resulting alerts (with ids)."""
        stored: list[Alert] = []
        with self._lock:
            for event in events:
                self.store.add_event(event)
                for alert in self.engine.evaluate(event):
                    stored.append(self.store.add_alert(alert))
        return stored
