"""HTTP + WebSocket API (FastAPI).

Endpoints
---------
GET  /                  dashboard (static HTML)
GET  /health            liveness/readiness
POST /events            ingest Windows Security events (JSON object or array)
POST /events/syslog     ingest syslog lines (text/plain, one per line)
GET  /events            most recently ingested events
GET  /alerts            alerts with filters + pagination
GET  /alerts/{id}       one alert
POST /alerts/{id}/ack   acknowledge an alert
GET  /stats             counters for the dashboard
GET  /rules             loaded detection rules
WS   /ws/alerts         pushes every new alert as JSON
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool

from siem import __version__
from siem.config import Settings
from siem.ingest import parse_syslog_line, parse_windows_event
from siem.models import Alert, AlertStatus, Event, Severity
from siem.pipeline import Pipeline
from siem.rules import RuleEngine, load_rules
from siem.store import AlertFilter, Store

log = logging.getLogger("siem")

STATIC_DIR = Path(__file__).parent / "static"
MAX_BATCH = 5000
MAX_SYSLOG_BYTES = 2 * 1024 * 1024


class Rejected(BaseModel):
    index: int
    error: str


class IngestResult(BaseModel):
    accepted: int
    rejected: list[Rejected]
    alerts: list[Alert]


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[Alert]


class AlertBroadcaster:
    """Tracks connected WebSocket clients and fans out new alerts to them."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.discard(ws)

    async def broadcast(self, alert: Alert) -> None:
        message = {"type": "alert", "data": alert.model_dump(mode="json")}
        for ws in list(self._clients):
            try:
                await ws.send_json(message)
            except Exception:  # client went away mid-send; drop it, keep serving others
                self.disconnect(ws)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        return "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'body'}: {err['msg']}"
            for err in exc.errors()
        )
    return str(exc)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        rules = load_rules(settings.rules_dir)
        store = Store(settings.db_path)
        app.state.rules = rules
        app.state.store = store
        app.state.pipeline = Pipeline(store, RuleEngine(rules))
        app.state.broadcaster = AlertBroadcaster()
        log.info("loaded %d rules from %s, db=%s", len(rules), settings.rules_dir, settings.db_path)
        try:
            yield
        finally:
            store.close()

    app = FastAPI(title="Mini-SIEM", version=__version__, lifespan=lifespan)

    async def ingest(request: Request, parsed: list[Event], rejected: list[Rejected]) -> Any:
        alerts = await run_in_threadpool(request.app.state.pipeline.process, parsed)
        for alert in alerts:
            await request.app.state.broadcaster.broadcast(alert)
        result = IngestResult(accepted=len(parsed), rejected=rejected, alerts=alerts)
        # Every record invalid -> 422, so clients notice a broken shipper.
        status = 422 if rejected and not parsed else 200
        return JSONResponse(result.model_dump(mode="json"), status_code=status)

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health")
    def health(request: Request) -> JSONResponse:
        db_ok = request.app.state.store.ping()
        body = {
            "status": "ok" if db_ok else "degraded",
            "version": __version__,
            "database": db_ok,
            "rules_loaded": len(request.app.state.rules),
            "ws_clients": request.app.state.broadcaster.client_count,
        }
        return JSONResponse(body, status_code=200 if db_ok else 503)

    @app.post("/events", response_model=IngestResult)
    async def ingest_windows(
        request: Request,
        body: Annotated[dict[str, Any] | list[dict[str, Any]], Body()],
    ) -> Any:
        records = body if isinstance(body, list) else [body]
        if len(records) > MAX_BATCH:
            raise HTTPException(413, f"batch larger than {MAX_BATCH} events")
        parsed: list[Event] = []
        rejected: list[Rejected] = []
        for i, record in enumerate(records):
            try:
                parsed.append(parse_windows_event(record))
            except ValueError as exc:
                rejected.append(Rejected(index=i, error=_describe_error(exc)))
        return await ingest(request, parsed, rejected)

    @app.post(
        "/events/syslog",
        response_model=IngestResult,
        openapi_extra={"requestBody": {"content": {"text/plain": {"schema": {"type": "string"}}}}},
    )
    async def ingest_syslog(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_SYSLOG_BYTES:
            raise HTTPException(413, "payload too large")
        parsed: list[Event] = []
        rejected: list[Rejected] = []
        lines = [ln for ln in raw.decode("utf-8", errors="replace").splitlines() if ln.strip()]
        for i, line in enumerate(lines):
            try:
                parsed.append(parse_syslog_line(line))
            except ValueError as exc:
                rejected.append(Rejected(index=i, error=str(exc)))
        return await ingest(request, parsed, rejected)

    @app.get("/events")
    def list_events(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = request.app.state.store.recent_events(limit, offset)
        return events

    @app.get("/alerts", response_model=AlertPage)
    def list_alerts(
        request: Request,
        severity: Annotated[list[Severity] | None, Query()] = None,
        rule_id: str | None = None,
        host: str | None = None,
        src_ip: str | None = None,
        status: AlertStatus | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> AlertPage:
        flt = AlertFilter(
            severity=severity or (),
            rule_id=rule_id,
            host=host,
            src_ip=src_ip,
            status=status,
            since=since,
            until=until,
        )
        items, total = request.app.state.store.list_alerts(flt, limit, offset)
        return AlertPage(total=total, limit=limit, offset=offset, items=items)

    @app.get("/alerts/{alert_id}", response_model=Alert)
    def get_alert(request: Request, alert_id: int) -> Alert:
        alert: Alert | None = request.app.state.store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(404, "alert not found")
        return alert

    @app.post("/alerts/{alert_id}/ack", response_model=Alert)
    def ack_alert(request: Request, alert_id: int) -> Alert:
        alert: Alert | None = request.app.state.store.set_alert_status(
            alert_id, AlertStatus.ACKNOWLEDGED
        )
        if alert is None:
            raise HTTPException(404, "alert not found")
        return alert

    @app.get("/stats")
    def stats(request: Request) -> dict[str, Any]:
        data: dict[str, Any] = request.app.state.store.stats()
        return data

    @app.get("/rules")
    def rules(request: Request) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in request.app.state.rules]

    @app.websocket("/ws/alerts")
    async def ws_alerts(ws: WebSocket) -> None:
        broadcaster: AlertBroadcaster = ws.app.state.broadcaster
        await broadcaster.connect(ws)
        try:
            while True:
                await ws.receive_text()  # clients don't need to send; this detects disconnects
        except WebSocketDisconnect:
            pass
        finally:
            broadcaster.disconnect(ws)

    return app
