"""FastAPI service: BIG-IP sessions, validation, AS3/TS remediation."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from as3_services import build_as3_declaration
from bigip_ts_validator import BigIPClient, BigIPError, ensure_extensions, validate
from ts_declaration_builder import build_ts_declaration, normalize_consumer_type

SESSION_TTL_SEC = 45 * 60
REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class _Session:
    client: BigIPClient
    created: float


_sessions: dict[str, _Session] = {}


def _gc_sessions() -> None:
    now = time.time()
    for sid, s in list(_sessions.items()):
        if now - s.created > SESSION_TTL_SEC:
            _sessions.pop(sid, None)


def _get_session(session_id: str) -> _Session:
    _gc_sessions()
    s = _sessions.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Unknown or expired session")
    return s


class ConnectBody(BaseModel):
    host: str = Field(..., description="BIG-IP management IP or hostname")
    username: str
    password: str
    verify_tls: bool = False


class ServicesBody(BaseModel):
    ltm: bool = False
    asm: bool = False
    afm: bool = False
    http_analytics: bool = False
    tcp_analytics: bool = False


class ValidateBody(BaseModel):
    consumer: str
    services: ServicesBody


class RemediateBody(BaseModel):
    consumer: str
    consumer_params: dict[str, Any] = Field(default_factory=dict)
    services: ServicesBody
    install_prereqs: bool = False
    apply_as3: bool = True
    post_ts: bool = True
    include_event_listener: bool = True
    include_system_poller: bool = True
    as3_version: str | None = None
    ts_version: str | None = None
    assume_yes: bool = True


app = FastAPI(title="BIG-IP Telemetry Streaming helper", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/session")
def create_session(body: ConnectBody) -> dict[str, str]:
    _gc_sessions()
    try:
        client = BigIPClient(body.host, body.username, body.password, verify_tls=body.verify_tls)
    except BigIPError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    sid = secrets.token_urlsafe(24)
    _sessions[sid] = _Session(client=client, created=time.time())
    return {"session_id": sid, "host": body.host}


@app.post("/api/session/{session_id}/validate")
def session_validate(session_id: str, body: ValidateBody) -> dict[str, Any]:
    s = _get_session(session_id)
    svc = body.services.model_dump()
    findings = validate(s.client, body.consumer, svc)
    findings["consumer_normalized"] = normalize_consumer_type(body.consumer)
    return findings


@app.post("/api/session/{session_id}/remediate")
def session_remediate(session_id: str, body: RemediateBody) -> dict[str, Any]:
    s = _get_session(session_id)
    svc = body.services.model_dump()
    if not any(svc.values()):
        raise HTTPException(status_code=400, detail="Select at least one telemetry service")

    steps: list[dict[str, Any]] = []

    if body.install_prereqs:
        try:
            installed = ensure_extensions(
                s.client,
                cache_dir=REPO_ROOT / "rpms",
                as3_version=body.as3_version,
                ts_version=body.ts_version,
                assume_yes=body.assume_yes,
            )
            steps.append({"step": "install_extensions", "installed": installed})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.apply_as3:
        try:
            as3_decl = build_as3_declaration(svc)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            as3_resp = s.client.post_as3(as3_decl)
            steps.append({"step": "post_as3", "response": as3_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    if body.post_ts:
        try:
            ts_decl = build_ts_declaration(
                body.consumer,
                body.consumer_params,
                include_event_listener=body.include_event_listener,
                include_system_poller=body.include_system_poller,
            )
            ts_resp = s.client.post_ts_declaration(ts_decl)
            steps.append({"step": "post_ts", "response": ts_resp})
        except BigIPError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    findings = validate(s.client, body.consumer, svc)
    findings["consumer_normalized"] = normalize_consumer_type(body.consumer)
    return {"steps": steps, "findings": findings}


@app.get("/api/consumers")
def list_consumers() -> dict[str, Any]:
    """Consumer types aligned with F5 TS docs (Push Consumers)."""
    return {
        "docs_url": "https://clouddocs.f5.com/products/extensions/f5-telemetry-streaming/latest/setting-up-consumer.html",
        "consumers": [
            {"type": "Splunk", "label": "Splunk (HEC)"},
            {"type": "Azure_Log_Analytics", "label": "Microsoft Azure Log Analytics"},
            {"type": "Azure_Application_Insights", "label": "Microsoft Azure Application Insights"},
            {"type": "AWS_CloudWatch", "label": "AWS CloudWatch"},
            {"type": "AWS_S3", "label": "AWS S3"},
            {"type": "DataDog", "label": "Datadog"},
            {"type": "ElasticSearch", "label": "ElasticSearch"},
            {"type": "Sumo_Logic", "label": "Sumo Logic"},
            {"type": "Generic_HTTP", "label": "Generic HTTP"},
            {"type": "Kafka", "label": "Kafka"},
            {"type": "Graphite", "label": "Graphite"},
            {"type": "Statsd", "label": "StatsD"},
            {"type": "default", "label": "Default (troubleshooting)"},
            {"type": "OpenTelemetry_Exporter", "label": "OpenTelemetry Exporter (advanced)"},
            {"type": "Google_Cloud_Monitoring", "label": "Google Cloud Monitoring"},
            {"type": "Google_Cloud_Logging", "label": "Google Cloud Logging"},
            {"type": "F5_Cloud", "label": "F5 Cloud"},
        ],
    }


def create_app() -> FastAPI:
    return app


_UI_DIST = REPO_ROOT / "frontend" / "dist"
if _UI_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_UI_DIST), html=True), name="frontend")
