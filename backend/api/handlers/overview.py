from __future__ import annotations
import time
import secrets
from typing import Any
from collections import Counter
from http import HTTPStatus
from api.router import router

from web.utils import (
    _request_display_host,
    _safe_int,
    read_recent_events,
)

@router.get("/healthz")
async def handle_healthz(self, request: dict[str, Any]) -> dict[str, Any]:
    return self._json_response({"ok": True, "service": "web"})

@router.get("/api/csrf")
async def handle_get_csrf(self, request: dict[str, Any]) -> dict[str, Any]:
    token = secrets.token_hex(16)
    now = time.time()
    self._csrf_tokens[token] = now
    self._csrf_tokens = {k: v for k, v in self._csrf_tokens.items() if now - v < 86400}
    return self._json_response({"csrf_token": token})

@router.get("/api/status")
async def handle_get_status(self, request: dict[str, Any]) -> dict[str, Any]:
    display_host = _request_display_host(request)
    return self._json_response(
        {
            "services": await self.orchestrator.service_status(display_host),
            "profile": await self.orchestrator.profile_status(),
            "log_path": str(self.orchestrator.config.logging.path),
            "web": {
                "host": self.orchestrator.config.web.host,
                "display_host": display_host,
                "port": self.orchestrator.config.web.port,
            },
        }
    )

@router.get("/api/overview")
async def handle_get_overview(self, request: dict[str, Any]) -> dict[str, Any]:
    return self._json_response(await self._build_overview_payload(request))

@router.get("/api/events")
async def handle_get_events(self, request: dict[str, Any]) -> dict[str, Any]:
    query = request["query"]
    limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
    service_filter = query.get("service", [""])[0].strip().lower()
    event_filter = query.get("event_type", [""])[0].strip().lower()
    events = await read_recent_events(self.orchestrator.config.logging.path, limit * 4)
    filtered = [
        event
        for event in events
        if (not service_filter or str(event.get("service", "")).lower() == service_filter)
        and (not event_filter or str(event.get("event_type", "")).lower() == event_filter)
    ]
    return self._json_response({"events": filtered[:limit]})

@router.get("/api/stats")
async def handle_get_stats(self, request: dict[str, Any]) -> dict[str, Any]:
    records = await read_recent_events(self.orchestrator.config.logging.path, 1000)
    by_service = Counter(record.get("service", "unknown") for record in records)
    by_type = Counter(record.get("event_type", "unknown") for record in records)
    return self._json_response(
        {
            "total_recent_events": len(records),
            "by_service": dict(by_service),
            "by_type": dict(by_type),
        }
    )

@router.get("/api/settings")
async def handle_get_settings(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    payload = await self._build_settings_payload(request, cookies)
    return self._json_response(payload)

@router.get("/api/logs/export")
async def handle_export_logs(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    return await self._export_logs_response()

@router.get("/api/ioc/csv")
async def handle_export_ioc_csv(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    return await self._export_ioc_csv_response()

@router.get("/api/ioc/stix")
async def handle_export_ioc_stix(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    return await self._export_ioc_stix_response()

@router.post("/api/logs/clear")
async def handle_clear_logs(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    return await self._handle_clear_logs()

@router.get("/api/threat-intel")
async def handle_threat_intel(self, request: dict[str, Any]) -> dict[str, Any]:
    return await self._handle_threat_intel()
