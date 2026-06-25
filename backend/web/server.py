from __future__ import annotations

import asyncio
import csv
import io
import json
import time
import uuid
from database.database import async_session
from database.models import Event, User, Session as DBSession
from sqlalchemy import select, delete, desc  # type: ignore
from collections import Counter
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from core.config import __version__
from defense import (
    add_to_blacklist,
    add_to_whitelist,
    delete_from_blacklist,
    delete_from_whitelist,
    get_blacklist,
    get_whitelist,
    resolve_mac,
    is_blacklisted,
    is_auto_blacklist_enabled,
    set_auto_blacklist_enabled,
)
from core.geo import bulk_lookup
from threat_intel import get_cached_top_ips, enrich_top_ips
from api.router import router

if TYPE_CHECKING:
    from orchestrator import Orchestrator


from web.utils import (
    read_recent_events, _response, _decode_json_body, _clear_file,
    _hash_password, _verify_password, _load_users, _save_users,
    _normalize_role, _format_duration, _parse_request_line, _parse_cookies,
    ROLE_ADMIN, ROLE_VIEWER, USER_ROLES, _safe_int, _request_display_host
)


class WebDashboard:
    def __init__(self, host: str, port: int, orchestrator: Orchestrator) -> None:
        self.host = host
        self.port = port
        self.orchestrator = orchestrator
        # Panel de kucuk bir asyncio HTTP sunucusu olarak calisir.
        self._server: asyncio.AbstractServer | None = None
        # Basit oturumlar bellek icinde, kullanicilar yerel JSON dosyasinda tutulur.
        self._sessions: dict[str, dict[str, Any]] = {}
        # self._reload_users() moved to start()
        self._started_at = time.monotonic()
        self._login_attempts: dict[str, list[float]] = {}
        self._csrf_tokens: dict[str, float] = {}

    async def _load_sessions(self) -> dict[str, dict[str, Any]]:
        try:
            async with async_session() as session:
                result = await session.execute(select(DBSession))
                sessions = {}
                for r in result.scalars().all():
                    sessions[r.session_id] = {
                        "username": r.username,
                        "role": r.role,
                        "created_at": r.created_at.timestamp() if r.created_at else time.time()
                    }
                return sessions
        except Exception as e:
            print(f"DB load sessions error: {e}")
            return {}

    async def _reload_users(self) -> None:
        self._users = await _load_users(
            None,
            {
                self.orchestrator.config.auth.username: {
                    "password": self.orchestrator.config.auth.password,
                    "role": ROLE_ADMIN,
                },
            },
        )

    async def _save_sessions(self) -> None:
        try:
            async with async_session() as session:
                await session.execute(delete(DBSession))
                now = datetime.now(UTC)
                for sid, data in self._sessions.items():
                    session.add(DBSession(
                        session_id=sid, 
                        username=data.get("username", "unknown"),
                        role=data.get("role", ROLE_VIEWER),
                        created_at=now
                    ))
                await session.commit()
        except Exception as e:
            print(f"DB save sessions error: {e}")

    async def start(self) -> None:
        self._sessions = await self._load_sessions()
        await self._reload_users()
        
        from api.handlers.settings import load_siem_config
        await load_siem_config()
        
        # Tarayici istekleri handle_client metoduna yonlendirilir.
        self._server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        self._sessions.clear()

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            client_ip = ""
            peername = writer.get_extra_info("peername")
            if peername:
                client_ip = peername[0]
            request = await self._read_request(reader)
            request["client_ip"] = client_ip
            response = await self._route_request(request)
            if response.get("stream", False):
                await self._send_sse_stream(writer, response["generator"])
            else:
                await self._send_response(writer, response)
        except EOFError:
            return
        except Exception as exc:
            await self.orchestrator.logger.log(
                {
                    "service": "web",
                    "event_type": "request_error",
                    "error": type(exc).__name__,
                    "summary": f"Dashboard request failed with {type(exc).__name__}.",
                }
            )
            body = f"Internal server error: {type(exc).__name__}".encode("utf-8")
            await self._send_response(
                writer,
                _response(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    body,
                ),
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    async def _route_request(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request["method"]
        path = request["path"]
        cookies = request["cookies"]
        headers = request["headers"]
        authenticated = self._is_authenticated(cookies)

        # CSRF check for POST requests (except login which establishes the session)
        if method == "POST" and path != "/api/login":
            client_token = headers.get("x-csrf-token", "")
            if not client_token or client_token not in self._csrf_tokens:
                return self._json_response(
                    {"error": "Invalid or missing CSRF token."},
                    status=HTTPStatus.FORBIDDEN,
                )

        # Authentication check for API routes (except auth/CSRF endpoints)
        if path.startswith("/api/") and not authenticated and path not in {"/api/login", "/api/session", "/api/csrf"}:
            return self._json_response(
                {"error": "Authentication required."},
                status=HTTPStatus.UNAUTHORIZED,
            )

        # Delegate routing to the APIRouter instance
        response = await router.route(method, path, self, request)
        if response is not None:
            return response

        # Fallback if route not matched
        if path.startswith("/api/"):
            return self._json_response(
                {"error": "Not found."},
                status=HTTPStatus.NOT_FOUND,
            )

        return _response(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

    async def _handle_clear_logs(self) -> dict[str, Any]:
        path = self.orchestrator.config.logging.path
        await asyncio.to_thread(_clear_file, path)
        return self._json_response({"ok": True, "log_path": str(path)})

    async def _read_request(self, reader: asyncio.StreamReader) -> dict[str, Any]:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            raise EOFError
        method, target, _ = _parse_request_line(request_line.decode("utf-8", "replace"))
        headers: dict[str, str] = {}
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in {b"\r\n", b"\n", b""}:
                break
            key, _, value = line.decode("utf-8", "replace").partition(":")
            if key and value:
                headers[key.strip().lower()] = value.strip()

        body = b""
        content_length = _safe_int(headers.get("content-length", "0"), default=0, minimum=0, maximum=65536)
        if content_length:
            body = await asyncio.wait_for(reader.readexactly(content_length), timeout=10)

        parsed = urlparse(target)
        return {
            "method": method.upper(),
            "target": target,
            "path": parsed.path,
            "query": parse_qs(parsed.query),
            "headers": headers,
            "cookies": _parse_cookies(headers.get("cookie", "")),
            "body": body,
        }

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        response: dict[str, Any],
    ) -> None:
        status = response["status"]
        body = response["body"]
        headers = {
            "Content-Type": response["content_type"],
            "Content-Length": str(len(body)),
            "Connection": "close",
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        }
        headers.update(response.get("headers", {}))
        header_lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
        for key, value in headers.items():
            if isinstance(value, list):
                for item in value:
                    header_lines.append(f"{key}: {item}")
            else:
                header_lines.append(f"{key}: {value}")
        header_blob = ("\r\n".join(header_lines) + "\r\n\r\n").encode("utf-8")
        writer.write(header_blob + body)
        await writer.drain()

    async def _send_sse_stream(self, writer: asyncio.StreamWriter, generator: Any) -> None:
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        writer.write(headers.encode("utf-8"))
        await writer.drain()
        
        try:
            async for data in generator:
                writer.write(f"data: {data}\n\n".encode("utf-8"))
                await writer.drain()
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass

    def _is_authenticated(self, cookies: dict[str, str]) -> bool:
        token = cookies.get("session", "")
        session_data = self._sessions.get(token)
        if not session_data:
            return False
        if time.time() - session_data.get("created_at", 0) > 86400:
            self._sessions.pop(token, None)
            return False
        return True

    def _current_username(self, cookies: dict[str, str]) -> str:
        token = cookies.get("session", "")
        session_data = self._sessions.get(token)
        return str(session_data.get("username", "")) if session_data else ""

    def _current_role(self, cookies: dict[str, str]) -> str:
        return self._user_role(self._current_username(cookies))

    def _user_password(self, username: str) -> str:
        user = self._users.get(username, {})
        return str(user.get("password", "")) if isinstance(user, dict) else ""

    def _user_role(self, username: str) -> str:
        user = self._users.get(username, {})
        if not isinstance(user, dict):
            return ROLE_VIEWER
        return _normalize_role(str(user.get("role", ROLE_VIEWER)))

    def _is_admin(self, cookies: dict[str, str]) -> bool:
        return self._current_role(cookies) == ROLE_ADMIN

    def _home_path(self, cookies: dict[str, str]) -> str:
        return "/dashboard"

    def _admin_count(self) -> int:
        return sum(1 for username in self._users if self._user_role(username) == ROLE_ADMIN)

    def _json_response(
        self,
        payload: dict[str, Any],
        *,
        status: HTTPStatus = HTTPStatus.OK,
        cookies: list[str] | None = None,
    ) -> dict[str, Any]:
        headers: dict[str, Any] = {}
        if cookies:
            headers["Set-Cookie"] = cookies
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        return {
            "status": status,
            "content_type": "application/json; charset=utf-8",
            "body": body,
            "headers": headers,
        }

    def _redirect(self, location: str) -> dict[str, Any]:
        return _response(
            HTTPStatus.FOUND,
            "text/plain; charset=utf-8",
            f"Redirecting to {location}".encode("utf-8"),
            headers={"Location": location},
        )

    def _forbidden_response(self) -> dict[str, Any]:
        return self._json_response(
            {"error": "Admin access required."},
            status=HTTPStatus.FORBIDDEN,
        )

    def _build_settings_payload(
        self,
        request: dict[str, Any],
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        display_host = _request_display_host(request)
        log_path = self.orchestrator.config.logging.path
        log_size = log_path.stat().st_size if log_path.exists() else 0
        uptime_seconds = int(time.monotonic() - self._started_at)
        return {
            "panel": {
                "url": f"http://{display_host}:{self.orchestrator.config.web.port}",
                "host": self.orchestrator.config.web.host,
                "display_host": display_host,
                "port": self.orchestrator.config.web.port,
            },
            "session": {
                "username": self._current_username(cookies),
                "role": self._current_role(cookies),
            },
            "logging": {
                "path": str(log_path),
                "size_bytes": log_size,
                "exists": log_path.exists(),
            },
            "runtime": {
                "uptime_seconds": uptime_seconds,
                "uptime": _format_duration(uptime_seconds),
                "health": "ok" if self._server is not None else "stopped",
                "version": __version__,
            },
            "users": self._user_payload(),
        }

    async def _export_logs_response(self) -> dict[str, Any]:
        records = await read_recent_events(self.orchestrator.config.logging.path, 10000)
        lines = [json.dumps(r) for r in reversed(records)]
        body = "\n".join(lines).encode("utf-8")
        return _response(
            HTTPStatus.OK,
            "application/x-ndjson; charset=utf-8",
            body,
            headers={
                "Content-Disposition": 'attachment; filename="honeypot-events.jsonl"',
            },
        )

    async def _handle_threat_intel(self) -> dict[str, Any]:
        records = await read_recent_events(self.orchestrator.config.logging.path, 2000)
        now_ts = time.time()
        start_ts = now_ts - 24 * 60 * 60
        ip_counts: dict[str, int] = {}
        for record in records:
            ts_str = record.get("timestamp", "")
            src_ip = record.get("src_ip", "")
            if not ts_str or not src_ip:
                continue
            try:
                dt = datetime.strptime(ts_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
                dt = dt.replace(tzinfo=UTC)
                if start_ts <= dt.timestamp() <= now_ts:
                    ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
            except Exception:
                continue

        ti_config = self.orchestrator.config.threat_intel
        attackers = await get_cached_top_ips(
            ip_counts,
            honeypot_host=self.orchestrator.config.host,
            limit=10,
        )

        # Build summary
        tor_count = sum(1 for a in attackers if a.get("is_tor"))
        cloud_count = sum(1 for a in attackers if a.get("cloud_provider"))
        abuse_scores = [a["abuse_score"] for a in attackers if isinstance(a.get("abuse_score"), (int, float))]
        avg_abuse = round(sum(abuse_scores) / len(abuse_scores), 1) if abuse_scores else "N/A"

        return self._json_response({
            "attackers": attackers,
            "summary": {
                "tor_count": tor_count,
                "cloud_count": cloud_count,
                "avg_abuse_score": avg_abuse,
            },
        })

    def _user_payload(self) -> list[dict[str, str]]:
        return [
            {"username": username, "role": self._user_role(username)}
            for username in sorted(self._users)
        ]

    async def _build_overview_payload(self, request: dict[str, Any]) -> dict[str, Any]:
        display_host = _request_display_host(request)
        query = request["query"]
        limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=2000)
        service_filter = query.get("service", [""])[0].strip().lower()
        event_filter = query.get("event_type", [""])[0].strip().lower()
        records = await read_recent_events(self.orchestrator.config.logging.path, max(1000, limit))
        filtered = [
            event
            for event in records
            if (not service_filter or str(event.get("service", "")).lower() == service_filter)
            and (not event_filter or str(event.get("event_type", "")).lower() == event_filter)
        ]
        by_service = Counter(record.get("service", "unknown") for record in records)
        by_type = Counter(record.get("event_type", "unknown") for record in records)

        # Calculate top IP in the last 24 hours and dynamically resolve its MAC
        now_ts = time.time()
        start_ts = now_ts - 24 * 60 * 60
        ip_totals = {}
        for record in records:
            ts_str = record.get("timestamp", "")
            if not ts_str or not record.get("src_ip"):
                continue
            try:
                dt = datetime.strptime(ts_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
                dt = dt.replace(tzinfo=UTC)
                if start_ts <= dt.timestamp() <= now_ts:
                    ip = str(record.get("src_ip"))
                    ip_totals[ip] = ip_totals.get(ip, 0) + 1
            except Exception:
                pass

        top_mac = "unknown"
        top_ip_blocked = False
        geo_markers = []
        if ip_totals:
            top_ip = max(ip_totals, key=ip_totals.get)
            top_mac = resolve_mac(top_ip)
            top_ip_blocked = await is_blacklisted(top_ip)
            # GeoIP lookup for map markers
            try:
                geo_data = bulk_lookup(list(ip_totals.keys())[:200])
                seen_coords: set[tuple[float, float]] = set()
                for ip, count in sorted(ip_totals.items(), key=lambda x: x[1], reverse=True):
                    info = geo_data.get(ip, {})
                    lat = info.get("lat", 0)
                    lon = info.get("lon", 0)
                    if lat == 0 and lon == 0:
                        continue
                    coord_key = (round(lat, 1), round(lon, 1))
                    if coord_key in seen_coords:
                        continue
                    seen_coords.add(coord_key)
                    geo_markers.append({
                        "ip": ip, "lat": lat, "lon": lon,
                        "country": info.get("country", ""),
                        "city": info.get("city", ""),
                        "count": count,
                    })
            except Exception:
                pass

        return {
            "services": await self.orchestrator.service_status(display_host),
            "profile": await self.orchestrator.profile_status(),
            "log_path": str(self.orchestrator.config.logging.path),
            "web": {
                "host": self.orchestrator.config.web.host,
                "display_host": display_host,
                "port": self.orchestrator.config.web.port,
            },
            "stats": {
                "total_recent_events": len(records),
                "by_service": dict(by_service),
                "by_type": dict(by_type),
                "top_ip_mac": top_mac,
                "top_ip_blocked": top_ip_blocked,
            },
            "geo_markers": geo_markers,
            "events": filtered[:limit],
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


    async def _gather_ioc_data(self) -> list[dict[str, Any]]:
        records = await read_recent_events(self.orchestrator.config.logging.path, 10000)
        
        stats: dict[str, dict[str, Any]] = {}
        for record in records:
            ts_str = record.get("timestamp", "")
            ip = record.get("src_ip", "")
            if not ts_str or not ip:
                continue
            try:
                dt = datetime.strptime(ts_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
                dt = dt.replace(tzinfo=UTC)
                ts = dt.timestamp()
            except Exception:
                continue
            
            if ip not in stats:
                stats[ip] = {"count": 0, "first": ts, "last": ts}
            stats[ip]["count"] += 1
            if ts < stats[ip]["first"]:
                stats[ip]["first"] = ts
            if ts > stats[ip]["last"]:
                stats[ip]["last"] = ts

        ip_counts = {ip: data["count"] for ip, data in stats.items()}
        
        ti_config = self.orchestrator.config.threat_intel
        attackers = await enrich_top_ips(
            ip_counts,
            honeypot_host=self.orchestrator.config.host,
            abuseipdb_key=ti_config.abuseipdb_key,
            greynoise_key=ti_config.greynoise_key,
            limit=500,
        )
        
        for attacker in attackers:
            ip = attacker["ip"]
            attacker["first_seen"] = datetime.fromtimestamp(stats[ip]["first"], UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            attacker["last_seen"] = datetime.fromtimestamp(stats[ip]["last"], UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            
        return attackers

    async def _export_ioc_csv_response(self) -> dict[str, Any]:
        attackers = await self._gather_ioc_data()
        
        output = io.StringIO()
        fieldnames = [
            "ip", "country", "city", "asn", "org", "rdns", "is_tor",
            "cloud_provider", "abuse_score", "greynoise_class", "event_count",
            "first_seen", "last_seen"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(attackers)
        
        body = output.getvalue().encode("utf-8")
        return _response(
            HTTPStatus.OK,
            "text/csv; charset=utf-8",
            body,
            headers={
                "Content-Disposition": 'attachment; filename="ioc_export.csv"',
            },
        )

    async def _export_ioc_stix_response(self) -> dict[str, Any]:
        attackers = await self._gather_ioc_data()
        
        objects = []
        now_str = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        for a in attackers:
            ip = a["ip"]
            ipv4_id = f"ipv4-addr--{uuid.uuid4()}"
            ipv4_obj = {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ipv4_id,
                "value": ip
            }
            objects.append(ipv4_obj)
            
            indicator_id = f"indicator--{uuid.uuid4()}"
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": now_str,
                "modified": now_str,
                "name": f"Malicious IP: {ip}",
                "description": f"Honeypot attacker. Abuse score: {a.get('abuse_score', 'N/A')}",
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "valid_from": now_str
            }
            objects.append(indicator_obj)
            
            obs_id = f"observed-data--{uuid.uuid4()}"
            first_dt = datetime.strptime(a["first_seen"].replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
            last_dt = datetime.strptime(a["last_seen"].replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
            obs_obj = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": obs_id,
                "created": now_str,
                "modified": now_str,
                "first_observed": first_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "last_observed": last_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "number_observed": a.get("event_count", 1),
                "object_refs": [ipv4_id]
            }
            objects.append(obs_obj)
            
            rel_id = f"relationship--{uuid.uuid4()}"
            rel_obj = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": now_str,
                "modified": now_str,
                "relationship_type": "based-on",
                "source_ref": indicator_id,
                "target_ref": obs_id
            }
            objects.append(rel_obj)
            
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": objects
        }
        
        body = json.dumps(bundle, indent=2).encode("utf-8")
        return _response(
            HTTPStatus.OK,
            "application/json; charset=utf-8",
            body,
            headers={
                "Content-Disposition": 'attachment; filename="ioc_export.stix.json"',
            },
        )


# Import all handler modules to register routes onto the global router
import api.handlers.auth
import api.handlers.blacklist
import api.handlers.services
import api.handlers.overview
import api.handlers.analyze
import api.handlers.alerts
import api.handlers.settings
