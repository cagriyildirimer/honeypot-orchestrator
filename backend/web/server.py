from __future__ import annotations

import asyncio
import csv
import io
import json
import hashlib
import secrets
import time
import uuid
from database import async_session
from models import Event, User, Session as DBSession
from sqlalchemy import select, delete, desc
from collections import Counter
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from config import __version__
from defense import (
    add_to_blacklist,
    add_to_whitelist,
    delete_from_blacklist,
    delete_from_whitelist,
    get_blacklist,
    get_whitelist,
    resolve_mac,
    is_blacklisted,
)
from geo import bulk_lookup
from threat_intel import enrich_top_ips

if TYPE_CHECKING:
    from orchestrator import Orchestrator


ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
USER_ROLES = {ROLE_ADMIN, ROLE_VIEWER}


class WebDashboard:
    def __init__(self, host: str, port: int, orchestrator: Orchestrator) -> None:
        self.host = host
        self.port = port
        self.orchestrator = orchestrator
        # Panel de kucuk bir asyncio HTTP sunucusu olarak calisir.
        self._server: asyncio.AbstractServer | None = None
        # Basit oturumlar bellek icinde, kullanicilar yerel JSON dosyasinda tutulur.
        self._users_path = self.orchestrator.config.logging.path.parent / "web_users.json"
        self._sessions_path = self.orchestrator.config.logging.path.parent / "web_sessions.json"
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
            self._users_path,
            {
                self.orchestrator.config.auth.username: {
                    "password": self.orchestrator.config.auth.password,
                    "role": ROLE_ADMIN,
                },
            },
        )

    async def _save_sessions(self) -> None:
        try:
            with open(self._sessions_path, "w", encoding="utf-8") as f:
                json.dump(self._sessions, f)
        except Exception:
            pass
        # self._reload_users() moved to start()

    async def start(self) -> None:
        self._sessions = await self._load_sessions()
        await self._reload_users()
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

        if path == "/healthz" and method == "GET":
            return self._json_response({"ok": True, "service": "web"})

        if path == "/api/csrf" and method == "GET":
            token = secrets.token_hex(16)
            now = time.time()
            self._csrf_tokens[token] = now
            # Clean up old CSRF tokens (older than 24h)
            self._csrf_tokens = {k: v for k, v in self._csrf_tokens.items() if now - v < 86400}
            return self._json_response({"csrf_token": token})

        # CSRF check for POST requests (except login which establishes the session)
        if method == "POST" and path != "/api/login":
            client_token = headers.get("x-csrf-token", "")
            if not client_token or client_token not in self._csrf_tokens:
                return self._json_response(
                    {"error": "Invalid or missing CSRF token."},
                    status=HTTPStatus.FORBIDDEN,
                )



        if path == "/api/services/toggle" and method == "POST":
            if not self._is_admin(cookies):
                return self._json_response(
                    {"error": "Admin access required."},
                    status=HTTPStatus.FORBIDDEN,
                )
            payload = _decode_json_body(request["body"])
            service_name = str(payload.get("service", ""))
            enabled = bool(payload.get("enabled", False))
            if enabled:
                success = await self.orchestrator.start_service(service_name)
            else:
                success = await self.orchestrator.stop_service(service_name)
            return self._json_response({"ok": success})

        if path == "/api/login" and method == "POST":
            payload = _decode_json_body(request["body"])
            return await self._handle_login(payload, request)

        if path == "/api/logout" and method == "POST":
            return await self._handle_logout(cookies)

        if path == "/api/session" and method == "GET":
            return self._json_response(
                {
                    "authenticated": authenticated,
                    "username": self._current_username(cookies) if authenticated else "",
                    "role": self._current_role(cookies) if authenticated else "",
                }
            )

        if path.startswith("/api/") and not authenticated:
            return self._json_response(
                {"error": "Authentication required."},
                status=HTTPStatus.UNAUTHORIZED,
            )

        if path == "/api/status" and method == "GET":
            display_host = _request_display_host(request)
            return self._json_response(
                {
                    "services": self.orchestrator.service_status(display_host),
                    "profile": self.orchestrator.profile_status(),
                    "log_path": str(self.orchestrator.config.logging.path),
                    "web": {
                        "host": self.orchestrator.config.web.host,
                        "display_host": display_host,
                        "port": self.orchestrator.config.web.port,
                    },
                }
            )

        if path == "/api/overview" and method == "GET":
            return self._json_response(await self._build_overview_payload(request))

        if path == "/api/events" and method == "GET":
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

        if path == "/api/stats" and method == "GET":
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

        if path == "/api/settings" and method == "GET":
            return self._json_response(self._build_settings_payload(request, cookies))

        if path == "/api/logs/export" and method == "GET":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            return self._export_logs_response()

        if path == "/api/ioc/csv" and method == "GET":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            return await self._export_ioc_csv_response()

        if path == "/api/ioc/stix" and method == "GET":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            return await self._export_ioc_stix_response()

        if path == "/api/logs/clear" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            return await self._handle_clear_logs()

        if path == "/api/users" and method == "GET":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            return self._json_response({"users": self._user_payload()})

        if path == "/api/users" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            return await self._handle_create_user(payload)

        if path == "/api/users/delete" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            return await self._handle_delete_user(payload, cookies)

        if path == "/api/users/password" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            return await self._handle_change_user_password(payload)

        if path == "/api/users/role" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            return await self._handle_change_user_role(payload, cookies)

        if path == "/api/profile" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            profile_name = str(payload.get("profile", "")).strip()
            if not profile_name:
                return self._json_response(
                    {"error": "Profile name is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            try:
                return self._json_response(await self.orchestrator.set_profile(profile_name))
            except KeyError:
                return self._json_response(
                    {"error": f"Unknown profile: {profile_name}."},
                    status=HTTPStatus.NOT_FOUND,
                )
            except OSError as exc:
                return self._json_response(
                    {
                        "error": f"Could not apply profile: {profile_name}.",
                        "detail": str(exc),
                    },
                    status=HTTPStatus.CONFLICT,
                )

        if path == "/api/whitelist" and method == "GET":
            return self._json_response({"whitelist": get_whitelist()})

        if path == "/api/whitelist" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            ip = str(payload.get("ip", "")).strip()
            description = str(payload.get("description", "")).strip()
            if not ip or not description:
                return self._json_response(
                    {"error": "IP and description are required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            if add_to_whitelist(ip, description):
                return self._json_response({"ok": True, "whitelist": get_whitelist()})
            return self._json_response(
                {"error": "Failed to add or already exists."},
                status=HTTPStatus.CONFLICT,
            )

        if path == "/api/whitelist/delete" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            ip = str(payload.get("ip", "")).strip()
            if not ip:
                return self._json_response(
                    {"error": "IP is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            if delete_from_whitelist(ip):
                return self._json_response({"ok": True, "whitelist": get_whitelist()})
            return self._json_response(
                {"error": "Not found in whitelist."},
                status=HTTPStatus.NOT_FOUND,
            )

        if path == "/api/blacklist" and method == "GET":
            return self._json_response({"blacklist": get_blacklist()})

        if path == "/api/blacklist" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            ip = str(payload.get("ip", "")).strip()
            description = str(payload.get("description", "")).strip()
            if not ip or not description:
                return self._json_response(
                    {"error": "IP/MAC and description are required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            if add_to_blacklist(ip, description):
                return self._json_response({"ok": True, "blacklist": get_blacklist()})
            return self._json_response(
                {"error": "Failed to add or already exists."},
                status=HTTPStatus.CONFLICT,
            )

        if path == "/api/blacklist/delete" and method == "POST":
            if not self._is_admin(cookies):
                return self._forbidden_response()
            payload = _decode_json_body(request["body"])
            ip = str(payload.get("ip", "")).strip()
            if not ip:
                return self._json_response(
                    {"error": "IP/MAC is required."},
                    status=HTTPStatus.BAD_REQUEST,
                )
            if delete_from_blacklist(ip):
                return self._json_response({"ok": True, "blacklist": get_blacklist()})
            return self._json_response(
                {"error": "Not found in blacklist."},
                status=HTTPStatus.NOT_FOUND,
            )

        if path == "/api/threat-intel" and method == "GET":
            return await self._handle_threat_intel()

        if path.startswith("/api/"):
            return self._json_response(
                {"error": "Not found."},
                status=HTTPStatus.NOT_FOUND,
            )

        return _response(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

    async def _handle_login(self, payload: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
        client_ip = request.get("client_ip", "")
        now = time.time()
        
        if client_ip:
            self._login_attempts[client_ip] = [t for t in self._login_attempts.get(client_ip, []) if now - t < 300]
            if len(self._login_attempts[client_ip]) >= 5:
                return self._json_response(
                    {"ok": False, "error": "Too many failed attempts. Try again in 5 minutes."},
                    status=HTTPStatus.TOO_MANY_REQUESTS,
                )

        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if not _verify_password(password, self._user_password(username)):
            if client_ip:
                self._login_attempts.setdefault(client_ip, []).append(now)
            await self.orchestrator.logger.log(
                {
                    "service": "web",
                    "event_type": "login_failed",
                    "summary": f"Dashboard login failed for {username or 'unknown'}.",
                }
            )
            return self._json_response(
                {"ok": False, "error": "Invalid username or password."},
                status=HTTPStatus.UNAUTHORIZED,
            )

        if client_ip in self._login_attempts:
            del self._login_attempts[client_ip]

        token = secrets.token_hex(32)
        self._sessions[token] = {"username": username, "created_at": time.time()}
        await self._save_sessions()
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "login_success",
                "summary": f"Dashboard login success for {username}.",
            }
        )
        return self._json_response(
            {"ok": True, "username": username, "role": self._user_role(username)},
            cookies=[_build_cookie("session", token, max_age=86400)],
        )

    async def _handle_logout(self, cookies: dict[str, str]) -> dict[str, Any]:
        token = cookies.get("session", "")
        if token:
            self._sessions.pop(token, None)
            await self._save_sessions()
        return self._json_response(
            {"ok": True},
            cookies=[_build_cookie("session", "", max_age=0)],
        )

    async def _handle_clear_logs(self) -> dict[str, Any]:
        path = self.orchestrator.config.logging.path
        await asyncio.to_thread(_clear_file, path)
        return self._json_response({"ok": True, "log_path": str(path)})

    async def _handle_create_user(self, payload: dict[str, Any]) -> dict[str, Any]:
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        role = _normalize_role(str(payload.get("role", ROLE_VIEWER)))
        if not username or not password:
            return self._json_response(
                {"error": "Username and password are required."},
                status=HTTPStatus.BAD_REQUEST,
            )
        if username in self._users:
            return self._json_response(
                {"error": f"User already exists: {username}."},
                status=HTTPStatus.CONFLICT,
            )
        self._users[username] = {"password": _hash_password(password), "role": role}
        await asyncio.to_thread(_save_users, self._users_path, self._users)
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "user_created",
                "summary": f"Dashboard user {username} was created.",
            }
        )
        return self._json_response({"ok": True, "users": self._user_payload()})

    async def _handle_delete_user(
        self,
        payload: dict[str, Any],
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        username = str(payload.get("username", "")).strip()
        if not username:
            return self._json_response(
                {"error": "Username is required."},
                status=HTTPStatus.BAD_REQUEST,
            )
        if username not in self._users:
            return self._json_response(
                {"error": f"Unknown user: {username}."},
                status=HTTPStatus.NOT_FOUND,
            )
        if username == self._current_username(cookies):
            return self._json_response(
                {"error": "You cannot delete the signed-in user."},
                status=HTTPStatus.CONFLICT,
            )
        if len(self._users) <= 1:
            return self._json_response(
                {"error": "At least one user must remain."},
                status=HTTPStatus.CONFLICT,
            )
        if self._user_role(username) == ROLE_ADMIN and self._admin_count() <= 1:
            return self._json_response(
                {"error": "At least one admin user must remain."},
                status=HTTPStatus.CONFLICT,
            )
        del self._users[username]
        self._sessions = {
            token: session_data
            for token, session_data in self._sessions.items()
            if session_data.get("username") in self._users
        }
        await asyncio.to_thread(_save_users, self._users_path, self._users)
        await self._save_sessions()
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "user_deleted",
                "summary": f"Dashboard user {username} was deleted.",
            }
        )
        return self._json_response({"ok": True, "users": self._user_payload()})

    async def _handle_change_user_password(self, payload: dict[str, Any]) -> dict[str, Any]:
        username = str(payload.get("username", "")).strip()
        password = str(payload.get("password", ""))
        if not username or not password:
            return self._json_response(
                {"error": "Username and new password are required."},
                status=HTTPStatus.BAD_REQUEST,
            )
        if username not in self._users:
            return self._json_response(
                {"error": f"Unknown user: {username}."},
                status=HTTPStatus.NOT_FOUND,
            )
        self._users[username]["password"] = _hash_password(password)
        await asyncio.to_thread(_save_users, self._users_path, self._users)
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "user_password_changed",
                "summary": f"Dashboard user {username} password was changed.",
            }
        )
        return self._json_response({"ok": True, "users": self._user_payload()})

    async def _handle_change_user_role(
        self,
        payload: dict[str, Any],
        cookies: dict[str, str],
    ) -> dict[str, Any]:
        username = str(payload.get("username", "")).strip()
        role = _normalize_role(str(payload.get("role", "")))
        if not username:
            return self._json_response(
                {"error": "Username is required."},
                status=HTTPStatus.BAD_REQUEST,
            )
        if username not in self._users:
            return self._json_response(
                {"error": f"Unknown user: {username}."},
                status=HTTPStatus.NOT_FOUND,
            )
        if username == self._current_username(cookies) and role != ROLE_ADMIN:
            return self._json_response(
                {"error": "You cannot remove admin access from the signed-in user."},
                status=HTTPStatus.CONFLICT,
            )
        if self._user_role(username) == ROLE_ADMIN and role != ROLE_ADMIN and self._admin_count() <= 1:
            return self._json_response(
                {"error": "At least one admin user must remain."},
                status=HTTPStatus.CONFLICT,
            )
        self._users[username]["role"] = role
        await asyncio.to_thread(_save_users, self._users_path, self._users)
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "user_role_changed",
                "summary": f"Dashboard user {username} role was changed to {role}.",
            }
        )
        return self._json_response({"ok": True, "users": self._user_payload()})

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

    def _export_logs_response(self) -> dict[str, Any]:
        path = self.orchestrator.config.logging.path
        body = path.read_bytes() if path.exists() else b""
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
        attackers = await enrich_top_ips(
            ip_counts,
            honeypot_host=self.orchestrator.config.host,
            abuseipdb_key=ti_config.abuseipdb_key,
            greynoise_key=ti_config.greynoise_key,
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
            top_ip_blocked = is_blacklisted(top_ip)
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
            "services": self.orchestrator.service_status(display_host),
            "profile": self.orchestrator.profile_status(),
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
        attackers = await asyncio.to_thread(
            enrich_top_ips,
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


async def read_recent_events(path: Path, limit: int) -> list[dict[str, Any]]:
    try:
        async with async_session() as session:
            stmt = select(Event).order_by(desc(Event.timestamp)).limit(max(1, min(limit, 10000)))
            result = await session.execute(stmt)
            records = []
            for r in result.scalars().all():
                event_data = {
                    "id": r.id,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if r.timestamp else "",
                    "service": r.service,
                    "event_type": r.event_type,
                    "src_ip": r.src_ip,
                    "src_port": r.src_port,
                    "summary": r.summary,
                }
                if r.details:
                    event_data.update(r.details)
                records.append(event_data)
            return list(reversed(records))
    except Exception as e:
        print(f"DB read events error: {e}")
        return []


def _response(
    status: HTTPStatus,
    content_type: str,
    body: bytes,
    headers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "content_type": content_type,
        "body": body,
        "headers": headers or {},
    }


def _decode_json_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _clear_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


def _hash_password(password: str, salt: bytes | None = None, iterations: int = 600000) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${hash_bytes.hex()}"


def _verify_password(password: str, hashed: str) -> bool:
    if not hashed.startswith("pbkdf2_sha256$"):
        return password == hashed
    try:
        parts = hashed.split("$")
        if len(parts) != 4:
            return False
        _, iterations_str, salt_hex, hash_hex = parts
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return secrets.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


async def _load_users(path: Path, default_users: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    cleaned: dict[str, dict[str, str]] = {}
    needs_save = False

    try:
        async with async_session() as session:
            result = await session.execute(select(User))
            records = result.scalars().all()
            for r in records:
                cleaned[r.username] = {"password": r.password_hash, "role": r.role}
    except Exception as e:
        print(f"DB load users error: {e}")

    for username, user in default_users.items():
        if username not in cleaned:
            cleaned[username] = dict(user)
            needs_save = True

    for username, user_info in cleaned.items():
        password = user_info["password"]
        if not password.startswith("pbkdf2_sha256$"):
            user_info["password"] = _hash_password(password)
            needs_save = True

    if needs_save:
        await _save_users(path, cleaned)

    return cleaned


async def _save_users(path: Path, users: dict[str, dict[str, str]]) -> None:
    try:
        async with async_session() as session:
            await session.execute(delete(User))
            for username, data in users.items():
                session.add(User(
                    username=username,
                    password_hash=data["password"],
                    role=data["role"]
                ))
            await session.commit()
    except Exception as e:
        print(f"DB save users error: {e}")


def _normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    return normalized if normalized in USER_ROLES else ROLE_VIEWER


def _format_duration(total_seconds: int) -> str:
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or parts:
        parts.append(f"{hours}h")
    if minutes or parts:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def _parse_request_line(request_line: str) -> tuple[str, str, str]:
    parts = request_line.strip().split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    return "GET", "/", "HTTP/1.1"


def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for fragment in cookie_header.split(";"):
        key, _, value = fragment.strip().partition("=")
        if key:
            cookies[key] = value
    return cookies


def _build_cookie(name: str, value: str, *, max_age: int | None = None) -> str:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    return "; ".join(parts)


def _request_display_host(request: dict[str, Any]) -> str:
    host_header = str(request.get("headers", {}).get("host", "")).strip()
    if not host_header:
        return "127.0.0.1"
    if host_header.startswith("["):
        closing = host_header.find("]")
        if closing != -1:
            return host_header[1:closing]
        return host_header
    host, _, _ = host_header.partition(":")
    return host or "127.0.0.1"


def _safe_int(value: str, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(parsed, maximum))


def _tail_lines(path: Path, limit: int) -> list[str]:
    if limit <= 0:
        return []
    with path.open("rb") as file:
        file.seek(0, 2)
        position = file.tell()
        buffer = bytearray()
        newline_count = 0
        chunk_size = 4096

        while position > 0 and newline_count <= limit:
            read_size = min(chunk_size, position)
            position -= read_size
            file.seek(position)
            chunk = file.read(read_size)
            buffer[:0] = chunk
            newline_count = buffer.count(b"\n")

    return buffer.decode("utf-8", errors="replace").splitlines()[-limit:]
