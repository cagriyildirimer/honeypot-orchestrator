from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections import Counter
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from honeypot_orchestrator import __version__

if TYPE_CHECKING:
    from honeypot_orchestrator.orchestrator import Orchestrator


WEB_DIR = Path(__file__).parent
ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
USER_ROLES = {ROLE_ADMIN, ROLE_VIEWER}
TEMPLATE_ROUTES = {
    "/login": "login.html",
    "/dashboard": "dashboard.html",
    "/logs": "logs.html",
    "/settings/appearance": "appearance.html",
    "/settings/system": "system.html",
    "/settings/users": "users.html",
}
STATIC_ROUTES = {
    "/static/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/static/common.js": ("common.js", "application/javascript; charset=utf-8"),
    "/static/login.js": ("login.js", "application/javascript; charset=utf-8"),
    "/static/dashboard.js": ("dashboard.js", "application/javascript; charset=utf-8"),
    "/static/logs.js": ("logs.js", "application/javascript; charset=utf-8"),
    "/static/settings.js": ("settings.js", "application/javascript; charset=utf-8"),
    "/static/users.js": ("users.js", "application/javascript; charset=utf-8"),
}


class WebDashboard:
    def __init__(self, host: str, port: int, orchestrator: Orchestrator) -> None:
        self.host = host
        self.port = port
        self.orchestrator = orchestrator
        # Panel de kucuk bir asyncio HTTP sunucusu olarak calisir.
        self._server: asyncio.AbstractServer | None = None
        # Basit oturumlar bellek icinde, kullanicilar yerel JSON dosyasinda tutulur.
        self._sessions: dict[str, str] = {}
        self._users_path = self.orchestrator.config.logging.path.parent / "web_users.json"
        self._users = _load_users(
            self._users_path,
            {
                self.orchestrator.config.auth.username: {
                    "password": self.orchestrator.config.auth.password,
                    "role": ROLE_ADMIN,
                },
            },
        )
        self._started_at = time.monotonic()

    async def start(self) -> None:
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
            request = await self._read_request(reader)
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
        authenticated = self._is_authenticated(cookies)

        if path == "/":
            return self._redirect(self._home_path(cookies) if authenticated else "/login")

        if path == "/settings":
            return self._redirect("/settings/appearance" if authenticated else "/login")

        if path in TEMPLATE_ROUTES:
            if path == "/login":
                if authenticated:
                    return self._redirect(self._home_path(cookies))
            elif not authenticated:
                return self._redirect("/login")
            return _response(
                HTTPStatus.OK,
                "text/html; charset=utf-8",
                (WEB_DIR / "templates" / TEMPLATE_ROUTES[path]).read_bytes(),
            )

        if path in STATIC_ROUTES:
            filename, content_type = STATIC_ROUTES[path]
            return _response(
                HTTPStatus.OK,
                content_type,
                (WEB_DIR / "static" / filename).read_bytes(),
            )

        if path == "/healthz" and method == "GET":
            return self._json_response({"ok": True, "service": "web"})

        if path == "/api/login" and method == "POST":
            payload = _decode_json_body(request["body"])
            return await self._handle_login(payload)

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
            return self._json_response(self._build_overview_payload(request))

        if path == "/api/events" and method == "GET":
            query = request["query"]
            limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
            service_filter = query.get("service", [""])[0].strip().lower()
            event_filter = query.get("event_type", [""])[0].strip().lower()
            events = read_recent_events(self.orchestrator.config.logging.path, limit * 4)
            filtered = [
                event
                for event in events
                if (not service_filter or str(event.get("service", "")).lower() == service_filter)
                and (not event_filter or str(event.get("event_type", "")).lower() == event_filter)
            ]
            return self._json_response({"events": filtered[:limit]})

        if path == "/api/stats" and method == "GET":
            records = read_recent_events(self.orchestrator.config.logging.path, 1000)
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

        if path.startswith("/api/"):
            return self._json_response(
                {"error": "Not found."},
                status=HTTPStatus.NOT_FOUND,
            )

        return _response(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found")

    async def _handle_login(self, payload: dict[str, Any]) -> dict[str, Any]:
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if self._user_password(username) != password:
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

        token = secrets.token_urlsafe(24)
        self._sessions[token] = username
        await self.orchestrator.logger.log(
            {
                "service": "web",
                "event_type": "login_success",
                "summary": f"Dashboard login success for {username}.",
            }
        )
        return self._json_response(
            {"ok": True, "username": username, "role": self._user_role(username)},
            cookies=[_build_cookie("session", token)],
        )

    async def _handle_logout(self, cookies: dict[str, str]) -> dict[str, Any]:
        token = cookies.get("session", "")
        self._sessions.pop(token, None)
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
        self._users[username] = {"password": password, "role": role}
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
            token: session_username
            for token, session_username in self._sessions.items()
            if session_username != username
        }
        await asyncio.to_thread(_save_users, self._users_path, self._users)
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
        self._users[username]["password"] = password
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
        return token in self._sessions

    def _current_username(self, cookies: dict[str, str]) -> str:
        token = cookies.get("session", "")
        return self._sessions.get(token, "")

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

    def _user_payload(self) -> list[dict[str, str]]:
        return [
            {"username": username, "role": self._user_role(username)}
            for username in sorted(self._users)
        ]

    def _build_overview_payload(self, request: dict[str, Any]) -> dict[str, Any]:
        display_host = _request_display_host(request)
        query = request["query"]
        limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
        service_filter = query.get("service", [""])[0].strip().lower()
        event_filter = query.get("event_type", [""])[0].strip().lower()
        records = read_recent_events(self.orchestrator.config.logging.path, 1000)
        filtered = [
            event
            for event in records
            if (not service_filter or str(event.get("service", "")).lower() == service_filter)
            and (not event_filter or str(event.get("event_type", "")).lower() == event_filter)
        ]
        by_service = Counter(record.get("service", "unknown") for record in records)
        by_type = Counter(record.get("event_type", "unknown") for record in records)
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
            },
            "events": filtered[:limit],
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


def read_recent_events(path: Path, limit: int) -> list[dict[str, Any]]:
    # Log dosyasi henuz olusmadiysa panel bos liste gosterir.
    if not path.exists():
        return []
    lines = _tail_lines(path, max(1, min(limit, 2000)))
    records = []
    for line in lines:
        try:
            # Bozuk JSON satirlari paneli kirmasin diye atlanir.
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(records))


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


def _load_users(path: Path, default_users: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if not path.exists():
        _save_users(path, default_users)
        return dict(default_users)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(default_users)
    if not isinstance(payload, dict):
        return dict(default_users)
    users = payload.get("users", {})
    if not isinstance(users, dict):
        return dict(default_users)
    cleaned: dict[str, dict[str, str]] = {}
    for username, value in users.items():
        normalized_username = str(username).strip()
        if not normalized_username:
            continue
        if isinstance(value, dict):
            password = str(value.get("password", ""))
            role = _normalize_role(str(value.get("role", ROLE_VIEWER)))
        else:
            password = str(value)
            role = ROLE_ADMIN if normalized_username in default_users else ROLE_VIEWER
        if password:
            cleaned[normalized_username] = {"password": password, "role": role}
    for username, user in default_users.items():
        cleaned.setdefault(username, dict(user))
    return cleaned or dict(default_users)


def _save_users(path: Path, users: dict[str, dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"users": users}
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True), encoding="utf-8")


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
