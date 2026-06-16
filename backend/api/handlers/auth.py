from __future__ import annotations
from typing import Any
import time
import secrets
from http import HTTPStatus
from api.router import router

# Let's import the helper functions from web.server to avoid duplicate logic
from web.server import (
    _verify_password,
    _hash_password,
    _normalize_role,
    _save_users,
    _build_cookie,
    _decode_json_body,
    ROLE_ADMIN,
    ROLE_VIEWER,
)

@router.post("/api/login")
async def handle_login(self, request: dict[str, Any]) -> dict[str, Any]:
    payload = _decode_json_body(request["body"])
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

@router.post("/api/logout")
async def handle_logout(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    token = cookies.get("session", "")
    if token:
        self._sessions.pop(token, None)
        await self._save_sessions()
    return self._json_response(
        {"ok": True},
        cookies=[_build_cookie("session", "", max_age=0)],
    )

@router.get("/api/session")
async def handle_session(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    authenticated = self._is_authenticated(cookies)
    return self._json_response(
        {
            "authenticated": authenticated,
            "username": self._current_username(cookies) if authenticated else "",
            "role": self._current_role(cookies) if authenticated else "",
        }
    )

@router.get("/api/users")
async def handle_get_users(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    return self._json_response({"users": self._user_payload()})

@router.post("/api/users")
async def handle_create_user(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
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
    await _save_users(None, self._users)
    await self.orchestrator.logger.log(
        {
            "service": "web",
            "event_type": "user_created",
            "summary": f"Dashboard user {username} was created.",
        }
    )
    return self._json_response({"ok": True, "users": self._user_payload()})

@router.post("/api/users/delete")
async def handle_delete_user(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
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
    await _save_users(None, self._users)
    await self._save_sessions()
    await self.orchestrator.logger.log(
        {
            "service": "web",
            "event_type": "user_deleted",
            "summary": f"Dashboard user {username} was deleted.",
        }
    )
    return self._json_response({"ok": True, "users": self._user_payload()})

@router.post("/api/users/password")
async def handle_change_password(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
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
    await _save_users(None, self._users)
    await self.orchestrator.logger.log(
        {
            "service": "web",
            "event_type": "user_password_changed",
            "summary": f"Dashboard user {username} password was changed.",
        }
    )
    return self._json_response({"ok": True, "users": self._user_payload()})

@router.post("/api/users/role")
async def handle_change_role(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
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
    await _save_users(None, self._users)
    await self.orchestrator.logger.log(
        {
            "service": "web",
            "event_type": "user_role_changed",
            "summary": f"Dashboard user {username} role was changed to {role}.",
        }
    )
    return self._json_response({"ok": True, "users": self._user_payload()})
