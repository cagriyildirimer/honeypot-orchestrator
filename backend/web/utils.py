from __future__ import annotations

import json
import hashlib
import secrets
from http import HTTPStatus
from pathlib import Path
from typing import Any
from datetime import datetime, UTC

from sqlalchemy import select, delete, desc
from database.database import async_session
from database.models import Event, User

ROLE_ADMIN = "admin"
ROLE_VIEWER = "viewer"
USER_ROLES = {ROLE_ADMIN, ROLE_VIEWER}

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
                    if isinstance(r.details, dict):
                        safe_details = {
                            k: v for k, v in r.details.items()
                            if k not in {"id", "timestamp", "service", "event_type", "src_ip", "src_port", "summary"}
                        }
                        event_data.update(safe_details)
                records.append(event_data)
            return records
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
            stmt = select(User)
            result = await session.execute(stmt)
            db_users = {u.username: u for u in result.scalars().all()}

            for username, data in users.items():
                if username in db_users:
                    db_user = db_users[username]
                    db_user.password_hash = data["password"]
                    db_user.role = data["role"]
                else:
                    session.add(User(
                        username=username,
                        password_hash=data["password"],
                        role=data["role"]
                    ))

            for username, db_user in db_users.items():
                if username not in users:
                    await session.delete(db_user)

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


def _build_cookie(name: str, value: str, *, max_age: int | None = None, secure: bool = False) -> str:
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Strict"]
    if max_age is not None:
        parts.append(f"Max-Age={max_age}")
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def _request_display_host(request: dict[str, Any]) -> str:
    import os
    lan_ip = os.environ.get("HONEYPOT_LAN_IP")
    if lan_ip:
        return lan_ip.strip()
        
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
