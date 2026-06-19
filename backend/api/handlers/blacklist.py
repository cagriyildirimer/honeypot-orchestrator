from __future__ import annotations
from typing import Any
from http import HTTPStatus
from api.router import router

from web.utils import _decode_json_body
from defense import (
    get_whitelist,
    get_blacklist,
    add_to_whitelist,
    add_to_blacklist,
    delete_from_whitelist,
    delete_from_blacklist,
    is_auto_blacklist_enabled,
    set_auto_blacklist_enabled,
)

@router.get("/api/whitelist")
async def handle_get_whitelist(self, request: dict[str, Any]) -> dict[str, Any]:
    return self._json_response({"whitelist": await get_whitelist()})

@router.post("/api/whitelist")
async def handle_add_whitelist(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
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
    if await add_to_whitelist(ip, description):
        return self._json_response({"ok": True, "whitelist": await get_whitelist()})
    return self._json_response(
        {"error": "Failed to add or already exists."},
        status=HTTPStatus.CONFLICT,
    )

@router.post("/api/whitelist/delete")
async def handle_delete_whitelist(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
    ip = str(payload.get("ip", "")).strip()
    if not ip:
        return self._json_response(
            {"error": "IP is required."},
            status=HTTPStatus.BAD_REQUEST,
        )
    if await delete_from_whitelist(ip):
        return self._json_response({"ok": True, "whitelist": await get_whitelist()})
    return self._json_response(
        {"error": "Not found in whitelist."},
        status=HTTPStatus.NOT_FOUND,
    )

@router.get("/api/blacklist")
async def handle_get_blacklist(self, request: dict[str, Any]) -> dict[str, Any]:
    return self._json_response({"blacklist": await get_blacklist()})

@router.post("/api/blacklist")
async def handle_add_blacklist(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
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
    if await add_to_blacklist(ip, description):
        return self._json_response({"ok": True, "blacklist": await get_blacklist()})
    return self._json_response(
        {"error": "Failed to add or already exists."},
        status=HTTPStatus.CONFLICT,
    )

@router.post("/api/blacklist/delete")
async def handle_delete_blacklist(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
    ip = str(payload.get("ip", "")).strip()
    if not ip:
        return self._json_response(
            {"error": "IP/MAC is required."},
            status=HTTPStatus.BAD_REQUEST,
        )
    if await delete_from_blacklist(ip):
        return self._json_response({"ok": True, "blacklist": await get_blacklist()})
    return self._json_response(
        {"error": "Not found in blacklist."},
        status=HTTPStatus.NOT_FOUND,
    )

@router.get("/api/settings/auto-blacklist")
async def handle_get_auto_blacklist(self, request: dict[str, Any]) -> dict[str, Any]:
    enabled = await is_auto_blacklist_enabled()
    return self._json_response({"auto_blacklist_enabled": enabled})

@router.post("/api/settings/auto-blacklist")
async def handle_set_auto_blacklist(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
    if not self._is_admin(cookies):
        return self._forbidden_response()
    payload = _decode_json_body(request["body"])
    enabled = bool(payload.get("enabled", True))
    await set_auto_blacklist_enabled(enabled)
    return self._json_response({"ok": True, "auto_blacklist_enabled": enabled})
