from __future__ import annotations
from typing import Any
from http import HTTPStatus
from api.router import router

from web.server import _decode_json_body

@router.post("/api/services/toggle")
async def handle_services_toggle(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
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

@router.post("/api/profile")
async def handle_profile_post(self, request: dict[str, Any]) -> dict[str, Any]:
    cookies = request["cookies"]
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
