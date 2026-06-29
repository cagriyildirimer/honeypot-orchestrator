import json
import uuid
from http import HTTPStatus
from api.router import router
from database.database import async_session
from sqlalchemy import select
from database.models import SystemSettings
from core.siem_forwarder import siem_forwarder
from web.utils import _decode_json_body

def normalize_siem_payload(payload):
    configs = siem_forwarder._normalize_configs(payload)
    seen = set()
    normalized = []
    for config in configs:
        if not config.get("id") or config["id"] in seen:
            config["id"] = f"siem-{uuid.uuid4().hex[:10]}"
        seen.add(config["id"])
        normalized.append(config)
    return {"configs": normalized}

async def load_siem_config():
    try:
        async with async_session() as session:
            result = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "siem_config"))
            row = result.scalar_one_or_none()
            if row:
                config = json.loads(row.setting_value)
                await siem_forwarder.update_config(normalize_siem_payload(config))
    except Exception as e:
        print(f"Error loading SIEM config: {e}")

@router.get("/api/settings/siem")
async def get_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return server._json_response({"error": "Unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
    
    return server._json_response({"configs": siem_forwarder.configs})

@router.post("/api/settings/siem")
async def set_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return server._json_response({"error": "Unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
    if not server._is_admin(request["cookies"]):
        return server._forbidden_response()
    
    try:
        body = _decode_json_body(request["body"])
        normalized = normalize_siem_payload(body)
        
        async with async_session() as session:
            result = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "siem_config"))
            row = result.scalar_one_or_none()
            
            if row:
                row.setting_value = json.dumps(normalized)
            else:
                session.add(SystemSettings(setting_key="siem_config", setting_value=json.dumps(normalized)))
            await session.commit()
            
        await siem_forwarder.update_config(normalized)
        return server._json_response({"ok": True, "message": "SIEM configuration updated.", "configs": siem_forwarder.configs})
    except Exception as e:
        return server._json_response({"error": str(e)}, status=HTTPStatus.BAD_REQUEST)

@router.post("/api/settings/siem/test")
async def test_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return server._json_response({"error": "Unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
    if not server._is_admin(request["cookies"]):
        return server._forbidden_response()
    
    test_event = {
        "event_type": "siem_test",
        "service": "system",
        "src_ip": "127.0.0.1",
        "summary": "Honeypot Director SIEM connection test."
    }
    
    try:
        body = _decode_json_body(request["body"])
        target_id = str(body.get("id", ""))
        target = None
        if target_id:
            target = next((config for config in siem_forwarder.configs if config.get("id") == target_id), None)
        if target is None:
            enabled_targets = [config for config in siem_forwarder.configs if config.get("enabled")]
            if len(enabled_targets) == 1:
                target = enabled_targets[0]
        if target is None:
            return server._json_response({"error": "Select an enabled SIEM target to test."}, status=HTTPStatus.BAD_REQUEST)
        await siem_forwarder.forward_to(target, test_event)
        return server._json_response({"ok": True, "message": "Test event sent to SIEM."})
    except Exception as e:
        return server._json_response({"error": str(e)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)
