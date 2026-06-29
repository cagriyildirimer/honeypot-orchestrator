import json
from api.router import router
from database.database import async_session
from sqlalchemy import select
from database.models import SystemSettings
from core.siem_forwarder import siem_forwarder

async def load_siem_config():
    try:
        async with async_session() as session:
            result = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "siem_config"))
            row = result.scalar_one_or_none()
            if row:
                config = json.loads(row.setting_value)
                await siem_forwarder.update_config(config)
    except Exception as e:
        print(f"Error loading SIEM config: {e}")

@router.get("/api/settings/siem")
async def get_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return {"status": 401, "body": b'{"error":"Unauthorized"}', "content_type": "application/json"}
    
    config = {
        "enabled": siem_forwarder.enabled,
        "host": siem_forwarder.host,
        "port": siem_forwarder.port,
        "protocol": siem_forwarder.protocol,
        "scope": siem_forwarder.scope
    }
    return server._json_response(config)

@router.post("/api/settings/siem")
async def set_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return {"status": 401, "body": b'{"error":"Unauthorized"}', "content_type": "application/json"}
    if not server._is_admin(request["cookies"]):
        return server._forbidden_response()
    
    try:
        body = json.loads(request["body"])
        
        async with async_session() as session:
            result = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "siem_config"))
            row = result.scalar_one_or_none()
            
            if row:
                row.setting_value = json.dumps(body)
            else:
                session.add(SystemSettings(setting_key="siem_config", setting_value=json.dumps(body)))
            await session.commit()
            
        await siem_forwarder.update_config(body)
        return server._json_response({"ok": True, "message": "SIEM configuration updated."})
    except Exception as e:
        return server._json_response({"error": str(e)}, status=400)

@router.post("/api/settings/siem/test")
async def test_siem_config_handler(server, request):
    if not server._is_authenticated(request["cookies"]):
        return {"status": 401, "body": b'{"error":"Unauthorized"}', "content_type": "application/json"}
    if not server._is_admin(request["cookies"]):
        return server._forbidden_response()
    
    test_event = {
        "event_type": "siem_test",
        "service": "system",
        "src_ip": "127.0.0.1",
        "summary": "Honeypot Director SIEM connection test."
    }
    
    try:
        await siem_forwarder.forward(test_event)
        return server._json_response({"ok": True, "message": "Test event sent to SIEM."})
    except Exception as e:
        return server._json_response({"error": str(e)}, status=500)
