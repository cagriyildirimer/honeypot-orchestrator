from __future__ import annotations

import time
from datetime import datetime, UTC
from typing import Any
from sqlalchemy import select, delete
from database.database import async_session
from database.models import Whitelist, Blacklist, User, Session as DBSession, SystemSettings

# Whitelist operations
async def get_whitelist() -> list[dict[str, Any]]:
    try:
        async with async_session() as session:
            stmt = select(Whitelist)
            result = await session.execute(stmt)
            return [
                {
                    "ip": r.ip,
                    "description": r.description,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if r.timestamp else "",
                }
                for r in result.scalars().all()
            ]
    except Exception:
        return []

async def is_whitelisted(ip: str) -> bool:
    try:
        async with async_session() as session:
            result = await session.execute(select(Whitelist).where(Whitelist.ip == ip))
            return result.scalars().first() is not None
    except Exception:
        return False

async def add_to_whitelist(ip: str, description: str) -> bool:
    if not ip or not description:
        return False
    try:
        async with async_session() as session:
            exists = await session.execute(select(Whitelist).where(Whitelist.ip == ip))
            if exists.scalars().first() is not None:
                return False
            session.add(Whitelist(ip=ip, description=description, timestamp=datetime.now(UTC)))
            await session.commit()
            return True
    except Exception:
        return False

async def delete_from_whitelist(ip: str) -> bool:
    try:
        async with async_session() as session:
            res = await session.execute(delete(Whitelist).where(Whitelist.ip == ip))
            await session.commit()
            return res.rowcount > 0
    except Exception:
        return False

# Blacklist operations
async def get_blacklist() -> list[dict[str, Any]]:
    try:
        async with async_session() as session:
            stmt = select(Blacklist)
            result = await session.execute(stmt)
            return [
                {
                    "ip": r.ip,
                    "description": r.description,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if r.timestamp else "",
                }
                for r in result.scalars().all()
            ]
    except Exception:
        return []

async def is_blacklisted(ip: str) -> bool:
    try:
        async with async_session() as session:
            res = await session.execute(select(Blacklist).where(Blacklist.ip == ip))
            if res.scalars().first() is not None:
                return True
            
            # Lazy import to avoid circular references during reorganization
            from defense import resolve_mac
            mac = resolve_mac(ip)
            if mac not in {"unknown", "N/A"}:
                res_mac = await session.execute(select(Blacklist).where(Blacklist.ip == mac))
                if res_mac.scalars().first() is not None:
                    return True
            return False
    except Exception:
        return False

async def add_to_blacklist(ip_or_mac: str, description: str) -> bool:
    if not ip_or_mac or not description:
        return False
    try:
        async with async_session() as session:
            exists = await session.execute(select(Blacklist).where(Blacklist.ip == ip_or_mac))
            if exists.scalars().first() is not None:
                return False
                
            session.add(Blacklist(ip=ip_or_mac, description=description, timestamp=datetime.now(UTC)))
            await session.commit()
            
            try:
                from system.net_tuner import apply_firewall_rule
                apply_firewall_rule(ip_or_mac)
            except Exception:
                pass
            return True
    except Exception:
        return False

async def delete_from_blacklist(ip_or_mac: str) -> bool:
    try:
        async with async_session() as session:
            res = await session.execute(delete(Blacklist).where(Blacklist.ip == ip_or_mac))
            await session.commit()
            
            try:
                from system.net_tuner import remove_firewall_rule
                remove_firewall_rule(ip_or_mac)
            except Exception:
                pass
            return res.rowcount > 0
    except Exception:
        return False

# System Settings operations
async def get_system_setting(key: str, default: Any = None) -> Any:
    try:
        async with async_session() as session:
            res = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == key))
            row = res.scalars().first()
            if row:
                return row.setting_value
    except Exception:
        pass
    return default

async def set_system_setting(key: str, value: str) -> None:
    try:
        async with async_session() as session:
            res = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == key))
            row = res.scalars().first()
            now = datetime.now(UTC)
            if row:
                row.setting_value = value
                row.updated_at = now
            else:
                session.add(SystemSettings(setting_key=key, setting_value=value, updated_at=now))
            await session.commit()
    except Exception as e:
        print(f"Error setting SystemSetting {key}: {e}")
