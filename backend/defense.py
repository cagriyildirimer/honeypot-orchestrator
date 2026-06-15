from __future__ import annotations

import re
import subprocess
import platform
import time
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select, delete
from database import async_session
from models import Whitelist, Blacklist

_suspicious_counters: dict[str, int] = {}
_rate_limits: dict[str, list[float]] = {}
_last_cleanup: float = 0.0

def resolve_mac(ip: str) -> str:
    if ip in {"127.0.0.1", "::1", "localhost", "unknown"}:
        return "N/A"
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["arp", "-a", ip], timeout=2.0).decode("utf-8", errors="ignore")
            match = re.search(
                r"([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                output,
            )
            if match:
                return match.group(1).replace("-", ":").lower()
        else:
            output = subprocess.check_output(["arp", "-n", ip], timeout=2.0).decode("utf-8", errors="ignore")
            match = re.search(
                r"([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})",
                output,
            )
            if match:
                return match.group(1).lower()
    except Exception:
        pass
    return "unknown"


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


async def is_whitelisted(ip: str) -> bool:
    try:
        async with async_session() as session:
            result = await session.execute(select(Whitelist).where(Whitelist.ip == ip))
            return result.scalars().first() is not None
    except Exception:
        return False


async def is_blacklisted(ip: str) -> bool:
    try:
        async with async_session() as session:
            res = await session.execute(select(Blacklist).where(Blacklist.ip == ip))
            if res.scalars().first() is not None:
                return True
            
            mac = resolve_mac(ip)
            if mac not in {"unknown", "N/A"}:
                res_mac = await session.execute(select(Blacklist).where(Blacklist.ip == mac))
                if res_mac.scalars().first() is not None:
                    return True
            return False
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
                from net_tuner import apply_firewall_rule
                apply_firewall_rule(ip_or_mac)
            except Exception:
                pass
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


async def delete_from_blacklist(ip_or_mac: str) -> bool:
    try:
        async with async_session() as session:
            res = await session.execute(delete(Blacklist).where(Blacklist.ip == ip_or_mac))
            await session.commit()
            
            try:
                from net_tuner import remove_firewall_rule
                remove_firewall_rule(ip_or_mac)
            except Exception:
                pass
            return res.rowcount > 0
    except Exception:
        return False


def _cleanup_memory_structs() -> None:
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < 600:
        return
    _last_cleanup = now

    for ip in list(_rate_limits.keys()):
        history = [ts for ts in _rate_limits[ip] if now - ts < 1.0]
        if not history:
            del _rate_limits[ip]
        else:
            _rate_limits[ip] = history
            
    if len(_suspicious_counters) > 10000:
        _suspicious_counters.clear()


async def record_suspicious_event(ip: str) -> None:
    _cleanup_memory_structs()
    if not ip or ip in {"127.0.0.1", "::1", "localhost", "unknown"}:
        return
    if await is_whitelisted(ip):
        return
    
    current = _suspicious_counters.get(ip, 0) + 1
    _suspicious_counters[ip] = current
    if current >= 100:
        await add_to_blacklist(ip, "Automated ban: reached 100 suspicious events")
        return
    
    now = time.time()
    history = _rate_limits.get(ip, [])
    history = [ts for ts in history if now - ts < 1.0]
    history.append(now)
    _rate_limits[ip] = history
    if len(history) >= 10:
        await add_to_blacklist(ip, "Automated ban: rate limit exceeded (10 events/sec)")
