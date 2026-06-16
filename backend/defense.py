from __future__ import annotations

import re
import subprocess
import platform
import time
from datetime import datetime, UTC
from typing import Any

from database.repository import (
    get_whitelist,
    get_blacklist,
    is_whitelisted,
    is_blacklisted,
    add_to_whitelist,
    add_to_blacklist,
    delete_from_whitelist,
    delete_from_blacklist,
    get_system_setting,
    set_system_setting,
)

_suspicious_counters: dict[str, int] = {}
_rate_limits: dict[str, list[float]] = {}
_last_cleanup: float = 0.0
_auto_blacklist_enabled_cached: bool | None = None
_last_setting_check: float = 0.0

async def is_auto_blacklist_enabled() -> bool:
    global _auto_blacklist_enabled_cached, _last_setting_check
    now = time.time()
    if _auto_blacklist_enabled_cached is not None and now - _last_setting_check < 5.0:
        return _auto_blacklist_enabled_cached
    val = await get_system_setting("auto_blacklist_enabled")
    if val is not None:
        _auto_blacklist_enabled_cached = val == "true"
    else:
        _auto_blacklist_enabled_cached = True
    _last_setting_check = now
    return _auto_blacklist_enabled_cached

async def set_auto_blacklist_enabled(enabled: bool) -> None:
    global _auto_blacklist_enabled_cached, _last_setting_check
    val_str = "true" if enabled else "false"
    await set_system_setting("auto_blacklist_enabled", val_str)
    _auto_blacklist_enabled_cached = enabled
    _last_setting_check = time.time()

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


# Whitelist and Blacklist operations are imported from database.repository



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
    if not await is_auto_blacklist_enabled():
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
