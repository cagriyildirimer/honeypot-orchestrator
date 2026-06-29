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

_arp_table_cache: dict[str, str] = {}
_last_arp_load: float = 0.0

def load_arp_table() -> None:
    global _arp_table_cache, _last_arp_load
    now = time.time()
    if now - _last_arp_load < 10.0:  # reload every 10 seconds at most
        return
    _last_arp_load = now
    
    from pathlib import Path
    new_table = {}
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["arp", "-a"], timeout=2.0).decode("utf-8", errors="ignore")
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    ip_candidate = parts[0]
                    mac_candidate = parts[1].replace("-", ":").lower()
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_candidate):
                        new_table[ip_candidate] = mac_candidate
        else:
            arp_path = Path("/proc/net/arp")
            if arp_path.exists():
                lines = arp_path.read_text(errors="ignore").splitlines()
                if len(lines) > 1:
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_candidate = parts[0]
                            mac_candidate = parts[3].lower()
                            if mac_candidate != "00:00:00:00:00:00":
                                new_table[ip_candidate] = mac_candidate
            else:
                output = subprocess.check_output(["arp", "-n"], timeout=2.0).decode("utf-8", errors="ignore")
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_candidate = parts[0]
                        mac_candidate = parts[3].lower()
                        if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", mac_candidate):
                            new_table[ip_candidate] = mac_candidate
    except Exception:
        pass
    _arp_table_cache = new_table

def resolve_mac(ip: str) -> str:
    if ip in {"127.0.0.1", "::1", "localhost", "unknown"}:
        return "N/A"
    load_arp_table()
    return _arp_table_cache.get(ip, "unknown")


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
        _suspicious_counters.pop(ip, None)
        _rate_limits.pop(ip, None)
        await add_to_blacklist(ip, "Automated ban: reached 100 suspicious events")
        return
    
    now = time.time()
    history = _rate_limits.get(ip, [])
    history = [ts for ts in history if now - ts < 1.0]
    history.append(now)
    _rate_limits[ip] = history
    if len(history) >= 10:
        _suspicious_counters.pop(ip, None)
        _rate_limits.pop(ip, None)
        await add_to_blacklist(ip, "Automated ban: rate limit exceeded (10 events/sec)")
