from __future__ import annotations

import json
import re
import subprocess
import platform
import threading
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

# Global thread-safety lock for files
_lock = threading.Lock()
# In-memory counter for security-relevant suspicious events per IP
_suspicious_counters: dict[str, int] = {}
_last_cleanup: float = 0.0

WHITELIST_PATH = Path("logs/whitelist.json")
BLACKLIST_PATH = Path("logs/blacklist.json")


def _ensure_files() -> None:
    for path in (WHITELIST_PATH, BLACKLIST_PATH):
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"entries": []}, f, indent=2, sort_keys=True)


def get_whitelist() -> list[dict[str, Any]]:
    _ensure_files()
    with _lock:
        try:
            with open(WHITELIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("entries", [])
        except Exception:
            return []


def get_blacklist() -> list[dict[str, Any]]:
    _ensure_files()
    with _lock:
        try:
            with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("entries", [])
        except Exception:
            return []


def save_whitelist(entries: list[dict[str, Any]]) -> None:
    _ensure_files()
    with _lock:
        with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
            json.dump({"entries": entries}, f, indent=2, sort_keys=True)


def save_blacklist(entries: list[dict[str, Any]]) -> None:
    _ensure_files()
    with _lock:
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            json.dump({"entries": entries}, f, indent=2, sort_keys=True)


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


def is_whitelisted(ip: str) -> bool:
    entries = get_whitelist()
    return any(item.get("ip") == ip for item in entries)


def is_blacklisted(ip: str) -> bool:
    entries = get_blacklist()
    # 1. IP matches directly
    if any(item.get("ip") == ip for item in entries):
        return True
    # 2. Check if peer MAC matches a banned MAC entry
    mac = resolve_mac(ip)
    if mac not in {"unknown", "N/A"}:
        if any(item.get("ip") == mac for item in entries):
            return True
    return False


def add_to_whitelist(ip: str, description: str) -> bool:
    if not ip or not description:
        return False
    entries = get_whitelist()
    if any(item.get("ip") == ip for item in entries):
        return False
    entries.append({
        "ip": ip,
        "description": description,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    })
    save_whitelist(entries)
    return True


def add_to_blacklist(ip_or_mac: str, description: str) -> bool:
    if not ip_or_mac or not description:
        return False
    entries = get_blacklist()
    if any(item.get("ip") == ip_or_mac for item in entries):
        return False
    entries.append({
        "ip": ip_or_mac,
        "description": description,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    })
    save_blacklist(entries)
    return True


def delete_from_whitelist(ip: str) -> bool:
    entries = get_whitelist()
    filtered = [item for item in entries if item.get("ip") != ip]
    if len(filtered) == len(entries):
        return False
    save_whitelist(filtered)
    return True


def delete_from_blacklist(ip_or_mac: str) -> bool:
    entries = get_blacklist()
    filtered = [item for item in entries if item.get("ip") != ip_or_mac]
    if len(filtered) == len(entries):
        return False
    save_blacklist(filtered)
    return True


import time

_rate_limits: dict[str, list[float]] = {}

def _cleanup_memory_structs() -> None:
    global _last_cleanup
    now = time.time()
    if now - _last_cleanup < 600:  # Every 10 minutes
        return
    _last_cleanup = now

    # Cleanup rate limits older than 1 second
    for ip in list(_rate_limits.keys()):
        history = [ts for ts in _rate_limits[ip] if now - ts < 1.0]
        if not history:
            del _rate_limits[ip]
        else:
            _rate_limits[ip] = history
            
    # Cap suspicious counters to prevent infinite memory growth
    if len(_suspicious_counters) > 10000:
        _suspicious_counters.clear()

def record_suspicious_event(ip: str) -> None:
    _cleanup_memory_structs()
    if not ip or ip in {"127.0.0.1", "::1", "localhost", "unknown"}:
        return
    if is_whitelisted(ip):
        return
    
    current = _suspicious_counters.get(ip, 0) + 1
    _suspicious_counters[ip] = current
    if current >= 100:
        add_to_blacklist(ip, "Automated ban: reached 100 suspicious events")
        return
    
    # Sliding window rate limiting: 10 events / second
    now = time.time()
    history = _rate_limits.get(ip, [])
    history = [ts for ts in history if now - ts < 1.0]
    history.append(now)
    _rate_limits[ip] = history
    if len(history) >= 10:
        add_to_blacklist(ip, "Automated ban: rate limit exceeded (10 events/sec)")
