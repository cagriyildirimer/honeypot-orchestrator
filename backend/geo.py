"""Lightweight GeoIP lookup using ip-api.com (free, no key needed)."""
from __future__ import annotations

import json
import urllib.request
import threading
from typing import Any

_cache: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()

PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "127.", "0.", "::1")


def lookup(ip: str) -> dict[str, Any]:
    if not ip or ip in {"unknown", "localhost"} or ip.startswith(PRIVATE_PREFIXES):
        return {"country": "Private", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
    with _lock:
        if ip in _cache:
            return _cache[ip]
    try:
        req = urllib.request.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp",
            headers={"User-Agent": "HoneypotOrchestrator/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") == "success":
            result = {
                "country": data.get("country", ""),
                "countryCode": data.get("countryCode", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
            }
        else:
            result = {"country": "Unknown", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
    except Exception:
        result = {"country": "Unknown", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
    with _lock:
        if len(_cache) < 5000:
            _cache[ip] = result
    return result


def bulk_lookup(ips: list[str]) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    to_fetch: list[str] = []
    for ip in ips:
        if not ip or ip in {"unknown", "localhost"} or ip.startswith(PRIVATE_PREFIXES):
            results[ip] = {"country": "Private", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
        elif ip in _cache:
            results[ip] = _cache[ip]
        else:
            to_fetch.append(ip)
    # ip-api.com batch endpoint (max 100 per request)
    for i in range(0, len(to_fetch), 100):
        batch = to_fetch[i:i + 100]
        try:
            payload = json.dumps([{"query": ip, "fields": "status,query,country,countryCode,city,lat,lon,isp"} for ip in batch]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "HoneypotOrchestrator/1.0"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                batch_data = json.loads(resp.read().decode("utf-8"))
            for entry in batch_data:
                ip = entry.get("query", "")
                if entry.get("status") == "success":
                    result = {
                        "country": entry.get("country", ""),
                        "countryCode": entry.get("countryCode", ""),
                        "lat": entry.get("lat", 0),
                        "lon": entry.get("lon", 0),
                        "city": entry.get("city", ""),
                        "isp": entry.get("isp", ""),
                    }
                else:
                    result = {"country": "Unknown", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
                results[ip] = result
                with _lock:
                    if len(_cache) < 5000:
                        _cache[ip] = result
        except Exception:
            for ip in batch:
                results[ip] = {"country": "Unknown", "countryCode": "XX", "lat": 0, "lon": 0, "city": "", "isp": ""}
    return results
