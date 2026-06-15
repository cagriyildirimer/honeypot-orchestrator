"""Threat Intelligence enrichment for top attacker IPs.

Only the top-N external IPs are enriched.  Private/RFC-1918 IPs and the
honeypot's own subnet (auto-detected from the first two octets of every
candidate IP) are silently excluded.

All results are cached in-memory for 1 hour (thread-safe).
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
import urllib.request
from typing import Any

from geo import PRIVATE_PREFIXES, bulk_lookup

# ---------------------------------------------------------------------------
# Cloud provider CIDR blocks (major ranges, embedded)
# ---------------------------------------------------------------------------
_CLOUD_CIDRS: dict[str, list[str]] = {
    "AWS": [
        "3.0.0.0/8", "13.32.0.0/12", "13.48.0.0/13", "13.56.0.0/14",
        "15.177.0.0/16", "15.230.0.0/16", "18.0.0.0/8", "34.192.0.0/10",
        "35.152.0.0/13", "44.192.0.0/10", "50.16.0.0/14", "52.0.0.0/10",
        "54.64.0.0/10", "54.128.0.0/10", "54.192.0.0/10",
        "99.77.0.0/16", "99.150.0.0/16",
    ],
    "GCP": [
        "8.34.208.0/20", "8.35.192.0/20", "23.236.48.0/20", "23.251.128.0/19",
        "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/14",
        "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17",
        "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13",
        "104.196.0.0/14", "107.167.160.0/19", "107.178.192.0/18",
        "108.59.80.0/20", "108.170.192.0/18",
        "130.211.0.0/16", "146.148.0.0/17",
    ],
    "Azure": [
        "13.64.0.0/11", "13.96.0.0/13", "13.104.0.0/14",
        "20.0.0.0/8", "23.96.0.0/13", "40.64.0.0/10",
        "51.104.0.0/14", "51.120.0.0/14", "52.96.0.0/12",
        "52.112.0.0/14", "52.120.0.0/14", "52.136.0.0/13",
        "52.148.0.0/14", "52.152.0.0/13", "52.160.0.0/11",
        "52.224.0.0/11", "65.52.0.0/14", "70.37.0.0/17",
        "104.40.0.0/13", "104.208.0.0/13", "137.116.0.0/15",
        "168.61.0.0/16", "168.62.0.0/15",
    ],
    "DigitalOcean": [
        "64.225.0.0/16", "67.205.128.0/17", "68.183.0.0/16",
        "104.131.0.0/16", "104.236.0.0/16", "128.199.0.0/16",
        "134.122.0.0/16", "134.209.0.0/16", "137.184.0.0/16",
        "138.68.0.0/16", "138.197.0.0/16", "139.59.0.0/16",
        "142.93.0.0/16", "143.110.0.0/16", "143.198.0.0/16",
        "146.190.0.0/16", "157.230.0.0/16", "157.245.0.0/16",
        "159.65.0.0/16", "159.89.0.0/16", "159.203.0.0/16",
        "161.35.0.0/16", "162.243.0.0/16", "163.47.8.0/21",
        "164.90.0.0/16", "164.92.0.0/16", "165.22.0.0/16",
        "165.227.0.0/16", "167.71.0.0/16", "167.172.0.0/16",
        "170.64.0.0/16", "174.138.0.0/16", "178.128.0.0/16",
        "178.62.0.0/16", "188.166.0.0/16", "192.241.128.0/17",
        "198.199.64.0/18", "204.48.16.0/20", "206.189.0.0/16",
        "209.97.128.0/17",
    ],
    "OVH": [
        "5.39.0.0/17", "5.135.0.0/16", "5.196.0.0/16",
        "37.59.0.0/16", "37.187.0.0/16", "46.105.0.0/16",
        "51.38.0.0/15", "51.68.0.0/15", "51.75.0.0/16",
        "51.77.0.0/16", "51.79.0.0/16", "51.81.0.0/16",
        "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
        "51.161.0.0/16", "51.178.0.0/16", "51.195.0.0/16",
        "51.210.0.0/16", "51.254.0.0/15", "54.36.0.0/14",
        "91.134.0.0/16", "92.222.0.0/16", "135.125.0.0/16",
        "137.74.0.0/16", "141.94.0.0/16", "141.95.0.0/16",
        "144.217.0.0/16", "145.239.0.0/16", "147.135.0.0/16",
        "149.56.0.0/16", "151.80.0.0/16", "158.69.0.0/16",
        "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/15",
        "185.12.32.0/22", "188.165.0.0/16", "193.70.0.0/16",
        "198.27.64.0/18", "198.100.144.0/20",
        "213.186.32.0/19", "213.251.128.0/18",
    ],
    "Linode": [
        "23.92.16.0/20", "23.239.0.0/18", "45.33.0.0/17",
        "45.56.64.0/18", "45.79.0.0/16", "50.116.0.0/18",
        "66.175.208.0/20", "66.228.32.0/19", "69.164.192.0/19",
        "72.14.176.0/20", "74.207.224.0/19", "85.159.208.0/21",
        "96.126.96.0/19", "97.107.128.0/20",
        "103.3.60.0/22", "109.74.192.0/20",
        "139.144.0.0/16", "139.162.0.0/16", "143.42.0.0/16",
        "172.104.0.0/15", "172.232.0.0/14",
        "173.230.128.0/19", "173.255.192.0/18",
        "178.79.128.0/17", "185.3.92.0/22",
        "192.155.80.0/20", "194.195.208.0/20",
        "198.58.96.0/19", "198.74.48.0/20",
    ],
}

# Pre-compiled into ipaddress networks for fast matching
_CLOUD_NETWORKS: list[tuple[str, ipaddress.IPv4Network]] = []
_CLOUD_NETWORKS_READY = False
_cloud_init_lock = threading.Lock()


def _init_cloud_networks() -> None:
    global _CLOUD_NETWORKS_READY
    if _CLOUD_NETWORKS_READY:
        return
    with _cloud_init_lock:
        if _CLOUD_NETWORKS_READY:
            return
        for provider, cidrs in _CLOUD_CIDRS.items():
            for cidr in cidrs:
                try:
                    _CLOUD_NETWORKS.append((provider, ipaddress.IPv4Network(cidr, strict=False)))
                except ValueError:
                    continue
        _CLOUD_NETWORKS_READY = True


def _match_cloud_provider(ip_str: str) -> str:
    """Return cloud provider name or empty string."""
    _init_cloud_networks()
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return ""
    for provider, network in _CLOUD_NETWORKS:
        if addr in network:
            return provider
    return ""


# ---------------------------------------------------------------------------
# Tor exit node list (downloaded once per day)
# ---------------------------------------------------------------------------
_tor_exit_nodes: set[str] = set()
_tor_last_fetch: float = 0.0
_tor_lock = threading.Lock()
_TOR_REFRESH_INTERVAL = 86400  # 24 hours


def _refresh_tor_exit_nodes() -> None:
    global _tor_exit_nodes, _tor_last_fetch
    now = time.time()
    if now - _tor_last_fetch < _TOR_REFRESH_INTERVAL:
        return
    with _tor_lock:
        if now - _tor_last_fetch < _TOR_REFRESH_INTERVAL:
            return
        try:
            req = urllib.request.Request(
                "https://check.torproject.org/torbulkexitlist",
                headers={"User-Agent": "HoneypotOrchestrator/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = resp.read().decode("utf-8", errors="replace")
            nodes: set[str] = set()
            for line in data.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    nodes.add(line)
            _tor_exit_nodes = nodes
            _tor_last_fetch = time.time()
        except Exception:
            # On failure, keep the old set and try again later (after 5 min)
            if _tor_last_fetch == 0.0:
                _tor_last_fetch = time.time() - _TOR_REFRESH_INTERVAL + 300


def _is_tor_exit(ip_str: str) -> bool:
    _refresh_tor_exit_nodes()
    return ip_str in _tor_exit_nodes




# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def _reverse_dns(ip_str: str) -> str:
    try:
        return socket.getfqdn(ip_str)
    except Exception:
        return ip_str


# ---------------------------------------------------------------------------
# AbuseIPDB (optional, requires API key)
# ---------------------------------------------------------------------------

def _query_abuseipdb(ip_str: str, api_key: str) -> int | str:
    """Return abuse confidence score (0-100) or 'N/A'."""
    if not api_key:
        return "N/A"
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_str}&maxAgeInDays=90",
            headers={
                "Key": api_key,
                "Accept": "application/json",
                "User-Agent": "HoneypotOrchestrator/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return int(data.get("data", {}).get("abuseConfidenceScore", 0))
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# GreyNoise (optional, requires API key)
# ---------------------------------------------------------------------------

def _query_greynoise(ip_str: str, api_key: str) -> str:
    """Return classification string: 'malicious', 'benign', 'unknown', or 'N/A'."""
    if not api_key:
        return "N/A"
    try:
        req = urllib.request.Request(
            f"https://api.greynoise.io/v3/community/{ip_str}",
            headers={
                "key": api_key,
                "Accept": "application/json",
                "User-Agent": "HoneypotOrchestrator/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return str(data.get("classification", "unknown")).lower()
    except Exception:
        return "N/A"


# ---------------------------------------------------------------------------
# ASN / Org / GeoIP enrichment (delegated to geo.bulk_lookup)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Subnet detection — exclude IPs sharing the first two octets with the honeypot
# ---------------------------------------------------------------------------

def _detect_honeypot_prefix(host_ip: str) -> str:
    """Return first two octets of the honeypot's bind address (e.g. '192.168.')."""
    if not host_ip or host_ip in {"0.0.0.0", "::", "localhost", "127.0.0.1"}:
        return ""
    parts = host_ip.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}."
    return ""


def _is_private_or_local(ip_str: str, honeypot_prefix: str) -> bool:
    if not ip_str or ip_str in {"unknown", "localhost"}:
        return True
    if ip_str.startswith(PRIVATE_PREFIXES):
        return True
    if honeypot_prefix and ip_str.startswith(honeypot_prefix):
        return True
    return False


# ---------------------------------------------------------------------------
# Main enrichment function
# ---------------------------------------------------------------------------

def _enrich_ip_sync(ip: str, geo: dict[str, Any], abuseipdb_key: str, greynoise_key: str) -> dict[str, Any]:
    return {
        "ip": ip,
        "rdns": _reverse_dns(ip),
        "asn": geo.get("asn", ""),
        "org": geo.get("org", ""),
        "country": geo.get("country", "Unknown"),
        "countryCode": geo.get("countryCode", "XX"),
        "city": geo.get("city", ""),
        "lat": geo.get("lat", 0),
        "lon": geo.get("lon", 0),
        "is_tor": _is_tor_exit(ip),
        "cloud_provider": _match_cloud_provider(ip),
        "abuse_score": _query_abuseipdb(ip, abuseipdb_key),
        "greynoise_class": _query_greynoise(ip, greynoise_key),
    }

async def enrich_top_ips(
    ip_counts: dict[str, int],
    *,
    honeypot_host: str = "",
    abuseipdb_key: str = "",
    greynoise_key: str = "",
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Enrich the top *limit* external IPs with threat intelligence data.

    Returns a list of dicts sorted by event count (descending).
    """
    honeypot_prefix = _detect_honeypot_prefix(honeypot_host)

    # Filter out private / honeypot-subnet IPs
    external: dict[str, int] = {
        ip: count
        for ip, count in ip_counts.items()
        if not _is_private_or_local(ip, honeypot_prefix)
    }

    # Top N by event count
    top_ips = sorted(external.items(), key=lambda x: x[1], reverse=True)[:limit]
    if not top_ips:
        return []

    ip_list = [ip for ip, _ in top_ips]

    import asyncio
    from database import async_session
    from models import ThreatIntelCache
    from sqlalchemy import select
    from datetime import datetime, UTC

    # Check cache first
    cached: dict[str, dict[str, Any]] = {}
    to_enrich: list[str] = []

    try:
        async with async_session() as session:
            stmt = select(ThreatIntelCache).where(ThreatIntelCache.ip.in_(ip_list))
            result = await session.execute(stmt)
            records = result.scalars().all()
            now = datetime.now(UTC)
            db_cached = {}
            for r in records:
                updated_at = r.updated_at.replace(tzinfo=UTC) if r.updated_at.tzinfo is None else r.updated_at
                if (now - updated_at).total_seconds() <= 3600:
                    db_cached[r.ip] = r.data
                    
            for ip in ip_list:
                if ip in db_cached:
                    cached[ip] = db_cached[ip]
                else:
                    to_enrich.append(ip)
    except Exception as e:
        print(f"Error accessing DB for TI cache: {e}")
        to_enrich = ip_list

    # Batch GeoIP / ASN for cache misses
    geo_data: dict[str, dict[str, Any]] = {}
    if to_enrich:
        geo_data = await asyncio.to_thread(bulk_lookup, to_enrich)

    # Enrich each IP that wasn't cached

    # Fetch API keys from DB
    db_abuse_key, db_grey_key = await _get_api_keys_from_db()
    abuseipdb_key = db_abuse_key or abuseipdb_key
    greynoise_key = db_grey_key or greynoise_key

    if to_enrich:
        try:
            async with async_session() as session:
                now = datetime.now(UTC)
                for ip in to_enrich:
                    geo = geo_data.get(ip, {})
                    entry = await asyncio.to_thread(
                        _enrich_ip_sync, ip, geo, abuseipdb_key, greynoise_key
                    )
                    cached[ip] = entry
                    
                    cache_entry = await session.get(ThreatIntelCache, ip)
                    if cache_entry:
                        cache_entry.data = entry
                        cache_entry.updated_at = now
                    else:
                        session.add(ThreatIntelCache(ip=ip, data=entry, updated_at=now))
                
                await session.commit()
        except Exception as e:
            print(f"Error writing to DB for TI cache: {e}")
            for ip in to_enrich:
                geo = geo_data.get(ip, {})
                entry = await asyncio.to_thread(_enrich_ip_sync, ip, geo, abuseipdb_key, greynoise_key)
                cached[ip] = entry

    # Build final result list, sorted by event count
    results: list[dict[str, Any]] = []
    for ip, count in top_ips:
        entry = dict(cached.get(ip, {"ip": ip}))
        entry["event_count"] = count
        results.append(entry)

    return results

async def get_cached_top_ips(ip_counts: dict[str, int], honeypot_host: str = "", limit: int = 10) -> list[dict[str, Any]]:
    honeypot_prefix = _detect_honeypot_prefix(honeypot_host)
    external: dict[str, int] = {
        ip: count
        for ip, count in ip_counts.items()
        if not _is_private_or_local(ip, honeypot_prefix)
    }
    top_ips = sorted(external.items(), key=lambda x: x[1], reverse=True)[:limit]
    if not top_ips:
        return []
    ip_list = [ip for ip, _ in top_ips]

    from database import async_session
    from models import ThreatIntelCache
    from sqlalchemy import select
    
    cached: dict[str, dict[str, Any]] = {}
    try:
        async with async_session() as session:
            stmt = select(ThreatIntelCache).where(ThreatIntelCache.ip.in_(ip_list))
            result = await session.execute(stmt)
            for r in result.scalars().all():
                cached[r.ip] = r.data
    except Exception as e:
        print(f"Error accessing DB for TI cache: {e}")

    results: list[dict[str, Any]] = []
    for ip, count in top_ips:
        if ip in cached:
            entry = dict(cached[ip])
        else:
            entry = {"ip": ip, "status": "Pending Analysis"}
        entry["event_count"] = count
        results.append(entry)

    return results



from crypto_utils import decrypt_value
from models import SystemSettings

async def _get_api_keys_from_db():
    abuse_key = ""
    grey_key = ""
    try:
        from database import async_session
        async with async_session() as session:
            from sqlalchemy import select
            res = await session.execute(select(SystemSettings).where(SystemSettings.setting_key.in_(["ti_abuseipdb_key", "ti_greynoise_key"])))
            for row in res.scalars().all():
                if row.setting_key == "ti_abuseipdb_key":
                    abuse_key = decrypt_value(row.setting_value)
                elif row.setting_key == "ti_greynoise_key":
                    grey_key = decrypt_value(row.setting_value)
    except Exception as e:
        print(f"Error reading keys from DB: {e}")
    return abuse_key, grey_key

