#!/usr/bin/env python3
"""Threat Intel pipeline test script.

Generates simulated attacker traffic to honeypot services and then queries
the /api/threat-intel endpoint to verify enrichment is working correctly.

Usage:
    python test_threat_intel.py [--host 127.0.0.1] [--web-port 8000]

The script performs two phases:
  Phase 1 - Unit tests on threat_intel.py functions (no network needed)
  Phase 2 - Integration: sends fake connections to honeypot services,
             waits a few seconds, then queries the threat-intel API
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import sys
import textwrap
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Rich-ish console helpers (no dependency)
# ---------------------------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"

def _ok(msg: str) -> None:
    print(f"  {GREEN}[OK]{RESET} {msg}")

def _fail(msg: str) -> None:
    print(f"  {RED}[FAIL]{RESET} {msg}")

def _info(msg: str) -> None:
    print(f"  {CYAN}[INFO]{RESET} {msg}")

def _warn(msg: str) -> None:
    print(f"  {YELLOW}[WARN]{RESET} {msg}")

def _header(title: str) -> None:
    print(f"\n{BOLD}{'-' * 60}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'-' * 60}{RESET}")

# ---------------------------------------------------------------------------
# Known "external" IPs to simulate attacks from
# These are real-world public IPs from various cloud/hosting providers
# that the enrichment pipeline should be able to look up.
# ---------------------------------------------------------------------------
FAKE_ATTACKER_IPS = [
    "45.33.32.156",     # Linode (Nmap scanme.nmap.org)
    "104.131.0.69",     # DigitalOcean
    "13.56.200.100",    # AWS
    "35.200.100.50",    # GCP
    "51.38.100.200",    # OVH
    "185.220.101.1",    # Known Tor exit node (may or may not be active)
    "193.70.50.42",     # OVH
    "64.225.50.10",     # DigitalOcean
    "54.36.100.200",    # OVH
    "34.70.100.50",     # GCP
    "20.50.100.200",    # Azure
    "139.162.100.50",   # Linode
]

# ---------------------------------------------------------------------------
# Phase 1: Unit tests for threat_intel.py (offline / no running services)
# ---------------------------------------------------------------------------
def phase1_unit_tests() -> tuple[int, int]:
    """Test threat_intel.py internal functions directly."""
    _header("Phase 1 - Unit Tests (threat_intel.py)")
    passed = 0
    failed = 0

    # Add parent dir to path so we can import
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    import asyncio
    from database.database import init_db
    try:
        asyncio.run(init_db())
        _ok("Database initialized successfully")
        passed += 1
    except Exception as e:
        _warn(f"Failed to initialize database: {e}")

    from threat_intel import (
        _is_private_or_local,
        _match_cloud_provider,
        _detect_honeypot_prefix,
        enrich_top_ips,
    )

    # --- Test 1: Private IP detection ---
    print(f"\n  {DIM}Testing _is_private_or_local ...{RESET}")
    private_ips = ["10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1", "0.0.0.0"]
    public_ips = ["8.8.8.8", "1.1.1.1", "45.33.32.156", "104.131.0.69"]

    for ip in private_ips:
        if _is_private_or_local(ip, ""):
            _ok(f"{ip} correctly identified as private")
            passed += 1
        else:
            _fail(f"{ip} was NOT detected as private!")
            failed += 1

    for ip in public_ips:
        if not _is_private_or_local(ip, ""):
            _ok(f"{ip} correctly identified as public")
            passed += 1
        else:
            _fail(f"{ip} was incorrectly detected as private!")
            failed += 1

    # --- Test 2: Honeypot prefix detection ---
    print(f"\n  {DIM}Testing _detect_honeypot_prefix ...{RESET}")
    prefix = _detect_honeypot_prefix("192.168.12.240")
    if prefix == "192.168.":
        _ok(f"Honeypot prefix correctly detected: '{prefix}'")
        passed += 1
    else:
        _fail(f"Expected '192.168.' but got '{prefix}'")
        failed += 1

    # Honeypot-subnet IP should be filtered out
    if _is_private_or_local("192.168.12.50", "192.168."):
        _ok("Honeypot-subnet IP correctly filtered")
        passed += 1
    else:
        _fail("Honeypot-subnet IP should have been filtered!")
        failed += 1

    # --- Test 3: Cloud provider matching ---
    print(f"\n  {DIM}Testing _match_cloud_provider ...{RESET}")
    cloud_tests = [
        ("13.56.200.100", "AWS"),
        ("35.200.100.50", "GCP"),
        ("104.131.0.69", "DigitalOcean"),
        ("51.38.100.200", "OVH"),
        ("45.33.32.156", "Linode"),
        ("20.50.100.200", "Azure"),
    ]
    for ip, expected_provider in cloud_tests:
        result = _match_cloud_provider(ip)
        if result == expected_provider:
            _ok(f"{ip} -> {result}")
            passed += 1
        else:
            _fail(f"{ip} -> expected '{expected_provider}' but got '{result}'")
            failed += 1

    # Non-cloud IP should return empty string
    result = _match_cloud_provider("8.8.8.8")
    if result == "":
        _ok("8.8.8.8 correctly identified as non-cloud")
        passed += 1
    else:
        _fail(f"8.8.8.8 -> expected '' but got '{result}'")
        failed += 1

    # --- Test 4: Database Threat Intel Cache integration ---
    print(f"\n  {DIM}Testing ThreatIntelCache Database Integration ...{RESET}")
    from database.database import async_session
    from database.models import ThreatIntelCache

    async def _test_cache():
        async with async_session() as session:
            cache_entry = await session.get(ThreatIntelCache, "99.99.99.99")
            if cache_entry:
                await session.delete(cache_entry)
                await session.commit()
            
            test_data = {"ip": "99.99.99.99", "country": "TestCountry", "cloud_provider": "TestCloud"}
            from datetime import datetime, UTC
            session.add(ThreatIntelCache(ip="99.99.99.99", data=test_data, updated_at=datetime.now(UTC)))
            await session.commit()
            
            cache_entry = await session.get(ThreatIntelCache, "99.99.99.99")
            return cache_entry

    try:
        entry = asyncio.run(_test_cache())
        if entry and entry.data.get("country") == "TestCountry":
            _ok("Database Cache put/get works correctly")
            passed += 1
        else:
            _fail("Database Cache put/get failed!")
            failed += 1
    except Exception as exc:
        _fail(f"Database Cache test raised {type(exc).__name__}: {exc}")
        failed += 1

    # --- Test 5: enrich_top_ips with only private IPs (should return empty) ---
    print(f"\n  {DIM}Testing enrich_top_ips (private IPs only) ...{RESET}")
    private_counts = {"192.168.1.1": 100, "10.0.0.5": 50, "172.16.0.1": 30}
    try:
        result = asyncio.run(enrich_top_ips(private_counts, honeypot_host="192.168.12.240"))
        if result == []:
            _ok("Private-only input correctly returns empty list")
            passed += 1
        else:
            _fail(f"Expected empty list but got {len(result)} results")
            failed += 1
    except Exception as exc:
        _fail(f"enrich_top_ips (private only) raised {type(exc).__name__}: {exc}")
        failed += 1

    # --- Test 6: enrich_top_ips with real public IPs ---
    print(f"\n  {DIM}Testing enrich_top_ips (with public IPs, may call ip-api.com) ...{RESET}")
    mixed_counts = {
        "192.168.1.1": 500,
        "10.0.0.5": 200,
        "45.33.32.156": 42,     # Linode
        "8.8.8.8": 10,          # Google DNS
    }
    try:
        result = asyncio.run(enrich_top_ips(mixed_counts, honeypot_host="192.168.12.240", limit=5))
        if len(result) > 0:
            _ok(f"enrich_top_ips returned {len(result)} enriched IPs")
            passed += 1
            for entry in result:
                ip = entry.get("ip", "?")
                country = entry.get("country", "?")
                cloud = entry.get("cloud_provider", "")
                abuse = entry.get("abuse_score", "N/A")
                rdns = entry.get("rdns", "?")
                _info(
                    f"  {ip:20s} | country={country:15s} | cloud={cloud or 'none':15s} "
                    f"| abuse={str(abuse):5s} | rdns={rdns}"
                )
        else:
            _fail("enrich_top_ips returned empty list for public IPs")
            failed += 1
    except Exception as exc:
        _fail(f"enrich_top_ips raised {type(exc).__name__}: {exc}")
        failed += 1    # --- Test 7: Auto-Blacklist Toggle settings ---
    print(f"\n  {DIM}Testing Auto-Blacklist Toggle and record_suspicious_event ...{RESET}")
    try:
        from defense import (
            is_auto_blacklist_enabled,
            set_auto_blacklist_enabled,
            record_suspicious_event,
            is_blacklisted,
            delete_from_blacklist,
            _suspicious_counters,
        )
        test_ip = "199.199.199.199"
        
        # Clean up first
        asyncio.run(delete_from_blacklist(test_ip))
        if test_ip in _suspicious_counters:
            del _suspicious_counters[test_ip]

        # 1. Enable and verify
        asyncio.run(set_auto_blacklist_enabled(True))
        if asyncio.run(is_auto_blacklist_enabled()) is True:
            _ok("Auto-blacklist toggle: Enabled successfully")
            passed += 1
        else:
            _fail("Auto-blacklist toggle: Failed to enable")
            failed += 1

        # 2. Disable and verify
        asyncio.run(set_auto_blacklist_enabled(False))
        if asyncio.run(is_auto_blacklist_enabled()) is False:
            _ok("Auto-blacklist toggle: Disabled successfully")
            passed += 1
        else:
            _fail("Auto-blacklist toggle: Failed to disable")
            failed += 1

        # 3. With it disabled, trigger >100 suspicious events, verify IP is NOT blocked
        _suspicious_counters[test_ip] = 99
        asyncio.run(record_suspicious_event(test_ip))
        if not asyncio.run(is_blacklisted(test_ip)):
            _ok("With auto-blacklist disabled, IP was NOT banned after 100 events")
            passed += 1
        else:
            _fail("IP was banned even though auto-blacklist was disabled!")
            failed += 1

        # Clean up
        asyncio.run(delete_from_blacklist(test_ip))
        if test_ip in _suspicious_counters:
            del _suspicious_counters[test_ip]

        # 4. Enable again, trigger >100 suspicious events, verify IP IS blocked
        asyncio.run(set_auto_blacklist_enabled(True))
        _suspicious_counters[test_ip] = 99
        asyncio.run(record_suspicious_event(test_ip))
        if asyncio.run(is_blacklisted(test_ip)):
            _ok("With auto-blacklist enabled, IP was successfully banned after 100 events")
            passed += 1
        else:
            _fail("IP was NOT banned even though auto-blacklist was enabled!")
            failed += 1

        # Clean up finally
        asyncio.run(delete_from_blacklist(test_ip))
        if test_ip in _suspicious_counters:
            del _suspicious_counters[test_ip]

    except Exception as exc:
        _fail(f"Auto-blacklist unit test raised {type(exc).__name__}: {exc}")
        failed += 1


    return passed, failed


# ---------------------------------------------------------------------------
# Phase 2: Integration - send traffic to honeypot services
# ---------------------------------------------------------------------------

def _tcp_probe(host: str, port: int, payload: bytes, timeout: float = 3.0) -> str | None:
    """Send a TCP payload to host:port and return the response (or None on error)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if payload:
            sock.sendall(payload)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        resp = b"".join(chunks)
        sock.close()
        return resp.decode("utf-8", errors="replace")
    except Exception as exc:
        return f"[error: {type(exc).__name__}: {exc}]"


def _http_request(host: str, port: int, method: str = "GET", path: str = "/",
                  headers: dict | None = None, body: str = "", timeout: float = 5.0) -> str | None:
    """Send a raw HTTP request and return the response."""
    hdrs = headers or {}
    hdrs.setdefault("Host", f"{host}:{port}")
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0")
    hdrs.setdefault("Connection", "close")
    if body:
        hdrs["Content-Length"] = str(len(body))

    header_lines = [f"{method} {path} HTTP/1.1"]
    for k, v in hdrs.items():
        header_lines.append(f"{k}: {v}")
    raw = "\r\n".join(header_lines) + "\r\n\r\n" + body

    return _tcp_probe(host, port, raw.encode("utf-8"), timeout)


def _api_request(host: str, port: int, path: str, method: str = "GET",
                 body: dict | None = None, cookie: str = "",
                 timeout: float = 10.0) -> dict | None:
    """Send an HTTP request to the web API and return parsed JSON."""
    headers: dict[str, str] = {
        "Host": f"{host}:{port}",
        "User-Agent": "ThreatIntelTest/1.0",
        "Connection": "close",
        "Accept": "application/json",
    }
    if cookie:
        headers["Cookie"] = f"session={cookie}"

    body_str = ""
    if body is not None:
        body_str = json.dumps(body)
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body_str))

    raw_resp = _http_request(host, port, method, path, headers, body_str, timeout)
    if not raw_resp:
        return None

    # Parse HTTP response to extract JSON body
    parts = raw_resp.split("\r\n\r\n", 1)
    if len(parts) < 2:
        parts = raw_resp.split("\n\n", 1)
    if len(parts) < 2:
        return None

    try:
        return json.loads(parts[1])
    except (json.JSONDecodeError, IndexError):
        return None


def phase2_service_probes(host: str, web_port: int) -> tuple[int, int]:
    """Connect to honeypot services and generate log entries, then query threat-intel API."""
    _header("Phase 2 - Service Probes (simulate attacker traffic)")
    passed = 0
    failed = 0

    # Define services to probe with their port and test payloads
    service_probes = [
        # (service_name, port, description, payload_or_func)
        ("HTTP (Linux)",  8080, "HTTP GET /etc/passwd", lambda h, p: _http_request(h, p, "GET", "/../../etc/passwd")),
        ("HTTP (Linux)",  8080, "HTTP POST /login",     lambda h, p: _http_request(h, p, "POST", "/login", body="username=admin&password=admin")),
        ("HTTP (Windows)", 80,  "HTTP GET /admin",       lambda h, p: _http_request(h, p, "GET", "/admin/")),
        ("SSH (Linux)",  2222, "SSH banner grab",        lambda h, p: _tcp_probe(h, p, b"SSH-2.0-OpenSSH_8.9\r\n")),
        ("SSH (Windows)", 2223, "SSH banner grab",       lambda h, p: _tcp_probe(h, p, b"SSH-2.0-PuTTY_Release_0.78\r\n")),
        ("FTP",          2121, "FTP USER/PASS",          lambda h, p: _tcp_probe(h, p, b"USER admin\r\nPASS admin123\r\n")),
        ("Telnet",       2323, "Telnet connect",         lambda h, p: _tcp_probe(h, p, b"admin\r\npassword\r\n")),
        ("RDP",          3389, "RDP initial probe",      lambda h, p: _tcp_probe(h, p, b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00")),
        ("MSSQL",        1433, "TDS prelogin",           lambda h, p: _tcp_probe(h, p, b"\x12\x01\x00\x34\x00\x00\x00\x00")),
        ("SMB",          1445, "SMB negotiate",          lambda h, p: _tcp_probe(h, p, b"\x00\x00\x00\x45\xffSMB\x72\x00\x00\x00\x00")),
        ("RPC",           135, "RPC bind",               lambda h, p: _tcp_probe(h, p, b"\x05\x00\x0b\x03\x10\x00\x00\x00")),
        ("LDAP",          389, "LDAP bind",              lambda h, p: _tcp_probe(h, p, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")),
        ("NetBIOS",       139, "NetBIOS session",        lambda h, p: _tcp_probe(h, p, b"\x81\x00\x00\x44")),
    ]

    print(f"\n  {DIM}Sending probes to {host} ...{RESET}\n")

    success_count = 0
    fail_count = 0

    for svc_name, port, desc, probe_func in service_probes:
        try:
            result = probe_func(host, port)
            if result and "[error:" not in result:
                _ok(f"{svc_name:20s} :{port:<6d} {desc:30s} -> got response ({len(result)} chars)")
                success_count += 1
            elif result and "ConnectionRefused" in result:
                _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> service not running")
            else:
                _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> {result}")
        except Exception as exc:
            _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> {type(exc).__name__}")

    if success_count > 0:
        _ok(f"\n  {success_count} services responded")
        passed += 1
    else:
        _warn("No services responded - are honeypot services running?")

    # --- Inject Fake External IPs into logs to test Threat Intel ---
    print(f"\n  {DIM}Injecting fake external IP traffic into logs ...{RESET}")
    import os
    import subprocess
    import tempfile
    
    events_to_inject = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    for ip in FAKE_ATTACKER_IPS:
        # Add 5-15 random events per IP
        count = random.randint(5, 15)
        for _ in range(count):
            event = {
                "timestamp": now_str,
                "event_type": "simulated_attack",
                "src_ip": ip,
                "src_port": random.randint(1024, 65535),
                "dest_port": 80,
                "service": "simulated",
                "protocol": "tcp"
            }
            events_to_inject.append(json.dumps(event))
            
    payload = "\n".join(events_to_inject) + "\n"
    
    # Check if running alongside Docker, otherwise write locally
    docker_container = "honeypot-backend"
    try:
        res = subprocess.run(["docker", "ps", "-q", "-f", f"name={docker_container}"], capture_output=True, text=True)
        is_docker = bool(res.stdout.strip())
    except FileNotFoundError:
        is_docker = False
        
    try:
        if is_docker:
            # Inject into Docker container's log volume
            with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as tf:
                tf.write(payload)
                tmp_path = tf.name
            try:
                subprocess.run(["docker", "cp", tmp_path, f"{docker_container}:/tmp/fake_events.jsonl"], check=True, capture_output=True)
                subprocess.run(["docker", "exec", docker_container, "sh", "-c", "cat /tmp/fake_events.jsonl >> /app/logs/events.jsonl"], check=True, capture_output=True)
                _ok(f"Injected fake events for {len(FAKE_ATTACKER_IPS)} external IPs directly into Docker container '{docker_container}'")
                passed += 1
            finally:
                os.remove(tmp_path)
        else:
            # Write locally
            log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "events.jsonl")
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(payload)
            _ok(f"Injected fake events for {len(FAKE_ATTACKER_IPS)} external IPs into local {log_path}")
            passed += 1
    except Exception as exc:
        _warn(f"Failed to inject fake logs: {exc}")
        failed += 1

    # --- Wait for logs to be written ---
    print(f"  {DIM}Waiting 1 second for logs to be flushed ...{RESET}")
    time.sleep(1)

    return passed, failed


def phase3_api_check(host: str, web_port: int, username: str, password: str) -> tuple[int, int]:
    """Authenticate to the dashboard and query /api/threat-intel."""
    _header("Phase 3 - API Verification (/api/threat-intel)")
    passed = 0
    failed = 0

    # Step 1: Login
    print(f"\n  {DIM}Logging in as '{username}' ...{RESET}")
    login_resp = _api_request(host, web_port, "/api/login", "POST",
                              body={"username": username, "password": password})

    if not login_resp:
        _fail("Could not connect to web dashboard - is it running?")
        failed += 1
        return passed, failed

    if not login_resp.get("ok"):
        _fail(f"Login failed: {login_resp.get('error', 'unknown error')}")
        failed += 1
        return passed, failed

    _ok(f"Login successful (role: {login_resp.get('role', '?')})")
    passed += 1

    # Extract session cookie from raw response
    raw_resp = _http_request(
        host, web_port, "POST", "/api/login",
        headers={
            "Content-Type": "application/json",
            "Host": f"{host}:{web_port}",
            "Connection": "close",
        },
        body=json.dumps({"username": username, "password": password}),
    )

    session_token = ""
    if raw_resp:
        for line in raw_resp.split("\r\n"):
            if line.lower().startswith("set-cookie:") and "session=" in line:
                parts = line.split("session=", 1)
                if len(parts) > 1:
                    session_token = parts[1].split(";")[0].strip()
                    break

    if not session_token:
        _warn("Could not extract session cookie - trying without auth")

    # Step 2: Query /api/threat-intel
    print(f"\n  {DIM}Querying /api/threat-intel ...{RESET}")
    ti_resp = _api_request(host, web_port, "/api/threat-intel", cookie=session_token)

    if not ti_resp:
        _fail("No response from /api/threat-intel")
        failed += 1
        return passed, failed

    if "error" in ti_resp:
        _fail(f"API returned error: {ti_resp['error']}")
        failed += 1
        return passed, failed

    _ok("Got response from /api/threat-intel")
    passed += 1

    # Step 3: Validate response structure
    attackers = ti_resp.get("attackers", [])
    summary = ti_resp.get("summary", {})

    print(f"\n  {DIM}Validating response structure ...{RESET}")

    if isinstance(attackers, list):
        _ok(f"'attackers' is a list with {len(attackers)} entries")
        passed += 1
    else:
        _fail("'attackers' should be a list")
        failed += 1

    if isinstance(summary, dict):
        expected_keys = {"tor_count", "cloud_count", "avg_abuse_score"}
        actual_keys = set(summary.keys())
        if expected_keys.issubset(actual_keys):
            _ok(f"'summary' has all expected keys: {expected_keys}")
            passed += 1
        else:
            _fail(f"'summary' missing keys: {expected_keys - actual_keys}")
            failed += 1
    else:
        _fail("'summary' should be a dict")
        failed += 1

    # Step 4: Print enriched attacker data
    if attackers:
        print(f"\n  {BOLD}Enriched Attacker Data:{RESET}\n")
        print(f"  {'IP':<18} {'Country':<15} {'Cloud':<15} {'ASN':<12} {'Abuse':<8} {'Tor':<5} {'Events':<8} {'rDNS'}")
        print(f"  {'─'*18} {'─'*15} {'─'*15} {'─'*12} {'─'*8} {'─'*5} {'─'*8} {'─'*30}")
        for a in attackers:
            tor_mark = f"{RED}YES{RESET}" if a.get("is_tor") else "no"
            abuse = a.get("abuse_score", "N/A")
            if isinstance(abuse, (int, float)) and abuse >= 50:
                abuse_str = f"{RED}{abuse}{RESET}"
            elif isinstance(abuse, (int, float)) and abuse > 0:
                abuse_str = f"{YELLOW}{abuse}{RESET}"
            else:
                abuse_str = str(abuse)
            cloud = a.get("cloud_provider", "") or "-"
            print(
                f"  {a.get('ip', '?'):<18} "
                f"{a.get('country', '?'):<15} "
                f"{cloud:<15} "
                f"{a.get('asn', '?'):<12} "
                f"{str(abuse):<8} "
                f"{'YES' if a.get('is_tor') else 'no':<5} "
                f"{a.get('event_count', 0):<8} "
                f"{a.get('rdns', '?')}"
            )
        print()

        # Verify enrichment quality
        enriched_count = sum(
            1 for a in attackers
            if a.get("country", "Unknown") != "Unknown" or a.get("cloud_provider")
        )
        if enriched_count > 0:
            _ok(f"{enriched_count}/{len(attackers)} attackers have geo/cloud enrichment")
            passed += 1
        else:
            _warn("No enrichment data found - ip-api.com may be unreachable")
    else:
        _warn("No attackers returned - log file may not have enough recent external IP entries")
        _info("This is normal if honeypot services haven't received external traffic yet")

    # Print summary
    if summary:
        print(f"\n  {BOLD}Summary:{RESET}")
        _info(f"Tor exit nodes among top attackers: {summary.get('tor_count', 0)}")
        _info(f"Cloud-hosted attackers: {summary.get('cloud_count', 0)}")
        _info(f"Average AbuseIPDB score: {summary.get('avg_abuse_score', 'N/A')}")

    # Step 5: Also check /api/overview for stats
    print(f"\n  {DIM}Querying /api/overview for log stats ...{RESET}")
    overview_resp = _api_request(host, web_port, "/api/overview", cookie=session_token)
    if overview_resp and "stats" in overview_resp:
        stats = overview_resp["stats"]
        _ok(f"Total recent events: {stats.get('total_recent_events', 0)}")
        by_svc = stats.get("by_service", {})
        if by_svc:
            _info(f"Events by service: {json.dumps(by_svc, indent=None)}")
        passed += 1
    elif overview_resp:
        _warn("Overview response didn't contain 'stats'")
    else:
        _warn("Could not get /api/overview")

    return passed, failed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test the Threat Intelligence pipeline end-to-end",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python test_threat_intel.py
              python test_threat_intel.py --host 192.168.12.240 --web-port 8000
              python test_threat_intel.py --skip-probes
        """),
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Honeypot host address (default: 127.0.0.1)")
    parser.add_argument("--web-port", type=int, default=8000,
                        help="Web dashboard port (default: 8000)")
    parser.add_argument("--username", default="admin",
                        help="Dashboard username (default: admin)")
    parser.add_argument("--password", default="admin123",
                        help="Dashboard password (default: admin123)")
    parser.add_argument("--skip-probes", action="store_true",
                        help="Skip Phase 2 (service probes)")
    parser.add_argument("--skip-unit", action="store_true",
                        help="Skip Phase 1 (unit tests)")
    parser.add_argument("--skip-api", action="store_true",
                        help="Skip Phase 3 (API verification)")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}        Honeypot Threat Intel - Test Suite                  {RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"  Target:   {args.host}")
    print(f"  Web port: {args.web_port}")
    print(f"  Time:     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    total_passed = 0
    total_failed = 0

    # Phase 1: Unit tests
    if not args.skip_unit:
        p, f = phase1_unit_tests()
        total_passed += p
        total_failed += f

    # Phase 2: Service probes
    if not args.skip_probes:
        p, f = phase2_service_probes(args.host, args.web_port)
        total_passed += p
        total_failed += f

    # Phase 3: API verification
    if not args.skip_api:
        p, f = phase3_api_check(args.host, args.web_port, args.username, args.password)
        total_passed += p
        total_failed += f

    # Final report
    _header("Results")
    total = total_passed + total_failed
    if total_failed == 0:
        print(f"\n  {GREEN}{BOLD}ALL {total_passed} CHECKS PASSED [OK]{RESET}\n")
    else:
        print(f"\n  {RED}{BOLD}{total_failed} FAILED{RESET} / {total} total checks")
        print(f"  {GREEN}{total_passed} passed{RESET}\n")

    sys.exit(1 if total_failed > 0 else 0)


if __name__ == "__main__":
    main()
