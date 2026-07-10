#!/usr/bin/env python3
"""Threat Intel pipeline test script.

Generates simulated attacker traffic to honeypot services and then queries
the /api/threat-intel endpoint to verify enrichment is working correctly.

Usage:
    python test_threat_intel.py [--host 127.0.0.1] [--web-port 8000]
"""

import argparse
import json
import random
import socket
import sys
import textwrap
import time
import os
import re
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
    "185.220.101.5",    # Known Tor exit node
    "193.70.50.42",     # OVH
    "64.225.50.10",     # DigitalOcean
    "54.36.100.200",    # OVH
    "34.70.100.50",     # GCP
    "20.50.100.200",    # Azure
    "139.162.100.50",   # Linode
]

# ---------------------------------------------------------------------------
# Helper: Database connection resolver
# ---------------------------------------------------------------------------
def get_db_url() -> str:
    # 1. Environment Variable
    if os.environ.get("HONEYPOT_DB_URL"):
        return os.environ.get("HONEYPOT_DB_URL")

    # 2. Check .env file in parent directories
    root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env_paths = [
        os.path.join(root_dir, ".env"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        ".env"
    ]
    for path in env_paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("HONEYPOT_DB_URL="):
                        val = line.split("HONEYPOT_DB_URL=", 1)[1].strip()
                        # strip quotes if present
                        val = re.sub(r'^["\']|["\']$', '', val)
                        return val

    # 3. Default fallback
    return "postgresql://honeypot:honeypot_password@localhost:5432/honeypot"

# ---------------------------------------------------------------------------
# Helper to inject database records directly via psycopg2
# ---------------------------------------------------------------------------
def inject_db_events(ips: list[str]) -> bool:
    db_url = get_db_url()
    
    # Check if psycopg2 is installed
    try:
        import psycopg2
    except ImportError:
        _warn("psycopg2 is not installed. Trying to install psycopg2-binary to proceed...")
        import subprocess
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "psycopg2-binary"], check=True)
            import psycopg2
        except Exception:
            _fail("Could not import/install psycopg2. Please run: pip install psycopg2-binary")
            return False

    events_to_inject = []
    now_utc = datetime.now(timezone.utc)
    for ip in ips:
        count = random.randint(5, 15)
        for _ in range(count):
            events_to_inject.append({
                "timestamp": now_utc,
                "event_type": "simulated_attack",
                "src_ip": ip,
                "src_port": random.randint(1024, 65535),
                "service": "simulated",
                "summary": "Simulated external attack probe",
                "details": json.dumps({"test_tool": "test_threat_intel"})
            })

    try:
        _info(f"Connecting to database at {db_url.split('@')[-1]} ...")
        conn = psycopg2.connect(db_url)
        cursor = conn.cursor()
        
        # Clear cached threat intel entries to force backend to rebuild cache with the new API keys
        cursor.execute("DELETE FROM threat_intel_cache;")
        _ok("Cleared stale threat_intel_cache table in database.")

        for ev in events_to_inject:
            cursor.execute(
                "INSERT INTO events (timestamp, service, event_type, src_ip, src_port, summary, details) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (ev["timestamp"], ev["service"], ev["event_type"], ev["src_ip"], ev["src_port"], ev["summary"], ev["details"])
            )
        conn.commit()
        cursor.close()
        conn.close()
        _ok(f"Injected fake events for {len(ips)} external IPs directly into PostgreSQL Database")
        return True
    except Exception as exc:
        _fail(f"Failed to inject events directly to Database: {exc}")
        return False

# ---------------------------------------------------------------------------
# Service Probes Simulation (tcp/http helper functions)
# ---------------------------------------------------------------------------
def _tcp_probe(host: str, port: int, payload: bytes, timeout: float = 3.0) -> str | None:
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

    parts = raw_resp.split("\r\n\r\n", 1)
    if len(parts) < 2:
        parts = raw_resp.split("\n\n", 1)
    if len(parts) < 2:
        return None

    try:
        return json.loads(parts[1])
    except (json.JSONDecodeError, IndexError):
        return None

# ---------------------------------------------------------------------------
# Phase 1: Service Probes (simulate attacker traffic)
# ---------------------------------------------------------------------------
def phase1_service_probes(host: str, web_port: int) -> tuple[int, int]:
    _header("Phase 1 - Service Probes (simulate local attacker traffic)")
    passed = 0
    failed = 0

    service_probes = [
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
    for svc_name, port, desc, probe_func in service_probes:
        try:
            result = probe_func(host, port)
            if result and "[error:" not in result:
                _ok(f"{svc_name:20s} :{port:<6d} {desc:30s} -> got response ({len(result)} chars)")
                success_count += 1
            elif result and "ConnectionRefused" in result:
                _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> service not running (check configuration)")
            else:
                _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> {result}")
        except Exception as exc:
            _warn(f"{svc_name:20s} :{port:<6d} {desc:30s} -> {type(exc).__name__}")

    if success_count > 0:
        _ok(f"\n  {success_count} services responded")
        passed += 1
    else:
        _warn("No services responded - are honeypot services running?")

    return passed, failed

# ---------------------------------------------------------------------------
# Phase 2: Attacker IP Simulation (DB Injection)
# ---------------------------------------------------------------------------
def phase2_attacker_injection() -> tuple[int, int]:
    _header("Phase 2 - Attacker IP Simulation (directly inject fake external logs)")
    passed = 0
    failed = 0

    if inject_db_events(FAKE_ATTACKER_IPS):
        passed += 1
    else:
        failed += 1

    return passed, failed

# ---------------------------------------------------------------------------
# Phase 3: Web API Verification (/api/threat-intel & /api/overview)
# ---------------------------------------------------------------------------
def phase3_api_check(host: str, web_port: int, username: str, password: str) -> tuple[int, int]:
    _header("Phase 3 - API Verification (/api/threat-intel & /api/overview)")
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

    # Extract session cookie
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

        enriched_count = sum(
            1 for a in attackers
            if a.get("country", "Unknown") != "Unknown" or a.get("cloud_provider")
        )
        if enriched_count > 0:
            _ok(f"{enriched_count}/{len(attackers)} attackers have geo/cloud enrichment")
            passed += 1
        else:
            _warn("No enrichment data found yet - if background worker hasn't run yet, refresh in a few minutes.")
    else:
        _warn("No attackers returned - log file/database may not have enough recent external IP entries")

    if summary:
        print(f"\n  {BOLD}Summary Statistics:{RESET}")
        _info(f"Tor exit nodes among top attackers: {summary.get('tor_count', 0)}")
        _info(f"Cloud-hosted attackers: {summary.get('cloud_count', 0)}")
        _info(f"Average AbuseIPDB score: {summary.get('avg_abuse_score', 'N/A')}")

    # Step 5: Check /api/overview
    print(f"\n  {DIM}Querying /api/overview for stats ...{RESET}")
    overview_resp = _api_request(host, web_port, "/api/overview", cookie=session_token)
    if overview_resp and "stats" in overview_resp:
        stats = overview_resp["stats"]
        _ok(f"Total recent events: {stats.get('total_recent_events', 0)}")
        by_svc = stats.get("by_service", {})
        if by_svc:
            _info(f"Events by service: {json.dumps(by_svc, indent=None)}")
        passed += 1
    elif overview_resp:
        _warn("Overview response did not contain 'stats'")
    else:
        _warn("Could not get /api/overview")

    return passed, failed

# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test the Threat Intelligence pipeline end-to-end",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python test_threat_intel.py
              python test_threat_intel.py --host 192.168.1.240 --web-port 80
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
                        help="Skip Phase 1 (decoy service probes)")
    parser.add_argument("--skip-inject", action="store_true",
                        help="Skip Phase 2 (attacker IP simulation injection)")
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

    # Phase 1: Service probes
    if not args.skip_probes:
        p, f = phase1_service_probes(args.host, args.web_port)
        total_passed += p
        total_failed += f

    # Phase 2: Attacker IP Simulation
    if not args.skip_inject:
        p, f = phase2_attacker_injection()
        total_passed += p
        total_failed += f

    # Phase 3: API Verification
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
