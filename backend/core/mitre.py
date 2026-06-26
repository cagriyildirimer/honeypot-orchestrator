from __future__ import annotations
from typing import Any

# MITRE ATT&CK Tactic & Technique definitions
MITRE_TACTICS = {
    "Initial Access": "Tactic used by adversaries to gain an initial foothold within a network.",
    "Execution": "Tactic representing techniques that result in adversary-controlled code running on a local or remote system.",
    "Credential Access": "Tactic used for stealing credentials like usernames and passwords.",
    "Discovery": "Tactic representing techniques used to gain knowledge about the system and internal network.",
    "Lateral Movement": "Tactic representing techniques used to enter and control remote systems on a network."
}

MITRE_TECHNIQUES = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques (e.g., login attempts in SSH, FTP, HTTP, Telnet, MSSQL, SMB) to gain access to accounts."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in public-facing web or service applications (e.g., exploit payloads in HTTP, HTTP vulnerability scans)."
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services and open ports (e.g., connections, port scans, DNS/NetBIOS/LLMNR queries, LDAP directory searches)."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may use command and scripting interpreters to execute commands on the host (e.g., SSH/Telnet shell commands, SQL query execution, script running)."
    },
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may exploit remote services to gain unauthorized access (e.g., SMB/RDP remote exploitation attempts, unauthorized remote desktop connections)."
    }
}

def map_event_to_mitre(event: dict[str, Any]) -> str | None:
    """
    Maps a honeypot event to a MITRE ATT&CK Technique ID.
    Returns the Technique ID (e.g. 'T1110') or None if no mapping exists.
    """
    service = str(event.get("service") or "").lower()
    event_type = str(event.get("event_type") or "").lower()
    summary = str(event.get("summary") or "").lower()
    
    # Exclude system/orchestrator events and events without a valid source IP
    if not event.get("src_ip") or event_type in (
        "service_started", "service_stopped", "network_tuning_applied", "system_tuning"
    ):
        return None
    
    # 1. Credential Access / Brute Force
    if event_type in ("login_attempt", "login_failed", "brute_force"):
        return "T1110"
        
    # 2. Execution / Command Interpreter
    if event_type in ("command_execution", "command", "shell_command") or "command" in summary or "exec" in summary:
        return "T1059"
        
    # 3. Initial Access / Exploit Public-Facing Application
    if event_type in ("exploit_attempt", "exploit", "exploit_failed") or "exploit" in summary or "vuln" in summary:
        return "T1190"
        
    # 4. Lateral Movement / Exploitation of Remote Services
    if service in ("smb_windows", "rdp_windows") and event_type in ("connection_error", "exploit_attempt"):
        return "T1210"
        
    # 5. Discovery / Network Service Discovery (Default fallback for connection events)
    if event_type in ("connection", "connected", "dns_query", "query", "search") or service in (
        "dns_windows", "llmnr_windows", "nbtnns_windows", "netbios_windows", "ldap_windows", "ldaps_windows", "rpc_windows"
    ):
        return "T1046"
        
    return None
