from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from honeypot_orchestrator.event_logger import JSONLEventLogger

logger = logging.getLogger(__name__)


def setup_firewall(active_ports: list[tuple[int, str]], web_port: int | None) -> None:
    try:
        # Create chain if not exists
        subprocess.run(["iptables", "-N", "HONEYPOT_INPUT"], capture_output=True)
        # Flush the chain
        subprocess.run(["iptables", "-F", "HONEYPOT_INPUT"], capture_output=True)
        
        # Check if INPUT jumps to HONEYPOT_INPUT, if not insert it
        check_jump = subprocess.run(["iptables", "-C", "INPUT", "-j", "HONEYPOT_INPUT"], capture_output=True)
        if check_jump.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-j", "HONEYPOT_INPUT"], capture_output=True)
            
        # Allow loopback
        subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-i", "lo", "-j", "ACCEPT"], capture_output=True)
        # Allow established/related
        subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], capture_output=True)
        
        # Allow web dashboard port if enabled
        if web_port:
            subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-p", "tcp", "--dport", str(web_port), "-j", "ACCEPT"], capture_output=True)
            
        # Allow active decoy ports
        for port, proto in active_ports:
            subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-p", proto, "--dport", str(port), "-j", "ACCEPT"], capture_output=True)
            
        # Drop all other TCP, UDP, ICMP
        subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-p", "tcp", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-p", "udp", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-A", "HONEYPOT_INPUT", "-p", "icmp", "-j", "DROP"], capture_output=True)
    except Exception as e:
        logger.warning(f"Could not apply firewall rules: {e}")


def apply_nfqueue_rules(profile_name: str) -> None:
    try:
        # First, ensure we don't have duplicate OUTPUT rules
        subprocess.run(["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "NFQUEUE", "--queue-num", "1"], capture_output=True)
        # Drop invalid TCP flags (often used by Nmap to fingerprint OS)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "FIN,RST", "FIN,RST", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "ACK,FIN", "FIN", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "ACK,PSH", "PSH", "-j", "DROP"], capture_output=True)
        subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--tcp-flags", "ACK,URG", "URG", "-j", "DROP"], capture_output=True)

        if profile_name == "windows_server":
            # Add rules to drop invalid flags before they hit the stack
            subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "2", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "3", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "4", "-p", "tcp", "--tcp-flags", "FIN,RST", "FIN,RST", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "5", "-p", "tcp", "--tcp-flags", "ACK,FIN", "FIN", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "6", "-p", "tcp", "--tcp-flags", "ACK,PSH", "PSH", "-j", "DROP"], capture_output=True)
            subprocess.run(["iptables", "-I", "INPUT", "7", "-p", "tcp", "--tcp-flags", "ACK,URG", "URG", "-j", "DROP"], capture_output=True)

            # Redirect SYN-ACK packets to NFQUEUE
            subprocess.run(["iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK", "-j", "NFQUEUE", "--queue-num", "1"], capture_output=True)
            logger.info("NFQUEUE and invalid flag drop rules applied for windows_server profile.")
        else:
            logger.info("NFQUEUE and invalid flag drop rules removed for non-windows profile.")
    except Exception as e:
        logger.warning(f"Could not apply NFQUEUE rules: {e}")


def cleanup_firewall() -> None:
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-j", "HONEYPOT_INPUT"], capture_output=True)
        subprocess.run(["iptables", "-F", "HONEYPOT_INPUT"], capture_output=True)
        subprocess.run(["iptables", "-X", "HONEYPOT_INPUT"], capture_output=True)
    except Exception as e:
        logger.warning(f"Could not cleanup firewall rules: {e}")


async def apply_profile_network_settings(
    profile_name: str,
    event_logger: JSONLEventLogger,
    services: dict[str, Any],
    target_service_names: set[str],
    web_port: int,
    web_enabled: bool,
) -> None:
    """
    Adjusts standard namespaced network settings inside the container's namespace:
    - windows_server profile: TTL=128, tcp_timestamps=0
    - other profiles (linux_server/empty): TTL=64, tcp_timestamps=1
    """
    is_windows = profile_name == "windows_server"
    target_ttl = "128" if is_windows else "64"
    target_timestamps = "0" if is_windows else "1"
    target_rmem = "4096 65536 12582912" if is_windows else "4096 87380 16777216"
    target_wmem = "4096 65536 12582912" if is_windows else "4096 65536 16777216"

    # Advanced TCP Obfuscation to strip Linux specific options in SYN-ACK
    target_window_scaling = "0" if is_windows else "1"
    target_sack = "0" if is_windows else "1"
    target_ecn = "0" if is_windows else "2"
    target_dsack = "0" if is_windows else "1"
    target_fack = "0" if is_windows else "1"

    # Define path mappings
    sysctl_paths = {
        "net.ipv4.ip_default_ttl": ("/proc/sys/net/ipv4/ip_default_ttl", target_ttl),
        "net.ipv4.tcp_timestamps": ("/proc/sys/net/ipv4/tcp_timestamps", target_timestamps),
        "net.ipv4.tcp_window_scaling": ("/proc/sys/net/ipv4/tcp_window_scaling", target_window_scaling),
        "net.ipv4.tcp_sack": ("/proc/sys/net/ipv4/tcp_sack", target_sack),
        "net.ipv4.tcp_ecn": ("/proc/sys/net/ipv4/tcp_ecn", target_ecn),
        "net.ipv4.tcp_dsack": ("/proc/sys/net/ipv4/tcp_dsack", target_dsack),
        "net.ipv4.tcp_fack": ("/proc/sys/net/ipv4/tcp_fack", target_fack),
        "net.ipv4.tcp_rmem": ("/proc/sys/net/ipv4/tcp_rmem", target_rmem),
        "net.ipv4.tcp_wmem": ("/proc/sys/net/ipv4/tcp_wmem", target_wmem),
    }

    modified_params = []
    failed_params = []

    for name, (path, val) in sysctl_paths.items():
        try:
            with open(path, "w") as f:
                f.write(val)
            modified_params.append(f"{name}={val}")
        except IOError as e:
            failed_params.append(f"{name} ({e})")

    if failed_params:
        summary = (
            f"Failed to apply some network fingerprint adjustments: {', '.join(failed_params)}. "
            f"Check if container runs as root and has NET_ADMIN capability."
        )
        print(f"Warning: {summary}")
        await event_logger.log({
            "service": "orchestrator",
            "event_type": "network_tuning_warning",
            "summary": summary,
            "failed_params": failed_params,
        })

    if modified_params:
        summary = f"Applied network fingerprint adjustments: {', '.join(modified_params)}."
        print(summary)
        await event_logger.log({
            "service": "orchestrator",
            "event_type": "network_tuning_applied",
            "summary": summary,
            "profile": profile_name,
            "modified_params": modified_params,
        })

    # Collect active port information based on target decoy profile
    active_ports = []
    from honeypot_orchestrator.services.base import BaseUDPHoneypotService

    for s_name in target_service_names:
        service = services.get(s_name)
        if service:
            proto = "udp" if isinstance(service, BaseUDPHoneypotService) else "tcp"
            active_ports.append((service.port, proto))

    # Apply firewall rules to hide closed ports and ICMP scans
    setup_firewall(active_ports, web_port if web_enabled else None)
    apply_nfqueue_rules(profile_name)
