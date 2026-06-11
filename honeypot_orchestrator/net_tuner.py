from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from honeypot_orchestrator.event_logger import JSONLEventLogger

logger = logging.getLogger(__name__)


async def apply_profile_network_settings(profile_name: str, event_logger: JSONLEventLogger) -> None:
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

    # Define path mappings
    sysctl_paths = {
        "net.ipv4.ip_default_ttl": ("/proc/sys/net/ipv4/ip_default_ttl", target_ttl),
        "net.ipv4.tcp_timestamps": ("/proc/sys/net/ipv4/tcp_timestamps", target_timestamps),
        "net.ipv4.tcp_window_scaling": ("/proc/sys/net/ipv4/tcp_window_scaling", "1"),
        "net.ipv4.tcp_sack": ("/proc/sys/net/ipv4/tcp_sack", "1"),
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
