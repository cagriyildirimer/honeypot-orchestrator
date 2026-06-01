"""Honeypot service implementations and service registry."""

from __future__ import annotations

from honeypot_orchestrator.services.base import BaseHoneypotService
from honeypot_orchestrator.services.dns import DNSHoneypot
from honeypot_orchestrator.services.ftp import FTPHoneypot
from honeypot_orchestrator.services.http import HTTPHoneypot
from honeypot_orchestrator.services.ldap import LDAPHoneypot
from honeypot_orchestrator.services.ldaps import LDAPSHoneypot
from honeypot_orchestrator.services.mssql import MSSQLHoneypot
from honeypot_orchestrator.services.netbios import NetBIOSHoneypot
from honeypot_orchestrator.services.rdp import RDPHoneypot
from honeypot_orchestrator.services.smb import SMBHoneypot
from honeypot_orchestrator.services.ssh import FakeSSHHoneypot
from honeypot_orchestrator.services.telnet import TelnetHoneypot

ServiceType = type[BaseHoneypotService]

SERVICE_REGISTRY: dict[str, ServiceType] = {
    "http_linux": HTTPHoneypot,
    "http_windows": HTTPHoneypot,
    "ssh_linux": FakeSSHHoneypot,
    "ftp_linux": FTPHoneypot,
    "telnet_linux": TelnetHoneypot,
    "dns_windows": DNSHoneypot,
    "netbios_windows": NetBIOSHoneypot,
    "ldap_windows": LDAPHoneypot,
    "ldaps_windows": LDAPSHoneypot,
    "mssql_windows": MSSQLHoneypot,
    "rdp_windows": RDPHoneypot,
    "smb_windows": SMBHoneypot,
}

PROFILE_AWARE_SERVICE_TYPES: tuple[ServiceType, ...] = (
    HTTPHoneypot,
    FakeSSHHoneypot,
    FTPHoneypot,
    TelnetHoneypot,
    SMBHoneypot,
    LDAPHoneypot,
    LDAPSHoneypot,
)
