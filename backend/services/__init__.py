"""Honeypot service implementations and service registry."""

from __future__ import annotations

from services.base import BaseHoneypotService, BaseUDPHoneypotService
from services.dns import DNSHoneypot
from services.ftp import FTPHoneypot
from services.http import HTTPHoneypot
from services.ldap import LDAPHoneypot
from services.ldaps import LDAPSHoneypot
from services.llmnr import LLMNRHoneypot
from services.mssql import MSSQLHoneypot
from services.nbtnns import NBTNSSHoneypot
from services.netbios import NetBIOSHoneypot
from services.rdp import RDPHoneypot
from services.smb import SMBHoneypot
from services.ssh import FakeSSHHoneypot
from services.telnet import TelnetHoneypot
from services.rpc import RPCHoneypot

ServiceType = type[BaseHoneypotService] | type[BaseUDPHoneypotService]
ServiceInstance = BaseHoneypotService | BaseUDPHoneypotService

SERVICE_REGISTRY: dict[str, ServiceType] = {
    "http_linux": HTTPHoneypot,
    "http_windows": HTTPHoneypot,
    "ssh_linux": FakeSSHHoneypot,
    "ssh_windows": FakeSSHHoneypot,
    "ftp_linux": FTPHoneypot,
    "telnet_linux": TelnetHoneypot,
    "dns_windows": DNSHoneypot,
    "netbios_windows": NetBIOSHoneypot,
    "ldap_windows": LDAPHoneypot,
    "ldaps_windows": LDAPSHoneypot,
    "mssql_windows": MSSQLHoneypot,
    "rdp_windows": RDPHoneypot,
    "smb_windows": SMBHoneypot,
    "llmnr_windows": LLMNRHoneypot,
    "nbtnns_windows": NBTNSSHoneypot,
    "rpc_windows": RPCHoneypot,
}

PROFILE_AWARE_SERVICE_TYPES: tuple[type[BaseHoneypotService], ...] = (
    HTTPHoneypot,
    FakeSSHHoneypot,
    FTPHoneypot,
    TelnetHoneypot,
    SMBHoneypot,
    LDAPHoneypot,
    LDAPSHoneypot,
)
