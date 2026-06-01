from __future__ import annotations

import asyncio
from typing import Any

from honeypot_orchestrator.services.base import BaseUDPHoneypotService


class NBTNSSProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: NBTNSSHoneypot) -> None:
        self.service = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr
        query_name = _parse_netbios_ns_name(data)
        if not query_name:
            return
        
        asyncio.create_task(
            self.service.log_event(
                "netbios_ns_query",
                src_ip=src_ip,
                src_port=src_port,
                query_name=query_name,
                summary=f"NetBIOS NS query for {query_name}",
            )
        )
        
        response_ip = "127.0.0.1" if self.service.host in {"0.0.0.0", "::"} else self.service.host
        response = _build_netbios_ns_response(data, response_ip)
        if response and self.transport:
            self.transport.sendto(response, addr)


class NBTNSSHoneypot(BaseUDPHoneypotService):
    def create_protocol(self) -> asyncio.DatagramProtocol:
        return NBTNSSProtocol(self)


def _decode_netbios_ns_name(encoded: bytes) -> str:
    if len(encoded) < 32:
        return ""
    decoded = bytearray()
    for index in range(0, 32, 2):
        high = encoded[index] - 0x41
        low = encoded[index + 1] - 0x41
        decoded.append((high << 4) | low)
    return decoded.rstrip(b" ").decode("ascii", errors="replace")


def _parse_netbios_ns_name(data: bytes) -> str:
    if len(data) < 12 + 33:
        return ""
    name_len = data[12]
    if name_len != 32:
        return ""
    return _decode_netbios_ns_name(data[13:13+32])


def _build_netbios_ns_response(query_data: bytes, ip_address_str: str) -> bytes:
    if len(query_data) < 12:
        return b""
    transaction_id = query_data[0:2]
    name_sec = query_data[12:12+34]
    
    try:
        ip_bytes = bytes(int(part) for part in ip_address_str.split("."))
    except Exception:
        ip_bytes = b"\x7f\x00\x00\x01"
        
    header = b"".join(
        [
            transaction_id,
            b"\x85\x00",
            b"\x00\x00",
            b"\x00\x01",
            b"\x00\x00",
            b"\x00\x00",
        ]
    )
    
    answer = b"".join(
        [
            name_sec,
            b"\x00\x20",
            b"\x00\x01",
            (300000).to_bytes(4, "big"),
            (6).to_bytes(2, "big"),
            b"\x00\x00",
            ip_bytes,
        ]
    )
    
    return header + answer
