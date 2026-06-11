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
        if len(data) < 12:
            return
        
        # Determine query type: Name Query (0x0020) or Node Status Query (0x0021)
        # Questions section starts at 12. NetBIOS name is always 1 + 32 + 1 = 34 bytes.
        # Query type starts at offset 46 (2 bytes).
        if len(data) < 48:
            return
        
        query_type = data[46:48]
        query_name = _parse_netbios_ns_name(data)
        if not query_name:
            return
        
        if query_type == b"\x00\x21":
            asyncio.create_task(
                self.service.log_event(
                    "netbios_ns_node_status_query",
                    src_ip=src_ip,
                    src_port=src_port,
                    query_name=query_name,
                    summary=f"NetBIOS NS Node Status query (NBSTAT) from {src_ip}",
                )
            )
        else:
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
        if query_type == b"\x00\x21":
            response = _build_netbios_ns_node_status_response(data)
        else:
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


def _build_netbios_ns_node_status_response(query_data: bytes) -> bytes:
    if len(query_data) < 12:
        return b""
    transaction_id = query_data[0:2]
    name_sec = query_data[12:12+34]
    
    header = b"".join(
        [
            transaction_id,
            b"\x84\x00",  # Flags: Response, Authoritative
            b"\x00\x00",  # Questions: 0
            b"\x00\x01",  # Answer RRs: 1
            b"\x00\x00",  # Authority RRs: 0
            b"\x00\x00",  # Additional RRs: 0
        ]
    )
    
    # 3 names: WIN-SRV2019 (0x00 Workstation), CORP (0x00 Workgroup), WIN-SRV2019 (0x20 Server)
    n1 = b"WIN-SRV2019".ljust(15) + b"\x00" + b"\x04\x00"
    n2 = b"CORP".ljust(15) + b"\x00" + b"\x84\x00"
    n3 = b"WIN-SRV2019".ljust(15) + b"\x20" + b"\x04\x00"
    names_payload = n1 + n2 + n3
    
    # Stats: MAC Address + 40 bytes of 0x00
    mac_addr = b"\x00\x15\x5d\xa1\xb2\xc3"
    stats_payload = mac_addr + b"\x00" * 40
    
    data_payload = b"\x03" + names_payload + stats_payload
    data_len = len(data_payload)
    
    answer = b"".join(
        [
            name_sec,
            b"\x00\x21",  # TYPE: NBSTAT
            b"\x00\x01",  # CLASS: IN
            b"\x00\x00\x00\x00",  # TTL: 0
            data_len.to_bytes(2, "big"),
            data_payload,
        ]
    )
    
    return header + answer
