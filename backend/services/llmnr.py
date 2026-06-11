from __future__ import annotations

import asyncio
from typing import Any

from services.base import BaseUDPHoneypotService


class LLMNRProtocol(asyncio.DatagramProtocol):
    def __init__(self, service: LLMNRHoneypot) -> None:
        self.service = service
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr
        query_name = _parse_llmnr_name(data)
        if not query_name:
            return
        
        asyncio.create_task(
            self.service.log_event(
                "llmnr_query",
                src_ip=src_ip,
                src_port=src_port,
                query_name=query_name,
                summary=f"LLMNR query for {query_name}",
            )
        )
        
        response_ip = "127.0.0.1" if self.service.host in {"0.0.0.0", "::"} else self.service.host
        response = _build_llmnr_response(data, response_ip)
        if response and self.transport:
            self.transport.sendto(response, addr)


class LLMNRHoneypot(BaseUDPHoneypotService):
    def create_protocol(self) -> asyncio.DatagramProtocol:
        return LLMNRProtocol(self)


def _parse_llmnr_name(data: bytes) -> str:
    if len(data) < 12:
        return ""
    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        offset += 1
        if offset + length > len(data):
            return ""
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels)


def _build_llmnr_response(query_data: bytes, ip_address_str: str) -> bytes:
    if len(query_data) < 12:
        return b""
    transaction_id = query_data[0:2]
    offset = 12
    while offset < len(query_data):
        length = query_data[offset]
        if length == 0:
            offset += 1
            break
        offset += length + 1
    question_end = offset + 4
    if question_end > len(query_data):
        return b""
    question_sec = query_data[12:question_end]
    
    try:
        ip_bytes = bytes(int(part) for part in ip_address_str.split("."))
    except Exception:
        ip_bytes = b"\x7f\x00\x00\x01"
        
    header = b"".join(
        [
            transaction_id,
            b"\x80\x00",
            b"\x00\x01",
            b"\x00\x01",
            b"\x00\x00",
            b"\x00\x00",
        ]
    )
    
    answer = b"".join(
        [
            b"\xc0\x0c",
            b"\x00\x01",
            b"\x00\x01",
            (30).to_bytes(4, "big"),
            (4).to_bytes(2, "big"),
            ip_bytes,
        ]
    )
    
    return header + question_sec + answer
