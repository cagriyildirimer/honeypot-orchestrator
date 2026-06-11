from __future__ import annotations

import asyncio

from services.base import BaseHoneypotService


class DNSHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            length_prefix = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
            message_length = int.from_bytes(length_prefix, "big")
            payload = await asyncio.wait_for(reader.readexactly(message_length), timeout=10.0)
            query = _parse_dns_query(payload)
            await self.log_event(
                "dns_query",
                src_ip=src_ip,
                src_port=src_port,
                query_name=query["name"],
                query_type=query["type_name"],
                query_class=query["class_name"],
                summary=f"DNS {query['type_name']} {query['name']}",
            )
            response = _build_dns_response(
                payload,
                rcode=3,
                authoritative=True,
                recursion_available=True,
            )
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
        except (asyncio.IncompleteReadError, BrokenPipeError, ConnectionResetError):
            await self.log_event("client_disconnected", src_ip=src_ip, src_port=src_port)
        except Exception as exc:
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)


def _parse_dns_query(payload: bytes) -> dict[str, str]:
    if len(payload) < 12:
        return {
            "name": "<malformed>",
            "type_name": "UNKNOWN",
            "class_name": "UNKNOWN",
        }
    index = 12
    labels: list[str] = []
    while index < len(payload):
        length = payload[index]
        index += 1
        if length == 0:
            break
        if index + length > len(payload):
            return {
                "name": "<malformed>",
                "type_name": "UNKNOWN",
                "class_name": "UNKNOWN",
            }
        labels.append(payload[index : index + length].decode("ascii", errors="replace"))
        index += length
    qtype = int.from_bytes(payload[index : index + 2], "big") if index + 2 <= len(payload) else 0
    qclass = int.from_bytes(payload[index + 2 : index + 4], "big") if index + 4 <= len(payload) else 0
    return {
        "name": ".".join(labels) if labels else ".",
        "type_name": _dns_type_name(qtype),
        "class_name": _dns_class_name(qclass),
    }


def _build_dns_response(
    payload: bytes,
    *,
    rcode: int,
    authoritative: bool,
    recursion_available: bool,
) -> bytes:
    transaction_id = payload[:2] if len(payload) >= 2 else b"\x00\x00"
    question_count = payload[4:6] if len(payload) >= 6 else b"\x00\x00"
    flags = 0x8000 | 0x0100 | (rcode & 0x0F)
    if authoritative:
        flags |= 0x0400
    if recursion_available:
        flags |= 0x0080

    question = b""
    if len(payload) >= 12:
        index = 12
        while index < len(payload):
            length = payload[index]
            index += 1
            if length == 0:
                break
            index += length
        index += 4
        question = payload[12:index]

    return b"".join(
        [
            transaction_id,
            flags.to_bytes(2, "big"),
            question_count,
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            question,
        ]
    )


def _dns_type_name(qtype: int) -> str:
    return {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }.get(qtype, f"TYPE{qtype}")


def _dns_class_name(qclass: int) -> str:
    return {
        1: "IN",
        3: "CH",
        4: "HS",
        255: "ANY",
    }.get(qclass, f"CLASS{qclass}")
