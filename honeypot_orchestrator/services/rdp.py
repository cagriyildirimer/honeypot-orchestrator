from __future__ import annotations

import asyncio

from honeypot_orchestrator.services.base import BaseHoneypotService


class RDPHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            packet = await _read_tpkt_frame(reader)
            await self.log_event(
                "rdp_connection_request",
                src_ip=src_ip,
                src_port=src_port,
                cookie=_extract_rdp_cookie(packet),
                summary="RDP X.224 connection request captured.",
            )
            writer.write(_build_rdp_negotiation_failure())
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


async def _read_tpkt_frame(reader: asyncio.StreamReader) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
    total_length = int.from_bytes(header[2:4], "big")
    if total_length < 4:
        raise ValueError("Invalid TPKT length.")
    return header + await asyncio.wait_for(reader.readexactly(total_length - 4), timeout=10.0)


def _extract_rdp_cookie(packet: bytes) -> str:
    marker = b"Cookie: mstshash="
    start = packet.find(marker)
    if start == -1:
        return ""
    end = packet.find(b"\r\n", start)
    if end == -1:
        end = len(packet)
    return packet[start + len(marker) : end].decode("ascii", errors="replace")


def _build_rdp_negotiation_failure() -> bytes:
    return b"".join(
        [
            b"\x03\x00\x00\x13",
            b"\x0e\xd0\x00\x00\x12\x34\x00",
            b"\x03\x00\x08\x00\x01\x00\x00\x00",
        ]
    )
