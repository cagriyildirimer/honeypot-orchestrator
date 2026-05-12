from __future__ import annotations

import asyncio

from honeypot_orchestrator.services.base import BaseHoneypotService


class MSSQLHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            packet_type, payload = await _read_tds_packet(reader)
            await self.log_event(
                "mssql_prelogin",
                src_ip=src_ip,
                src_port=src_port,
                packet_type=f"0x{packet_type:02x}",
                summary="MSSQL prelogin captured.",
            )
            if packet_type == 0x12:
                await _write_tds_packet(writer, 0x04, _build_prelogin_response())

            try:
                login_packet_type, login_payload = await asyncio.wait_for(
                    _read_tds_packet(reader),
                    timeout=5.0,
                )
            except (TimeoutError, asyncio.IncompleteReadError):
                return

            username = _extract_login7_username(login_payload) if login_packet_type == 0x10 else ""
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                username=username,
                summary=f"MSSQL login attempt for {username or '<unknown>'}",
            )
            await _write_tds_packet(writer, 0x04, _build_login_error_response())
        except (BrokenPipeError, ConnectionResetError):
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


async def _read_tds_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await asyncio.wait_for(reader.readexactly(8), timeout=10.0)
    packet_type = header[0]
    total_length = int.from_bytes(header[2:4], "big")
    if total_length < 8:
        raise ValueError("Invalid TDS packet length.")
    payload = await asyncio.wait_for(reader.readexactly(total_length - 8), timeout=10.0)
    return packet_type, payload


async def _write_tds_packet(writer: asyncio.StreamWriter, packet_type: int, payload: bytes) -> None:
    header = bytes([packet_type, 0x01]) + (len(payload) + 8).to_bytes(2, "big") + b"\x00\x00\x01\x00"
    writer.write(header + payload)
    await writer.drain()


def _build_prelogin_response() -> bytes:
    table_size = 5 + 5 + 5 + 1
    version_offset = table_size
    encryption_offset = version_offset + 6
    instance_offset = encryption_offset + 1
    return b"".join(
        [
            b"\x00" + version_offset.to_bytes(2, "big") + b"\x00\x06",
            b"\x01" + encryption_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\x02" + instance_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\xff",
            b"\x00\x00\x0f\x00\x07\xd0",
            b"\x02",
            b"\x00",
        ]
    )


def _build_login_error_response() -> bytes:
    error_text = "Login failed for user"
    server_name = "WIN-SRV2019"
    error_token = b"".join(
        [
            b"\xaa",
            (16 + len(error_text.encode("utf-16le")) + len(server_name.encode("utf-16le"))).to_bytes(2, "little"),
            (18456).to_bytes(4, "little"),
            b"\x01",
            b"\x0e",
            len(error_text).to_bytes(2, "little"),
            error_text.encode("utf-16le"),
            len(server_name).to_bytes(1, "little"),
            server_name.encode("utf-16le"),
            b"\x01",
        ]
    )
    done_token = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return error_token + done_token


def _extract_login7_username(payload: bytes) -> str:
    if len(payload) < 48:
        return ""
    username_offset = int.from_bytes(payload[40:42], "little")
    username_length = int.from_bytes(payload[42:44], "little")
    if username_length <= 0:
        return ""
    start = username_offset
    end = start + (username_length * 2)
    if end > len(payload):
        return ""
    return payload[start:end].decode("utf-16le", errors="replace")
