from __future__ import annotations

import asyncio

from services.base import BaseHoneypotService


class NetBIOSHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            header = await asyncio.wait_for(reader.readexactly(4), timeout=10.0)
            packet_type = header[0]
            payload_length = int.from_bytes(header[1:4], "big")
            payload = b""
            if payload_length:
                payload = await asyncio.wait_for(reader.readexactly(payload_length), timeout=10.0)

            called_name, calling_name = _parse_session_request_names(payload)
            await self.log_event(
                "netbios_session_request",
                src_ip=src_ip,
                src_port=src_port,
                packet_type=f"0x{packet_type:02x}",
                called_name=called_name,
                calling_name=calling_name,
                summary=f"NetBIOS session request for {called_name}",
            )

            if packet_type == 0x81:
                await self.write_bytes(writer, b"\x82\x00\x00\x00")
                try:
                    next_frame = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                except TimeoutError:
                    next_frame = b""
                if next_frame:
                    await self.log_event(
                        "netbios_followup",
                        src_ip=src_ip,
                        src_port=src_port,
                        signature=next_frame[:16].hex(),
                        summary="NetBIOS follow-up payload captured.",
                    )
            elif packet_type == 0x00 and payload.startswith(b"\xffSMB"):
                # Nmap sends an SMB Negotiate Request directly wrapped in a Session Message (0x00)
                from services.smb import _parse_smb1_header, _build_smb1_negotiate_response
                smb1_request = _parse_smb1_header(header + payload)
                await self.log_event(
                    "netbios_smb_negotiate",
                    src_ip=src_ip,
                    src_port=src_port,
                    summary="NetBIOS received direct SMB1 negotiate request.",
                )
                smb_resp = _build_smb1_negotiate_response(
                    multiplex_id=smb1_request["multiplex_id"],
                    process_id=smb1_request["process_id"],
                    user_id=smb1_request["user_id"],
                    tree_id=smb1_request["tree_id"],
                    ntlm_challenge=b"\x11\x22\x33\x44\x55\x66\x77\x88",
                    domain="CORP",
                )
                # Wrap it in a NetBIOS Session Message header
                nbss_header = b"\x00\x00" + len(smb_resp).to_bytes(2, "big")
                await self.write_bytes(writer, nbss_header + smb_resp)
            else:
                await self.write_bytes(writer, b"\x83\x00\x00\x01\x80")
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

def _parse_session_request_names(payload: bytes) -> tuple[str, str]:
    if len(payload) < 68:
        return "<unknown>", "<unknown>"
    called_name = _decode_netbios_name(payload[1:33])
    calling_name = _decode_netbios_name(payload[35:67])
    return called_name, calling_name


def _decode_netbios_name(encoded: bytes) -> str:
    if len(encoded) != 32:
        return "<unknown>"
    decoded = bytearray()
    for index in range(0, len(encoded), 2):
        high = encoded[index] - 0x41
        low = encoded[index + 1] - 0x41
        if high < 0 or low < 0:
            return "<unknown>"
        decoded.append((high << 4) | low)
    return decoded.rstrip(b" ").decode("ascii", errors="replace")
