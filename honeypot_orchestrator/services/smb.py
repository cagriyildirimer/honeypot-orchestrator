from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from honeypot_orchestrator.services.base import BaseHoneypotService


class SMBHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        session_id = 0x1000

        try:
            first_packet = await _read_nbss_frame(reader)
            if first_packet.startswith(b"\xffSMB"):
                await self.log_event(
                    "smb1_negotiate",
                    src_ip=src_ip,
                    src_port=src_port,
                    summary="SMB1 negotiate request captured.",
                )
                await _write_nbss_frame(writer, _build_smb1_not_supported_response())
                return

            if not first_packet.startswith(b"\xfeSMB"):
                await self.log_event(
                    "smb_unknown_packet",
                    src_ip=src_ip,
                    src_port=src_port,
                    signature=first_packet[:16].hex(),
                    summary="Unknown SMB payload captured.",
                )
                return

            negotiate_request = _parse_smb2_header(first_packet)
            await self.log_event(
                "smb_negotiate",
                src_ip=src_ip,
                src_port=src_port,
                dialects=", ".join(_extract_smb2_dialects(first_packet)),
                summary="SMB2 negotiate request captured.",
            )
            await _write_nbss_frame(
                writer,
                _build_smb2_negotiate_response(
                    message_id=negotiate_request["message_id"],
                    credit_request=negotiate_request["credits"],
                ),
            )

            session_setup_packet = await _read_nbss_frame(reader)
            session_setup_request = _parse_smb2_header(session_setup_packet)
            ntlm_negotiate = _extract_session_setup_security_blob(session_setup_packet)
            await self.log_event(
                "smb_session_setup",
                src_ip=src_ip,
                src_port=src_port,
                ntlm_message_type=_ntlm_message_type(ntlm_negotiate),
                summary="SMB session setup negotiate captured.",
            )
            await _write_nbss_frame(
                writer,
                _build_smb2_session_setup_challenge(
                    message_id=session_setup_request["message_id"],
                    credit_request=session_setup_request["credits"],
                    session_id=session_id,
                ),
            )

            auth_packet = await _read_nbss_frame(reader)
            auth_request = _parse_smb2_header(auth_packet)
            ntlm_auth = _extract_session_setup_security_blob(auth_packet)
            identity = _parse_ntlm_authenticate(ntlm_auth)
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                username=identity["username"],
                domain=identity["domain"],
                workstation=identity["workstation"],
                summary=(
                    f"SMB login attempt for {identity['domain']}\\{identity['username']}"
                    if identity["username"]
                    else "SMB login attempt for <unknown>"
                ),
            )
            await _write_nbss_frame(
                writer,
                _build_smb2_logon_failure(
                    message_id=auth_request["message_id"],
                    credit_request=auth_request["credits"],
                    session_id=session_id,
                ),
            )
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


async def _read_nbss_frame(reader: asyncio.StreamReader) -> bytes:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=12.0)
    length = int.from_bytes(header[1:4], "big")
    if length <= 0:
        raise ValueError("Invalid NBSS frame length.")
    return await asyncio.wait_for(reader.readexactly(length), timeout=12.0)


async def _write_nbss_frame(writer: asyncio.StreamWriter, payload: bytes) -> None:
    writer.write(b"\x00" + len(payload).to_bytes(3, "big") + payload)
    await writer.drain()


def _parse_smb2_header(packet: bytes) -> dict[str, int]:
    if len(packet) < 64 or not packet.startswith(b"\xfeSMB"):
        raise ValueError("Invalid SMB2 header.")
    return {
        "command": int.from_bytes(packet[12:14], "little"),
        "credits": int.from_bytes(packet[14:16], "little"),
        "message_id": int.from_bytes(packet[24:32], "little"),
        "tree_id": int.from_bytes(packet[36:40], "little"),
        "session_id": int.from_bytes(packet[40:48], "little"),
    }


def _extract_smb2_dialects(packet: bytes) -> list[str]:
    if len(packet) < 68:
        return []
    dialect_count = int.from_bytes(packet[64:66], "little")
    offset = 64 + 36
    dialects: list[str] = []
    for index in range(dialect_count):
        start = offset + (index * 2)
        end = start + 2
        if end > len(packet):
            break
        dialects.append(_dialect_name(int.from_bytes(packet[start:end], "little")))
    return dialects


def _build_smb2_negotiate_response(*, message_id: int, credit_request: int) -> bytes:
    security_blob = _spnego_negotiate_token()
    security_offset = 64 + 65
    now = _filetime(datetime.now(UTC))
    body = b"".join(
        [
            (65).to_bytes(2, "little"),
            (1).to_bytes(2, "little"),
            (0x0302).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
            bytes.fromhex("7da29f0dd5324af6a9b7227bb3140f9c"),
            (0x00000044).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            now.to_bytes(8, "little"),
            now.to_bytes(8, "little"),
            security_offset.to_bytes(2, "little"),
            len(security_blob).to_bytes(2, "little"),
            (0).to_bytes(4, "little"),
            security_blob,
        ]
    )
    header = _build_smb2_header(
        command=0,
        message_id=message_id,
        credit_request=credit_request,
        status=0,
        session_id=0,
        tree_id=0,
        flags=0x00000001,
    )
    return header + body


def _build_smb2_session_setup_challenge(*, message_id: int, credit_request: int, session_id: int) -> bytes:
    security_blob = _spnego_challenge_token()
    security_offset = 64 + 8
    body = b"".join(
        [
            (9).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
            security_offset.to_bytes(2, "little"),
            len(security_blob).to_bytes(2, "little"),
            security_blob,
        ]
    )
    header = _build_smb2_header(
        command=1,
        message_id=message_id,
        credit_request=credit_request,
        status=0xC0000016,
        session_id=session_id,
        tree_id=0,
        flags=0x00000001,
    )
    return header + body


def _build_smb2_logon_failure(*, message_id: int, credit_request: int, session_id: int) -> bytes:
    security_blob = _spnego_reject_token()
    security_offset = 64 + 8
    body = b"".join(
        [
            (9).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
            security_offset.to_bytes(2, "little"),
            len(security_blob).to_bytes(2, "little"),
            security_blob,
        ]
    )
    header = _build_smb2_header(
        command=1,
        message_id=message_id,
        credit_request=credit_request,
        status=0xC000006D,
        session_id=session_id,
        tree_id=0,
        flags=0x00000001,
    )
    return header + body


def _build_smb2_header(
    *,
    command: int,
    message_id: int,
    credit_request: int,
    status: int,
    session_id: int,
    tree_id: int,
    flags: int,
) -> bytes:
    return b"".join(
        [
            b"\xfeSMB",
            (64).to_bytes(2, "little"),
            (1).to_bytes(2, "little"),
            status.to_bytes(4, "little"),
            command.to_bytes(2, "little"),
            max(1, credit_request).to_bytes(2, "little"),
            flags.to_bytes(4, "little"),
            (0).to_bytes(4, "little"),
            message_id.to_bytes(8, "little"),
            (0).to_bytes(4, "little"),
            tree_id.to_bytes(4, "little"),
            session_id.to_bytes(8, "little"),
            bytes.fromhex("9f6e5e13c4b144d7a8ff3fb0c4a07e11"),
        ]
    )


def _build_smb1_not_supported_response() -> bytes:
    return b"".join(
        [
            b"\xffSMB",
            b"\x72",
            b"\x00\x00\x00\x00",
            b"\x98",
            b"\x01\x28",
            b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00",
            b"\x00\x00",
        ]
    )


def _extract_session_setup_security_blob(packet: bytes) -> bytes:
    if len(packet) < 88:
        return b""
    security_offset = int.from_bytes(packet[76:78], "little")
    security_length = int.from_bytes(packet[78:80], "little")
    if security_length <= 0:
        return b""
    start = security_offset
    end = start + security_length
    if end > len(packet):
        return b""
    return packet[start:end]


def _ntlm_message_type(blob: bytes) -> str:
    token = _find_ntlmssp_token(blob)
    if len(token) < 12:
        return "unknown"
    message_type = int.from_bytes(token[8:12], "little")
    return {
        1: "negotiate",
        2: "challenge",
        3: "authenticate",
    }.get(message_type, str(message_type))


def _parse_ntlm_authenticate(blob: bytes) -> dict[str, str]:
    token = _find_ntlmssp_token(blob)
    if len(token) < 52 or token[:8] != b"NTLMSSP\x00":
        return {"username": "", "domain": "", "workstation": ""}
    if int.from_bytes(token[8:12], "little") != 3:
        return {"username": "", "domain": "", "workstation": ""}
    return {
        "domain": _read_ntlm_field(token, 28),
        "username": _read_ntlm_field(token, 36),
        "workstation": _read_ntlm_field(token, 44),
    }


def _read_ntlm_field(token: bytes, offset: int) -> str:
    if offset + 8 > len(token):
        return ""
    length = int.from_bytes(token[offset : offset + 2], "little")
    data_offset = int.from_bytes(token[offset + 4 : offset + 8], "little")
    if length <= 0 or data_offset + length > len(token):
        return ""
    return token[data_offset : data_offset + length].decode("utf-16le", errors="replace")


def _find_ntlmssp_token(blob: bytes) -> bytes:
    marker = b"NTLMSSP\x00"
    index = blob.find(marker)
    if index == -1:
        return b""
    return blob[index:]


def _spnego_negotiate_token() -> bytes:
    ntlm_oid = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    mech_type = b"\x06" + bytes([len(ntlm_oid)]) + ntlm_oid
    mech_sequence = b"\x30" + bytes([len(mech_type)]) + mech_type
    mech_types = b"\xa0" + bytes([len(mech_sequence)]) + mech_sequence
    inner = b"\x30" + bytes([len(mech_types)]) + mech_types
    return b"\x60" + bytes([len(inner)]) + inner


def _spnego_challenge_token() -> bytes:
    ntlm_challenge = _ntlm_challenge_message()
    response_token = b"\xa2" + _asn1_length(len(ntlm_challenge)) + ntlm_challenge
    inner = b"\x30" + _asn1_length(len(response_token)) + response_token
    return b"\xa1" + _asn1_length(len(inner)) + inner


def _spnego_reject_token() -> bytes:
    state = b"\x0a\x01\x02"
    neg_state = b"\xa0" + _asn1_length(len(state)) + state
    inner = b"\x30" + _asn1_length(len(neg_state)) + neg_state
    return b"\xa1" + _asn1_length(len(inner)) + inner


def _ntlm_challenge_message() -> bytes:
    target_name = "CORP".encode("utf-16le")
    target_info = b"".join(
        [
            (2).to_bytes(2, "little"),
            (8).to_bytes(2, "little"),
            "CORP".encode("utf-16le"),
            (1).to_bytes(2, "little"),
            (22).to_bytes(2, "little"),
            "WIN-SRV2019".encode("utf-16le"),
            (0).to_bytes(2, "little"),
            (0).to_bytes(2, "little"),
        ]
    )
    target_name_offset = 56
    target_info_offset = target_name_offset + len(target_name)
    return b"".join(
        [
            b"NTLMSSP\x00",
            (2).to_bytes(4, "little"),
            len(target_name).to_bytes(2, "little"),
            len(target_name).to_bytes(2, "little"),
            target_name_offset.to_bytes(4, "little"),
            (0x8201).to_bytes(4, "little"),
            bytes.fromhex("0123456789abcdef"),
            b"\x00" * 8,
            len(target_info).to_bytes(2, "little"),
            len(target_info).to_bytes(2, "little"),
            target_info_offset.to_bytes(4, "little"),
            (0x0000000F).to_bytes(4, "little"),
            target_name,
            target_info,
        ]
    )


def _dialect_name(code: int) -> str:
    return {
        0x0202: "SMB 2.0.2",
        0x0210: "SMB 2.1",
        0x0300: "SMB 3.0",
        0x0302: "SMB 3.0.2",
        0x0311: "SMB 3.1.1",
    }.get(code, hex(code))


def _asn1_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _filetime(value: datetime) -> int:
    unix_time = int(value.timestamp() * 10_000_000)
    return unix_time + 116444736000000000
