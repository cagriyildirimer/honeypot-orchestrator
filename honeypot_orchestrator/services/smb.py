from __future__ import annotations

import asyncio
from datetime import UTC, datetime

from honeypot_orchestrator.services.base import BaseHoneypotService

SMB_HOSTNAME = "WIN-SRV2019"
SMB_DOMAIN = "CORP"
SMB_DNS_DOMAIN = "corp.local"
SMB_FQDN = f"{SMB_HOSTNAME.lower()}.{SMB_DNS_DOMAIN}"
SMB_NATIVE_OS = "Windows Server 2019 Standard 17763"
SMB_NATIVE_LANMAN = "Windows Server 2019 6.3"


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
                smb1_request = _parse_smb1_header(first_packet)
                await self.log_event(
                    "smb1_negotiate",
                    src_ip=src_ip,
                    src_port=src_port,
                    summary="SMB1 negotiate request captured.",
                )
                await _write_nbss_frame(
                    writer,
                    _build_smb1_negotiate_response(
                        multiplex_id=smb1_request["multiplex_id"],
                        process_id=smb1_request["process_id"],
                        user_id=smb1_request["user_id"],
                        tree_id=smb1_request["tree_id"],
                    ),
                )
                try:
                    session_setup_packet = await asyncio.wait_for(_read_nbss_frame(reader), timeout=5.0)
                except (TimeoutError, asyncio.IncompleteReadError):
                    return

                if session_setup_packet.startswith(b"\xffSMB"):
                    session_setup = _parse_smb1_header(session_setup_packet)
                    identity = _parse_smb1_session_setup_identity(session_setup_packet)
                    await self.log_event(
                        "login_attempt",
                        src_ip=src_ip,
                        src_port=src_port,
                        username=identity["username"],
                        domain=identity["domain"],
                        workstation=identity["workstation"],
                        summary=(
                            f"SMB1 login attempt for {identity['domain']}\\{identity['username']}"
                            if identity["username"]
                            else "SMB1 anonymous session setup captured."
                        ),
                    )
                    await _write_nbss_frame(
                        writer,
                        _build_smb1_session_setup_response(
                            multiplex_id=session_setup["multiplex_id"],
                            process_id=session_setup["process_id"],
                            tree_id=session_setup["tree_id"],
                            user_id=0x0800,
                        ),
                    )
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
            (0x0311).to_bytes(2, "little"),
            (0x0001).to_bytes(2, "little"),
            bytes.fromhex("7da29f0dd5324af6a9b7227bb3140f9c"),
            (0x0000007F).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            now.to_bytes(8, "little"),
            (now - (86400 * 10_000_000 * 30)).to_bytes(8, "little"),
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


def _parse_smb1_header(packet: bytes) -> dict[str, int]:
    if len(packet) < 32 or not packet.startswith(b"\xffSMB"):
        raise ValueError("Invalid SMB1 header.")
    return {
        "command": packet[4],
        "status": int.from_bytes(packet[5:9], "little"),
        "flags": packet[9],
        "flags2": int.from_bytes(packet[10:12], "little"),
        "tree_id": int.from_bytes(packet[24:26], "little"),
        "process_id": (int.from_bytes(packet[12:14], "little") << 16) | int.from_bytes(packet[26:28], "little"),
        "user_id": int.from_bytes(packet[28:30], "little"),
        "multiplex_id": int.from_bytes(packet[30:32], "little"),
    }


def _build_smb1_header(
    *,
    command: int,
    status: int,
    flags: int,
    flags2: int,
    tree_id: int,
    process_id: int,
    user_id: int,
    multiplex_id: int,
) -> bytes:
    return b"".join(
        [
            b"\xffSMB",
            bytes([command]),
            status.to_bytes(4, "little"),
            bytes([flags]),
            flags2.to_bytes(2, "little"),
            ((process_id >> 16) & 0xFFFF).to_bytes(2, "little"),
            b"\x00" * 8,
            b"\x00\x00",
            tree_id.to_bytes(2, "little"),
            (process_id & 0xFFFF).to_bytes(2, "little"),
            user_id.to_bytes(2, "little"),
            multiplex_id.to_bytes(2, "little"),
        ]
    )


def _build_smb1_negotiate_response(*, multiplex_id: int, process_id: int, user_id: int, tree_id: int) -> bytes:
    challenge = bytes.fromhex("6a4f9c1d2e7b4081")
    security_mode = 0x03
    capabilities = 0x8000E3FD
    now = _filetime(datetime.now(UTC))
    body = b"".join(
        [
            b"\x11",
            (0).to_bytes(2, "little"),
            bytes([security_mode]),
            (50).to_bytes(2, "little"),
            (1).to_bytes(2, "little"),
            (16644).to_bytes(4, "little"),
            (65536).to_bytes(4, "little"),
            (0x00004D2B).to_bytes(4, "little"),
            capabilities.to_bytes(4, "little"),
            now.to_bytes(8, "little"),
            (180).to_bytes(2, "little", signed=True),
            bytes([len(challenge)]),
            (len(challenge) + len(SMB_DOMAIN) + 1).to_bytes(2, "little"),
            challenge,
            SMB_DOMAIN.encode("ascii") + b"\x00",
        ]
    )
    header = _build_smb1_header(
        command=0x72,
        status=0,
        flags=0x98,
        flags2=0xC803,
        tree_id=tree_id,
        process_id=process_id,
        user_id=user_id,
        multiplex_id=multiplex_id,
    )
    return header + body


def _build_smb1_session_setup_response(*, multiplex_id: int, process_id: int, tree_id: int, user_id: int) -> bytes:
    payload = (
        SMB_NATIVE_OS.encode("ascii")
        + b"\x00"
        + SMB_NATIVE_LANMAN.encode("ascii")
        + b"\x00"
        + SMB_DOMAIN.encode("ascii")
        + b"\x00"
    )
    body = b"".join(
        [
            b"\x03",
            b"\xff",
            b"\x00",
            b"\x00\x00",
            b"\x01\x00",
            len(payload).to_bytes(2, "little"),
            payload,
        ]
    )
    header = _build_smb1_header(
        command=0x73,
        status=0,
        flags=0x98,
        flags2=0xC803,
        tree_id=tree_id,
        process_id=process_id,
        user_id=user_id,
        multiplex_id=multiplex_id,
    )
    return header + body


def _parse_smb1_session_setup_identity(packet: bytes) -> dict[str, str]:
    identity = {"username": "", "domain": "", "workstation": ""}
    ntlm_token = _find_ntlmssp_token(packet)
    if ntlm_token:
        return _parse_ntlm_authenticate(ntlm_token)

    if len(packet) < 32 + 1 + 26 + 2:
        return identity
    header = _parse_smb1_header(packet)
    body = packet[32:]
    word_count = body[0]
    parameter_bytes = word_count * 2
    if len(body) < 1 + parameter_bytes + 2 or parameter_bytes < 26:
        return identity
    parameters = body[1 : 1 + parameter_bytes]
    oem_password_length = int.from_bytes(parameters[14:16], "little")
    unicode_password_length = int.from_bytes(parameters[16:18], "little")
    data_start = 1 + parameter_bytes
    byte_count = int.from_bytes(body[data_start : data_start + 2], "little")
    data = body[data_start + 2 : data_start + 2 + byte_count]
    if len(data) < oem_password_length + unicode_password_length:
        return identity
    strings = data[oem_password_length + unicode_password_length :]
    if header["flags2"] & 0x8000:
        absolute_offset = 32 + data_start + 2 + oem_password_length + unicode_password_length
        if absolute_offset % 2:
            strings = strings[1:]
        parsed = _split_smb_strings(strings, encoding="utf-16le")
    else:
        parsed = _split_smb_strings(strings, encoding="ascii")
    if parsed:
        identity["username"] = parsed[0]
    if len(parsed) > 1:
        identity["domain"] = parsed[1]
    if len(parsed) > 2:
        identity["workstation"] = parsed[2]
    return identity


def _split_smb_strings(data: bytes, *, encoding: str) -> list[str]:
    try:
        if encoding == "utf-16le":
            parts = data.decode("utf-16le", errors="ignore").split("\x00")
        else:
            parts = data.decode("ascii", errors="ignore").split("\x00")
    except UnicodeDecodeError:
        return []
    return [part for part in parts if part]


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
    mech_types_raw = b"".join(
        [
            _asn1_oid("1.2.840.113554.1.2.2"),
            _asn1_oid("1.2.840.48018.1.2.2"),
            _asn1_oid("1.3.6.1.4.1.311.2.2.10"),
        ]
    )
    mech_sequence = b"\x30" + _asn1_length(len(mech_types_raw)) + mech_types_raw
    mech_types = b"\xa0" + _asn1_length(len(mech_sequence)) + mech_sequence
    inner = b"\x30" + _asn1_length(len(mech_types)) + mech_types
    return b"\x60" + _asn1_length(len(inner)) + inner


def _spnego_challenge_token() -> bytes:
    ntlm_challenge = _ntlm_challenge_message()
    supported_mech = _asn1_oid("1.3.6.1.4.1.311.2.2.10")
    neg_state = b"\xa0" + _asn1_length(3) + b"\x0a\x01\x01"
    mech = b"\xa1" + _asn1_length(len(supported_mech)) + supported_mech
    response_token = b"\xa2" + _asn1_length(len(ntlm_challenge)) + ntlm_challenge
    inner = b"\x30" + _asn1_length(len(neg_state) + len(mech) + len(response_token)) + neg_state + mech + response_token
    return b"\xa1" + _asn1_length(len(inner)) + inner


def _spnego_reject_token() -> bytes:
    state = b"\x0a\x01\x02"
    neg_state = b"\xa0" + _asn1_length(len(state)) + state
    inner = b"\x30" + _asn1_length(len(neg_state)) + neg_state
    return b"\xa1" + _asn1_length(len(inner)) + inner


def _ntlm_challenge_message() -> bytes:
    target_name = SMB_DOMAIN.encode("utf-16le")
    now = _filetime(datetime.now(UTC))
    target_info = b"".join(
        [
            _ntlm_av_pair(2, SMB_DOMAIN),
            _ntlm_av_pair(1, SMB_HOSTNAME),
            _ntlm_av_pair(4, SMB_DNS_DOMAIN),
            _ntlm_av_pair(3, SMB_FQDN),
            _ntlm_av_pair(7, now.to_bytes(8, "little"), raw=True),
            _ntlm_av_pair(9, b"\x02\x00\x00\x00", raw=True),
            _ntlm_av_pair(10, b"\x00" * 16, raw=True),
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
            (0xE28A8235).to_bytes(4, "little"),
            bytes.fromhex("0123456789abcdef"),
            b"\x00" * 8,
            len(target_info).to_bytes(2, "little"),
            len(target_info).to_bytes(2, "little"),
            target_info_offset.to_bytes(4, "little"),
            b"\x0a\x00\x63\x45\x00\x00\x00\x0f",
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


def _asn1_oid(oid: str) -> bytes:
    parts = [int(part) for part in oid.split(".")]
    if len(parts) < 2:
        raise ValueError("Invalid OID.")
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
            continue
        stack: list[int] = []
        while part:
            stack.append(part & 0x7F)
            part >>= 7
        for index in range(len(stack) - 1, -1, -1):
            byte = stack[index]
            if index:
                byte |= 0x80
            encoded.append(byte)
    return b"\x06" + _asn1_length(len(encoded)) + bytes(encoded)


def _ntlm_av_pair(av_id: int, value: str | bytes, *, raw: bool = False) -> bytes:
    if raw:
        data = value if isinstance(value, bytes) else value.encode("utf-16le")
    else:
        data = value.encode("utf-16le") if isinstance(value, str) else value
    return av_id.to_bytes(2, "little") + len(data).to_bytes(2, "little") + data


def _filetime(value: datetime) -> int:
    unix_time = int(value.timestamp() * 10_000_000)
    return unix_time + 116444736000000000
