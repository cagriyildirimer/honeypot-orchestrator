from __future__ import annotations

import asyncio
from services.base import BaseHoneypotService


def _uses_tds72_plus(tds_version_bytes: bytes) -> bool:
    if len(tds_version_bytes) < 4:
        return False
    
    # Parse as both big-endian and little-endian
    val_be = int.from_bytes(tds_version_bytes, "big")
    val_le = int.from_bytes(tds_version_bytes, "little")
    
    # Legacy TDS versions (7.0, 7.1)
    legacy_versions = {
        0x00000070, 0x07000000,
        0x00000071, 0x07010000, 0x01000071
    }
    
    # Known TDS login versions
    known_versions = {
        0x00000070, 0x07000000,
        0x00000071, 0x07010000, 0x01000071,
        0x02000972, 0x03000A73, 0x03000B73, 0x04000074, 0x08000000
    }
    
    if val_le in known_versions:
        return val_le not in legacy_versions
    elif val_be in known_versions:
        return val_be not in legacy_versions
    else:
        # Fallback: if unrecognized, check if it looks like a 7.2+ version in either endianness.
        major_be = tds_version_bytes[0]
        major_le = tds_version_bytes[3]
        
        # If big-endian version is 0x08 or >= 0x72
        if major_be == 0x08 or 0x72 <= major_be <= 0x74:
            return True
        # If little-endian version is 0x08 or >= 0x72
        if major_le == 0x08 or 0x72 <= major_le <= 0x74:
            return True
            
        return False


class MSSQLHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            # 1. Read first packet (either PRELOGIN or LOGIN7 directly)
            try:
                packet_type, payload = await asyncio.wait_for(
                    _read_tds_packet(reader),
                    timeout=10.0,
                )
            except (TimeoutError, asyncio.IncompleteReadError):
                return

            if packet_type == 0x12:
                # Client sent PRELOGIN
                await self.log_event(
                    "mssql_prelogin",
                    src_ip=src_ip,
                    src_port=src_port,
                    packet_type=f"0x{packet_type:02x}",
                    summary="MSSQL prelogin captured.",
                )
                await _write_tds_packet(writer, 0x04, _build_prelogin_response())

                # Read LOGIN7 packet next
                try:
                    login_packet_type, login_payload = await asyncio.wait_for(
                        _read_tds_packet(reader),
                        timeout=10.0,
                    )
                except (TimeoutError, asyncio.IncompleteReadError):
                    return

                if login_packet_type != 0x10:
                    return
            elif packet_type == 0x10:
                # Client bypassed PRELOGIN and sent LOGIN7 directly
                await self.log_event(
                    "mssql_login_direct",
                    src_ip=src_ip,
                    src_port=src_port,
                    packet_type=f"0x{packet_type:02x}",
                    summary="MSSQL direct login (no prelogin) captured.",
                )
                login_payload = payload
            else:
                return

            # Use the raw login payload directly since LOGIN7 does not contain an All Headers block
            login7_payload = login_payload

            # Extract TDS version from LOGIN7 payload (offset 4, 4 bytes)
            tds_version_bytes = login7_payload[4:8] if len(login7_payload) >= 8 else b"\x00\x00\x00\x71"
            uses_tds72 = _uses_tds72_plus(tds_version_bytes)

            # 3. Extract LOGIN7 credentials and metadata
            username = _extract_login7_string(login7_payload, 40, 42)
            password = _extract_login7_password(login7_payload)
            client_hostname = _extract_login7_string(login7_payload, 36, 38)
            app_name = _extract_login7_string(login7_payload, 48, 50)
            database_name = _extract_login7_string(login7_payload, 68, 70)

            # 4. Validate credentials
            if _is_decoy_credential(username, password):
                # SUCCESS!
                await self.log_event(
                    "login_success",
                    src_ip=src_ip,
                    src_port=src_port,
                    service=self.name,
                    username=username,
                    password=password,
                    client_hostname=client_hostname,
                    app_name=app_name,
                    database_name=database_name,
                    summary=f"MSSQL successful login for user '{username}' (Host: {client_hostname}, App: {app_name})",
                )
                
                # Write login success response (TDS packet type 0x04)
                await _write_tds_packet(writer, 0x04, _build_login_success_response(uses_tds72))
                
                # 5. Enter Interactive Query Loop!
                while True:
                    try:
                        cmd_type, cmd_payload = await asyncio.wait_for(
                            _read_tds_packet(reader),
                            timeout=60.0,  # wait up to 60s for queries
                        )
                    except (TimeoutError, asyncio.IncompleteReadError):
                        break
                    
                    if cmd_type == 0x01:  # SQL Batch
                        # Preprocess query payload to skip All Headers block if present
                        query_payload = _skip_all_headers(cmd_payload)
                        query_str = query_payload.decode("utf-16le", errors="ignore").strip()
                        # Clean up query string from prefix garbage if present
                        if "\x00" in query_str:
                            query_str = "".join([c for c in query_str if ord(c) >= 32])
                        query_lower = query_str.lower()
                        
                        await self.log_event(
                            "sql_query",
                            src_ip=src_ip,
                            src_port=src_port,
                            service=self.name,
                            username=username,
                            query=query_str,
                            summary=f"MSSQL query executed by '{username}': {query_str[:100]}",
                        )
                        
                        # Process queries
                        if "@@version" in query_lower:
                            version_text = (
                                "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) \n"
                                "\tSep 24 2019 13:48:23 \n"
                                "\tCopyright (C) 2019 Microsoft Corporation\n"
                                "\tStandard Edition on Windows Server 2019 Standard 10.0 <X64> (Build 17763: )\n"
                            )
                            response_payload = _build_sql_text_response("version", version_text, uses_tds72)
                        elif "sys.databases" in query_lower or "sysdatabases" in query_lower:
                            db_list = ["master", "tempdb", "model", "msdb", "prod_customer_db"]
                            response_payload = _build_sql_list_response("name", db_list, uses_tds72)
                        elif "@@servername" in query_lower:
                            response_payload = _build_sql_text_response("servername", "WIN-SRV2019", uses_tds72)
                        else:
                            response_payload = _build_sql_empty_response(uses_tds72)
                            
                        # Write SQL Batch response (TDS packet type 0x04)
                        await _write_tds_packet(writer, 0x04, response_payload)
                    elif cmd_type == 0x0E:  # TRANSACTION MANAGER
                        # Respond with an empty done token
                        await _write_tds_packet(writer, 0x04, _build_sql_empty_response(uses_tds72))
                    elif cmd_type == 0x03:  # RPC Request
                        # Return empty DONE token to keep connection alive
                        await _write_tds_packet(writer, 0x04, _build_sql_empty_response(uses_tds72))
                    else:
                        # Unhandled packet types inside session
                        break
            else:
                # FAILURE!
                await self.log_event(
                    "login_attempt",
                    src_ip=src_ip,
                    src_port=src_port,
                    service=self.name,
                    username=username,
                    password=password,
                    client_hostname=client_hostname,
                    app_name=app_name,
                    database_name=database_name,
                    summary=f"MSSQL failed login attempt for user '{username}' (Host: {client_hostname})",
                )
                
                # Write login failure response (TDS packet type 0x04)
                await _write_tds_packet(writer, 0x04, _build_login_error_response(username or "sa", uses_tds72))
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
    # 4 options (Version, Encryption, Instance, ThreadID) + 1 terminator
    table_size = 5 + 5 + 5 + 5 + 1
    version_offset = table_size
    encryption_offset = version_offset + 6
    instance_offset = encryption_offset + 1
    threadid_offset = instance_offset + 1
    
    sql_server_2019_version = b"\x0f\x00\x07\xd0\x00\x00"
    return b"".join(
        [
            b"\x00" + version_offset.to_bytes(2, "big") + b"\x00\x06",
            b"\x01" + encryption_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\x02" + instance_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\x03" + threadid_offset.to_bytes(2, "big") + b"\x00\x00",
            b"\xff",
            sql_server_2019_version,
            b"\x02",                  # Encryption: ENCRYPT_NOT_SUP (0x02)
            b"\x00",                  # Instance: empty name (1 byte \x00)
        ]
    )


def _build_login_success_response(uses_tds72: bool = False) -> bytes:
    progname_bytes = "Microsoft SQL Server".encode("utf-16le")
    login_ack_len = 1 + 4 + 1 + len(progname_bytes) + 1 + 1 + 2
    
    tds_version = b"\x74\x00\x00\x04" if uses_tds72 else b"\x71\x00\x00\x01"
    
    login_ack = b"".join(
        [
            b"\xad",
            login_ack_len.to_bytes(2, "little"),
            b"\x01",  # Interface: LSQL_TS
            tds_version,
            bytes([len("Microsoft SQL Server")]),
            progname_bytes,
            b"\x0f",  # Major: 15
            b"\x00",  # Minor: 0
            b"\x07\xd0",  # Build: 2000
        ]
    )
    
    # ENVCHANGE for Database: master
    db_new = "master".encode("utf-16le")
    envchange_db = b"".join(
        [
            b"\xe3",
            (1 + 1 + len(db_new) + 1).to_bytes(2, "little"),
            b"\x01",  # Type: 1 (Database)
            bytes([len("master")]),
            db_new,
            b"\x00",  # OldLen: 0
        ]
    )
    
    # ENVCHANGE for Packet Size: 4096
    pkt_new = "4096".encode("utf-16le")
    envchange_pkt = b"".join(
        [
            b"\xe3",
            (1 + 1 + len(pkt_new) + 1).to_bytes(2, "little"),
            b"\x04",  # Type: 4 (Packet Size)
            bytes([len("4096")]),
            pkt_new,
            b"\x00",  # OldLen: 0
        ]
    )
    
    if uses_tds72:
        done = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Exactly 13 bytes
    else:
        done = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00"  # Exactly 9 bytes
    return envchange_db + envchange_pkt + login_ack + done


def _build_login_error_response(username: str, uses_tds72: bool = False) -> bytes:
    error_text = f"Login failed for user '{username}'."
    server_name = "WIN-SRV2019"
    msg_bytes = error_text.encode("utf-16le")
    server_bytes = server_name.encode("utf-16le")
    
    line_number_len = 4 if uses_tds72 else 2
    # 4 (Number) + 1 (State) + 1 (Severity) + 2 (MsgLen) + MsgText + 1 (ServerLen) + ServerName + 1 (ProcLen) + line_number_len
    remaining_len = 4 + 1 + 1 + 2 + len(msg_bytes) + 1 + len(server_bytes) + 1 + line_number_len
    
    line_number_bytes = b"\x00\x00\x00\x00" if uses_tds72 else b"\x00\x00"
    
    error_token = b"".join(
        [
            b"\xaa",
            remaining_len.to_bytes(2, "little"),
            (18456).to_bytes(4, "little"),  # Error number: 18456
            b"\x01",  # State: 1
            b"\x0e",  # Severity: 14
            len(error_text).to_bytes(2, "little"),  # MsgLen character count
            msg_bytes,
            len(server_name).to_bytes(1, "little"),  # ServerLen character count
            server_bytes,
            b"\x00",  # ProcLen: 0 (No procedure name)
            line_number_bytes,  # LineNumber
        ]
    )
    if uses_tds72:
        done_token = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Exactly 13 bytes
    else:
        done_token = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00"  # Exactly 9 bytes
    return error_token + done_token


def _extract_login7_string(payload: bytes, offset_idx: int, length_idx: int) -> str:
    if len(payload) < length_idx + 2:
        return ""
    offset = int.from_bytes(payload[offset_idx : offset_idx + 2], "little")
    length = int.from_bytes(payload[length_idx : length_idx + 2], "little")
    if length <= 0:
        return ""
    start = offset
    end = start + (length * 2)
    if end > len(payload):
        return ""
    return payload[start:end].decode("utf-16le", errors="replace")


def _extract_login7_password(payload: bytes) -> str:
    if len(payload) < 48:
        return ""
    offset = int.from_bytes(payload[44:46], "little")
    length = int.from_bytes(payload[46:48], "little")
    if length <= 0:
        return ""
    start = offset
    end = start + (length * 2)
    if end > len(payload):
        return ""
    
    obfuscated = payload[start:end]
    decrypted = bytearray()
    for b in obfuscated:
        xored = b ^ 0xA5
        swapped = ((xored & 0x0F) << 4) | ((xored & 0xF0) >> 4)
        decrypted.append(swapped)
    return decrypted.decode("utf-16le", errors="replace")


def _skip_all_headers(payload: bytes) -> bytes:
    if len(payload) < 4:
        return payload
    # Read first 4 bytes as a little-endian integer (TotalLength of All Headers block)
    all_headers_len = int.from_bytes(payload[0:4], "little")
    # A valid All Headers block must be strictly smaller than the entire payload length
    if 4 <= all_headers_len < len(payload):
        return payload[all_headers_len:]
    return payload


def _is_decoy_credential(username: str, password: str) -> bool:
    # Accept any non-empty username/password to ensure database clients always successfully log in and enter the interactive session
    return len(username.strip()) > 0


def _build_sql_text_response(col_name: str, row_text: str, uses_tds72: bool = False) -> bytes:
    col_name_bytes = col_name.encode("utf-16le")
    row_bytes = row_text.encode("utf-16le")
    
    usertype_bytes = b"\x00\x00\x00\x00" if uses_tds72 else b"\x00\x00"
    
    colmetadata = b"".join(
        [
            b"\x81",
            b"\x01\x00",  # 1 column
            usertype_bytes,  # UserType (4 bytes or 2 bytes)
            b"\x09\x00",  # Flags: Nullable
            b"\xe7",  # Type: NVARCHAR
            (500).to_bytes(2, "little"),  # MaxLen
            b"\x09\x04\xd0\x00\x34",  # Collation
            bytes([len(col_name)]),
            col_name_bytes,
        ]
    )
    
    row = b"".join(
        [
            b"\xd1",
            len(row_bytes).to_bytes(2, "little"),
            row_bytes,
        ]
    )
    
    if uses_tds72:
        done = b"".join(
            [
                b"\xfd",
                b"\x10\x00",  # Status: DONE_FINAL
                b"\x00\x00",  # CurCmd
                b"\x01\x00\x00\x00\x00\x00\x00\x00",  # Row count = 1 (8 bytes)
            ]
        )
    else:
        done = b"".join(
            [
                b"\xfd",
                b"\x10\x00",  # Status: DONE_FINAL
                b"\x00\x00",  # CurCmd
                b"\x01\x00\x00\x00",  # Row count = 1 (4 bytes)
            ]
        )
    
    return colmetadata + row + done


def _build_sql_list_response(col_name: str, rows_list: list[str], uses_tds72: bool = False) -> bytes:
    col_name_bytes = col_name.encode("utf-16le")
    usertype_bytes = b"\x00\x00\x00\x00" if uses_tds72 else b"\x00\x00"
    
    colmetadata = b"".join(
        [
            b"\x81",
            b"\x01\x00",  # 1 column
            usertype_bytes,  # UserType
            b"\x09\x00",  # Flags: Nullable
            b"\xe7",  # Type: NVARCHAR
            (256).to_bytes(2, "little"),  # MaxLen
            b"\x09\x04\xd0\x00\x34",  # Collation
            bytes([len(col_name)]),
            col_name_bytes,
        ]
    )
    
    row_tokens = []
    for item in rows_list:
        item_bytes = item.encode("utf-16le")
        row_tokens.append(
            b"".join(
                [
                    b"\xd1",
                    len(item_bytes).to_bytes(2, "little"),
                    item_bytes,
                ]
            )
        )
    rows = b"".join(row_tokens)
    
    if uses_tds72:
        done = b"".join(
            [
                b"\xfd",
                b"\x10\x00",  # Status: DONE_FINAL
                b"\x00\x00",  # CurCmd
                len(rows_list).to_bytes(8, "little"),  # Row count (8 bytes)
            ]
        )
    else:
        done = b"".join(
            [
                b"\xfd",
                b"\x10\x00",  # Status: DONE_FINAL
                b"\x00\x00",  # CurCmd
                len(rows_list).to_bytes(4, "little"),  # Row count (4 bytes)
            ]
        )
    
    return colmetadata + rows + done


def _build_sql_empty_response(uses_tds72: bool = False) -> bytes:
    row_count_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00" if uses_tds72 else b"\x00\x00\x00\x00"
    return b"".join(
        [
            b"\xfd",
            b"\x10\x00",  # Status: DONE_FINAL
            b"\x00\x00",  # CurCmd
            row_count_bytes,  # Row count = 0 (8 bytes or 4 bytes)
        ]
    )
