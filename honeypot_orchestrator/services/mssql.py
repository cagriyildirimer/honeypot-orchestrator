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
            # 1. Read PRELOGIN packet
            packet_type, _payload = await _read_tds_packet(reader)
            await self.log_event(
                "mssql_prelogin",
                src_ip=src_ip,
                src_port=src_port,
                packet_type=f"0x{packet_type:02x}",
                summary="MSSQL prelogin captured.",
            )
            if packet_type == 0x12:
                await _write_tds_packet(writer, 0x04, _build_prelogin_response())
            else:
                return

            # 2. Read LOGIN7 packet
            try:
                login_packet_type, login_payload = await asyncio.wait_for(
                    _read_tds_packet(reader),
                    timeout=10.0,
                )
            except (TimeoutError, asyncio.IncompleteReadError):
                return

            if login_packet_type != 0x10:  # 0x10 is LOGIN7
                return

            # Preprocess payload to skip All Headers block if present
            login7_payload = _skip_all_headers(login_payload)

            # 3. Extract LOGIN7 credentials and metadata
            username = _extract_login7_string(login7_payload, 40, 42)
            password = _extract_login7_password(login7_payload)
            client_hostname = _extract_login7_string(login7_payload, 36, 38)
            app_name = _extract_login7_string(login7_payload, 48, 50)
            database_name = _extract_login7_string(login7_payload, 60, 62)

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
                await _write_tds_packet(writer, 0x04, _build_login_success_response())
                
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
                            response_payload = _build_sql_text_response("version", version_text)
                        elif "sys.databases" in query_lower or "sysdatabases" in query_lower:
                            db_list = ["master", "tempdb", "model", "msdb", "prod_customer_db"]
                            response_payload = _build_sql_list_response("name", db_list)
                        elif "@@servername" in query_lower:
                            response_payload = _build_sql_text_response("servername", "WIN-SRV2019")
                        else:
                            response_payload = _build_sql_empty_response()
                            
                        # Write SQL Batch response (TDS packet type 0x04)
                        await _write_tds_packet(writer, 0x04, response_payload)
                    elif cmd_type == 0x0E:  # TRANSACTION MANAGER
                        # Respond with an empty done token
                        await _write_tds_packet(writer, 0x04, _build_sql_empty_response())
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
                await _write_tds_packet(writer, 0x04, _build_login_error_response(username or "sa"))
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
    table_size = 5 + 5 + 5 + 1
    version_offset = table_size
    encryption_offset = version_offset + 6
    instance_offset = encryption_offset + 1
    sql_server_2019_version = b"\x0f\x00\x07\xd0\x00\x00"
    return b"".join(
        [
            b"\x00" + version_offset.to_bytes(2, "big") + b"\x00\x06",
            b"\x01" + encryption_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\x02" + instance_offset.to_bytes(2, "big") + b"\x00\x01",
            b"\xff",
            sql_server_2019_version,
            b"\x02",
            b"\x00",
        ]
    )


def _build_login_success_response() -> bytes:
    progname_bytes = "Microsoft SQL Server".encode("utf-16le")
    login_ack_len = 1 + 4 + 1 + len(progname_bytes) + 1 + 1 + 2
    login_ack = b"".join(
        [
            b"\xad",
            login_ack_len.to_bytes(2, "little"),
            b"\x01",  # Interface: LSQL_TS
            b"\x74\x00\x00\x04",  # Version: TDS 7.4
            bytes([len("Microsoft SQL Server")]),
            progname_bytes,
            b"\x0f",  # Major: 15
            b"\x00",  # Minor: 0
            b"\x07\xd0",  # Build: 2000
        ]
    )
    done = b"\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    return login_ack + done


def _build_login_error_response(username: str) -> bytes:
    error_text = f"Login failed for user '{username}'."
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
    if 4 <= all_headers_len <= len(payload):
        return payload[all_headers_len:]
    return payload


def _is_decoy_credential(username: str, password: str) -> bool:
    u = username.lower().strip()
    p = password.strip()
    
    valid_creds = {
        "sa": {"password", "Password123", "admin", "sa", "123456", "P@ssw0rd123!"},
        "admin": {"password", "admin123", "admin", "admin!123"},
        "sql_service": {"password123", "sql_service", "sqlpass123"},
        "administrator": {"password", "Password123", "P@ssword123!"}
    }
    
    return u in valid_creds and p in valid_creds[u]


def _build_sql_text_response(col_name: str, row_text: str) -> bytes:
    col_name_bytes = col_name.encode("utf-16le")
    row_bytes = row_text.encode("utf-16le")
    
    colmetadata = b"".join(
        [
            b"\x81",
            b"\x01\x00",  # 1 column
            b"\x00\x00\x00\x00",  # UserType
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
    
    done = b"".join(
        [
            b"\xfd",
            b"\x10\x00",  # Status: DONE_FINAL
            b"\x00\x00",  # CurCmd
            b"\x01\x00\x00\x00\x00\x00\x00\x00",  # Row count = 1
        ]
    )
    
    return colmetadata + row + done


def _build_sql_list_response(col_name: str, rows_list: list[str]) -> bytes:
    col_name_bytes = col_name.encode("utf-16le")
    colmetadata = b"".join(
        [
            b"\x81",
            b"\x01\x00",  # 1 column
            b"\x00\x00\x00\x00",  # UserType
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
    
    done = b"".join(
        [
            b"\xfd",
            b"\x10\x00",  # Status: DONE_FINAL
            b"\x00\x00",  # CurCmd
            len(rows_list).to_bytes(8, "little"),  # Row count
        ]
    )
    
    return colmetadata + rows + done


def _build_sql_empty_response() -> bytes:
    return b"".join(
        [
            b"\xfd",
            b"\x10\x00",  # Status: DONE_FINAL
            b"\x00\x00",  # CurCmd
            b"\x00\x00\x00\x00\x00\x00\x00\x00",  # Row count = 0
        ]
    )
