from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from profiles import HoneypotProfile
from services.base import BaseHoneypotService


class LDAPHoneypot(BaseHoneypotService):
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        logger,
        profile: HoneypotProfile,
    ) -> None:
        super().__init__(name=name, host=host, port=port, logger=logger)
        self.profile = profile

    def set_profile(self, profile: HoneypotProfile) -> None:
        self.profile = profile

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            while True:
                packet = await asyncio.wait_for(reader.read(4096), timeout=15.0)
                if not packet:
                    break
                handled = await self._handle_packet(packet, src_ip=src_ip, src_port=src_port, writer=writer)
                if not handled:
                    break
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

    async def _handle_packet(
        self,
        packet: bytes,
        *,
        src_ip: str,
        src_port: int,
        writer: asyncio.StreamWriter,
    ) -> bool:
        message_id, protocol_op, payload = _parse_ldap_message(packet)
        if protocol_op == 0x60:
            username, password = _parse_bind_request(payload)
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                username=username,
                password=password,
                summary=f"LDAP bind attempt for {username or '<anonymous>'}",
            )
            await self.write_bytes(
                writer,
                _wrap_ldap_message(
                    message_id,
                    bytes([0x61]) + _ber_length(len(_build_bind_response_payload())) + _build_bind_response_payload(),
                ),
            )
            return True

        if protocol_op == 0x63:
            base_dn, scope = _parse_search_request(payload)
            await self.log_event(
                "ldap_search",
                src_ip=src_ip,
                src_port=src_port,
                base_dn=base_dn,
                scope=scope,
                summary=f"LDAP search under {base_dn or '<rootDSE>'}",
            )
            
            responses = []
            if not base_dn:
                responses.extend(_build_rootdse_search_response(message_id, self.profile))
            else:
                mock_entries = _build_ad_mock_entries(self.profile)
                for entry in mock_entries:
                    responses.append(_build_search_entry_response(message_id, entry["dn"], entry["attributes"]))
                
                done_payload = _build_generic_result_payload(result_code=0, diagnostic_message="")
                search_done = _wrap_ldap_message(
                    message_id,
                    bytes([0x65]) + _ber_length(len(done_payload)) + done_payload,
                )
                responses.append(search_done)
                
            for response_packet in responses:
                await self.write_bytes(writer, response_packet)
            return True

        if protocol_op == 0x42:
            await self.log_event(
                "ldap_unbind",
                src_ip=src_ip,
                src_port=src_port,
                summary="LDAP unbind received.",
            )
            return False

        await self.log_event(
            "ldap_operation",
            src_ip=src_ip,
            src_port=src_port,
            operation=f"0x{protocol_op:02x}",
            summary=f"Unhandled LDAP op 0x{protocol_op:02x}",
        )
        response_payload = _build_generic_result_payload(result_code=2, diagnostic_message="Protocol error")
        await self.write_bytes(
            writer,
            _wrap_ldap_message(
                message_id,
                bytes([0x65]) + _ber_length(len(response_payload)) + response_payload,
            ),
        )
        return False

def _parse_ldap_message(packet: bytes) -> tuple[int, int, bytes]:
    tag, _, body, _ = _read_tlv(packet, 0)
    if tag != 0x30:
        raise ValueError("LDAP packet is not a sequence.")
    _, _, message_id_bytes, offset = _read_tlv(body, 0)
    _, _, protocol_payload, _ = _read_tlv(body, offset)
    protocol_op = body[offset]
    return int.from_bytes(message_id_bytes, "big"), protocol_op, protocol_payload


def _parse_bind_request(payload: bytes) -> tuple[str, str]:
    _, _, _, offset = _read_tlv(payload, 0)
    _, _, name_bytes, offset = _read_tlv(payload, offset)
    username = name_bytes.decode("utf-8", errors="replace")
    password = ""
    if offset < len(payload):
        auth_tag = payload[offset]
        _, _, auth_value, _ = _read_tlv(payload, offset)
        if auth_tag == 0x80:
            password = auth_value.decode("utf-8", errors="replace")
    return username, password


def _parse_search_request(payload: bytes) -> tuple[str, str]:
    _, _, base_dn_bytes, offset = _read_tlv(payload, 0)
    _, _, scope_bytes, _ = _read_tlv(payload, offset)
    base_dn = base_dn_bytes.decode("utf-8", errors="replace")
    scope = {
        b"\x00": "baseObject",
        b"\x01": "singleLevel",
        b"\x02": "wholeSubtree",
    }.get(scope_bytes, scope_bytes.hex())
    return base_dn, scope


def _build_bind_response_payload() -> bytes:
    return _build_generic_result_payload(
        result_code=49,
        diagnostic_message=(
            "80090308: LdapErr: DSID-0C090457, comment: AcceptSecurityContext error, "
            "data 52e, v4563"
        ),
    )


def _build_generic_result_payload(*, result_code: int, diagnostic_message: str) -> bytes:
    return b"".join(
        [
            _ber_enumerated(result_code),
            _ber_octet_string(""),
            _ber_octet_string(diagnostic_message),
        ]
    )


def _build_rootdse_search_response(message_id: int, profile: HoneypotProfile) -> list[bytes]:
    current_time = datetime.now(UTC).strftime("%Y%m%d%H%M%S.0Z")
    dns_domain = profile.smb.dns_domain
    dc_suffix = ",".join(f"DC={part}" for part in dns_domain.split("."))
    attributes = [
        ("currentTime", [current_time]),
        ("defaultNamingContext", [dc_suffix]),
        ("dnsHostName", [f"{profile.smb.hostname.upper()}.{dns_domain}"]),
        ("supportedLDAPVersion", ["3"]),
    ]
    entry_payload = b"".join(
        [
            _ber_octet_string(""),
            _ber_sequence(b"".join(_build_partial_attribute(name, values) for name, values in attributes)),
        ]
    )
    search_entry = _wrap_ldap_message(
        message_id,
        bytes([0x64]) + _ber_length(len(entry_payload)) + entry_payload,
    )
    done_payload = _build_generic_result_payload(result_code=0, diagnostic_message="")
    search_done = _wrap_ldap_message(
        message_id,
        bytes([0x65]) + _ber_length(len(done_payload)) + done_payload,
    )
    return [search_entry, search_done]


def _build_partial_attribute(name: str, values: list[str]) -> bytes:
    value_set = bytes([0x31]) + _ber_length(
        sum(len(_ber_octet_string(value)) for value in values)
    ) + b"".join(_ber_octet_string(value) for value in values)
    return _ber_sequence(_ber_octet_string(name) + value_set)


def _wrap_ldap_message(message_id: int, protocol_op: bytes) -> bytes:
    body = _ber_integer(message_id) + protocol_op
    return _ber_sequence(body)


def _ber_sequence(payload: bytes) -> bytes:
    return bytes([0x30]) + _ber_length(len(payload)) + payload


def _ber_integer(value: int) -> bytes:
    if value == 0:
        encoded = b"\x00"
    else:
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
    return bytes([0x02]) + _ber_length(len(encoded)) + encoded


def _ber_enumerated(value: int) -> bytes:
    encoded = value.to_bytes(1, "big")
    return bytes([0x0A]) + _ber_length(len(encoded)) + encoded


def _ber_octet_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return bytes([0x04]) + _ber_length(len(encoded)) + encoded


def _ber_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Missing BER tag.")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Missing BER length.")
    first_length = data[offset]
    offset += 1
    if first_length & 0x80:
        size = first_length & 0x7F
        length = int.from_bytes(data[offset : offset + size], "big")
        offset += size
    else:
        length = first_length
    end = offset + length
    if end > len(data):
        raise ValueError("Truncated BER payload.")
    return tag, length, data[offset:end], end


def _build_search_entry_response(message_id: int, dn: str, attributes: list[tuple[str, list[str]]]) -> bytes:
    entry_payload = b"".join(
        [
            _ber_octet_string(dn),
            _ber_sequence(b"".join(_build_partial_attribute(name, values) for name, values in attributes)),
        ]
    )
    return _wrap_ldap_message(
        message_id,
        bytes([0x64]) + _ber_length(len(entry_payload)) + entry_payload,
    )


def _build_ad_mock_entries(profile: HoneypotProfile) -> list[dict[str, Any]]:
    dns_domain = profile.smb.dns_domain
    dc_suffix = ",".join(f"DC={part}" for part in dns_domain.split("."))
    
    return [
        {
            "dn": f"CN=Administrator,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", ["Administrator"]),
                ("sAMAccountName", ["Administrator"]),
                ("userPrincipalName", [f"Administrator@{dns_domain}"]),
                ("memberOf", [f"CN=Domain Admins,CN=Users,{dc_suffix}", f"CN=Enterprise Admins,CN=Users,{dc_suffix}"]),
                ("pwdLastSet", ["132649032000000000"]),
                ("userAccountControl", ["512"]),
            ]
        },
        {
            "dn": f"CN=cagri,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", ["cagri"]),
                ("sAMAccountName", ["cagri"]),
                ("userPrincipalName", [f"cagri@{dns_domain}"]),
                ("memberOf", [f"CN=Domain Users,CN=Users,{dc_suffix}"]),
                ("pwdLastSet", ["132849032000000000"]),
                ("userAccountControl", ["512"]),
            ]
        },
        {
            "dn": f"CN=sql_service,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "person", "organizationalPerson", "user"]),
                ("cn", ["sql_service"]),
                ("sAMAccountName", ["sql_service"]),
                ("userPrincipalName", [f"sql_service@{dns_domain}"]),
                ("memberOf", [f"CN=Domain Users,CN=Users,{dc_suffix}"]),
                ("pwdLastSet", ["132949032000000000"]),
                ("servicePrincipalName", [f"MSSQLSvc/{profile.smb.hostname.upper()}.{dns_domain}:1433"]),
                ("userAccountControl", ["512"]),
            ]
        },
        {
            "dn": f"CN={profile.smb.hostname.upper()},OU=Domain Controllers,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "person", "organizationalPerson", "user", "computer"]),
                ("cn", [profile.smb.hostname.upper()]),
                ("sAMAccountName", [f"{profile.smb.hostname.upper()}$"]),
                ("dnsHostName", [f"{profile.smb.hostname.upper()}.{dns_domain}"]),
                ("userAccountControl", ["532480"]),
            ]
        },
        {
            "dn": f"CN=SQL-PROD-01,CN=Computers,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "person", "organizationalPerson", "user", "computer"]),
                ("cn", ["SQL-PROD-01"]),
                ("sAMAccountName", ["SQL-PROD-01$"]),
                ("dnsHostName", [f"SQL-PROD-01.{dns_domain}"]),
                ("userAccountControl", ["4096"]),
            ]
        },
        {
            "dn": f"CN=Domain Admins,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "group"]),
                ("cn", ["Domain Admins"]),
                ("sAMAccountName", ["Domain Admins"]),
                ("member", [f"CN=Administrator,CN=Users,{dc_suffix}"]),
            ]
        },
        {
            "dn": f"CN=Enterprise Admins,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "group"]),
                ("cn", ["Enterprise Admins"]),
                ("sAMAccountName", ["Enterprise Admins"]),
                ("member", [f"CN=Administrator,CN=Users,{dc_suffix}"]),
            ]
        },
        {
            "dn": f"CN=Domain Users,CN=Users,{dc_suffix}",
            "attributes": [
                ("objectClass", ["top", "group"]),
                ("cn", ["Domain Users"]),
                ("sAMAccountName", ["Domain Users"]),
                ("member", [f"CN=Administrator,CN=Users,{dc_suffix}", f"CN=cagri,CN=Users,{dc_suffix}", f"CN=sql_service,CN=Users,{dc_suffix}"]),
            ]
        }
    ]
