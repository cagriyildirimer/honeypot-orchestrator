from __future__ import annotations

import asyncio

from system.profiles import HoneypotProfile
from services.base import BaseHoneypotService


class LDAPSHoneypot(BaseHoneypotService):
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
            client_hello = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            if not client_hello:
                return
            await self.log_event(
                "ldaps_tls_client_hello",
                src_ip=src_ip,
                src_port=src_port,
                tls_record_type=f"0x{client_hello[0]:02x}",
                tls_version=_tls_version_name(client_hello),
                summary="LDAPS TLS client hello captured.",
            )
            # Minimal TLS alert: the service looks present but refuses to proceed without a full TLS stack.
            writer.write(b"\x15\x03\x03\x00\x02\x02\x28")
            await writer.drain()
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


def _tls_version_name(packet: bytes) -> str:
    if len(packet) < 3:
        return "unknown"
    version = packet[1:3]
    return {
        b"\x03\x01": "TLS 1.0",
        b"\x03\x02": "TLS 1.1",
        b"\x03\x03": "TLS 1.2",
        b"\x03\x04": "TLS 1.3",
    }.get(version, version.hex())
