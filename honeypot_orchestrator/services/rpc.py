from __future__ import annotations

import asyncio
import logging

from honeypot_orchestrator.services.base import BaseHoneypotService

logger = logging.getLogger(__name__)

class RPCHoneypot(BaseHoneypotService):
    """
    Simulates a Windows MSRPC Endpoint Mapper (Port 135).
    Reads incoming DCERPC Bind requests and responds with a realistic Bind_Nak (Reject).
    This highly improves the realistic fingerprint of a Windows Server.
    """

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_ip, client_port = self.peer(writer)
        await self.log_event("rpc_connection", src_ip=client_ip, src_port=client_port)

        try:
            # We wait for the initial RPC payload
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not data:
                return

            # Check if it looks like a DCE/RPC version 5 request
            if data.startswith(b"\x05\x00"):
                # Nmap sends PTYPE 0x0B (Bind) to Endpoint Mapper
                ptype = data[2]
                call_id = data[12:16] if len(data) >= 16 else b"\x01\x00\x00\x00"

                # Log the specific request
                await self.log_event(
                    "rpc_request",
                    src_ip=client_ip,
                    src_port=client_port,
                    ptype=ptype,
                    data_hex=data[:32].hex(),
                    summary=f"Received DCERPC request with PTYPE {ptype}",
                )

                # Construct a realistic DCE/RPC Bind_Nak (Reject) PDU
                # 0x0004 = Presentation syntax not supported
                reject_reason = b"\x04\x00"
                response = (
                    b"\x05\x00"           # RPC Version = 5, Minor = 0
                    b"\x0d"               # PTYPE = bind_nak (0x0D)
                    b"\x03"               # PFC Flags = 3 (PFC_FIRST_FRAG | PFC_LAST_FRAG)
                    b"\x10\x00\x00\x00"   # Packed Data Representation (Little Endian)
                    b"\x12\x00"           # Fragment Length = 18 bytes
                    b"\x00\x00"           # Auth Length = 0
                    + call_id +           # Call ID (Extracted from request)
                    reject_reason         # Reject Reason
                )

                writer.write(response)
                await writer.drain()

                await self.log_event(
                    "rpc_response",
                    src_ip=client_ip,
                    src_port=client_port,
                    summary="Sent DCERPC Bind_Nak response",
                )

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            await self.log_event(
                "rpc_error",
                src_ip=client_ip,
                src_port=client_port,
                error=str(e),
                summary="RPC decoy encountered an error.",
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
