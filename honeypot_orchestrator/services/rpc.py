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

                # Construct a realistic DCE/RPC Bind_Ack (Accept) PDU
                # A standard Windows Bind_Ack is 68 bytes long
                response = (
                    b"\x05\x00"           # RPC Version = 5, Minor = 0
                    b"\x0c"               # PTYPE = bind_ack (0x0C)
                    b"\x03"               # PFC Flags = 3 (PFC_FIRST_FRAG | PFC_LAST_FRAG)
                    b"\x10\x00\x00\x00"   # Packed Data Representation (Little Endian)
                    b"\x44\x00"           # Fragment Length = 68 bytes
                    b"\x00\x00"           # Auth Length = 0
                    + call_id +           # Call ID (Extracted from request)
                    b"\x10\xb8\x00\x00"   # Max Xmit Frag (47104)
                    b"\x10\xb8\x00\x00"   # Max Recv Frag (47104)
                    b"\x12\x34\x56\x78"   # Assoc Group ID (Dummy)
                    b"\x04\x00"           # Sec Addr Len (4 bytes for "135\x00")
                    b"135\x00"            # Sec Addr
                    b"\x00\x00\x00\x00"   # Padding to align to 4 bytes
                    b"\x01\x00\x00\x00"   # Num Results (1)
                    b"\x00\x00"           # Result: Acceptance (0)
                    b"\x00\x00"           # Reason: Reason Not Specified (0)
                    b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11"  # Transfer Syntax UUID (NDR)
                    b"\x9f\xe8\x08\x00\x2b\x10\x48\x60"
                    b"\x02\x00\x00\x00"   # Syntax Version (2)
                )

                writer.write(response)
                await writer.drain()
                
                # Sleep briefly to ensure Nmap reads the response before we send FIN/RST
                await asyncio.sleep(0.5)

                await self.log_event(
                    "rpc_response",
                    src_ip=client_ip,
                    src_port=client_port,
                    summary="Sent DCERPC Bind_Nak response",
                )
            else:
                # If Nmap sends a non-RPC probe (e.g. HTTP GET to port 135)
                # Sleep briefly before closing to prevent immediate reset "tcpwrapped" labeling
                await asyncio.sleep(0.5)

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
