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
            data = await reader.read(4096)
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

                # Construct the exact DCE/RPC Bind_Nak (Reject) PDU expected by Nmap
                # Nmap's regex expects: ^\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0...$
                response = (
                    b"\x05\x00\x0d\x03"   # Version 5.0, Bind_Nak (0x0D), Flags 3
                    b"\x10\x00\x00\x00"   # Little Endian Data Rep
                    b"\x18\x00\x00\x00"   # Frag Len 24, Auth Len 0
                    + call_id +           # Call ID (4 bytes)
                    b"\x04\x00"           # Reject Reason: Local Limit Exceeded / Syntax
                    b"\x01"               # Num supported versions: 1
                    b"\x05\x00"           # Supported version: 5.0
                    b"\x00\x00\x00"       # Padding to 24 bytes
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
