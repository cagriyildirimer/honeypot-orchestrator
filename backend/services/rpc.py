from __future__ import annotations

import asyncio
import logging

from services.base import BaseHoneypotService

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
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                # Nmap's -sV version detection does NOT send a valid MSRPC Bind request!
                # Instead, it sends DNSVersionBindReqTCP and SMBProgNeg probes to port 135.
                # A real Windows server responds to these invalid probes with a DCE/RPC Bind_Nak.
                # Nmap relies on this exact Bind_Nak response to print "Microsoft Windows RPC" and detect the OS!
                
                # Extract what would be the PTYPE and Call ID if this were a valid RPC packet
                ptype = data[2] if len(data) > 2 else 0
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
                # Log that we sent the response
                await self.log_event(
                    "rpc_response",
                    src_ip=client_ip,
                    src_port=client_port,
                    summary="Sent DCERPC Bind_Nak response",
                )
                
                # Wait briefly so Nmap can read the response before we send FIN
                await asyncio.sleep(0.5)
                break

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
