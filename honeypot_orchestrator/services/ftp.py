from __future__ import annotations

import asyncio

from honeypot_orchestrator.services.base import BaseHoneypotService


class FTPHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        username = ""
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            await self.write(writer, "220 FTP server ready\r\n")
            while True:
                line = await self.read_line(reader)
                if not line:
                    break
                command, _, argument = line.partition(" ")
                command = command.upper()
                await self.log_event(
                    "ftp_command",
                    src_ip=src_ip,
                    src_port=src_port,
                    command=command,
                    argument=argument,
                    summary=f"FTP {command}",
                )
                if command == "USER":
                    username = argument
                    await self.write(writer, "331 Password required\r\n")
                elif command == "PASS":
                    await self.log_event(
                        "login_attempt",
                        src_ip=src_ip,
                        src_port=src_port,
                        username=username,
                        password=argument,
                        summary=f"FTP login attempt for {username}",
                    )
                    await self.write(writer, "530 Login incorrect\r\n")
                elif command == "QUIT":
                    await self.write(writer, "221 Goodbye\r\n")
                    break
                else:
                    await self.write(writer, "502 Command not implemented\r\n")
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
