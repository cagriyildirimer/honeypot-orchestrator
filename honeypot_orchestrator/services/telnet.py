from __future__ import annotations

import asyncio

from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


class TelnetHoneypot(BaseHoneypotService):
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        logger: JSONLEventLogger,
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
        # Telnet baglantisi basladiginda kaynak bilgisi loga yazilir.
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            telnet_profile = self.profile.telnet
            # Basit bir Linux konsol giris ekrani taklit edilir.
            await self.write(writer, telnet_profile.banner)
            username = await self.read_line(reader)
            await self.write(writer, telnet_profile.password_prompt)
            password = await self.read_line(reader)
            # Kullanici adi ve parola denemesi login_attempt olarak kaydedilir.
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                profile=self.profile.name,
                username=username,
                password=password,
                summary=f"Telnet login attempt for {username}",
            )
            # Gercek oturum acilmaz; her deneme basarisiz doner.
            await self.write(writer, telnet_profile.login_failed_response)
        except (BrokenPipeError, ConnectionResetError):
            # Istemci erken koparsa bu durum ayrica gorulebilir.
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
