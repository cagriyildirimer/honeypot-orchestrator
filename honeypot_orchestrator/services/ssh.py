from __future__ import annotations

import asyncio

from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


class FakeSSHHoneypot(BaseHoneypotService):
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
        # Baglanti kurulur kurulmaz kaynak IP/port bilgisi kaydedilir.
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            ssh_profile = self.profile.ssh
            # SSH istemcisinin bekledigi banner taklit edilir; gercek SSH oturumu acilmaz.
            await self.write(writer, ssh_profile.banner)
            await self.write(writer, ssh_profile.login_prompt)
            # Girilen kullanici adi ve parola yalnizca lab ici gozlem icin loglanir.
            username = await self.read_line(reader)
            await self.write(
                writer,
                ssh_profile.password_prompt_template.format(username=username or "unknown"),
            )
            password = await self.read_line(reader)
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                profile=self.profile.name,
                username=username,
                password=password,
                summary=f"Fake SSH login attempt for {username}",
            )
            # Honeypot her giris denemesini basarisiz gosterir.
            await self.write(writer, ssh_profile.denied_message)
        except (BrokenPipeError, ConnectionResetError):
            # Istemci oturum tamamlanmadan koparsa ayri olay olarak isaretlenir.
            await self.log_event("client_disconnected", src_ip=src_ip, src_port=src_port)
        except Exception as exc:
            # Beklenmeyen hatalar olay tipine hata sinifi eklenerek loglanir.
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)
