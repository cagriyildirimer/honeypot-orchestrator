from __future__ import annotations

import asyncio

from honeypot_orchestrator.services.base import BaseHoneypotService


class FakeSSHHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        # Bağlantı kurulur kurulmaz kaynak IP/port bilgisi kaydedilir.
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            # SSH istemcisinin beklediği banner taklit edilir; gerçek SSH oturumu açılmaz.
            await self.write(writer, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")
            await self.write(writer, "login as: ")
            # Girilen kullanıcı adı ve parola yalnızca lab içi gözlem için loglanır.
            username = await self.read_line(reader)
            await self.write(writer, f"{username}@localhost's password: ")
            password = await self.read_line(reader)
            await self.log_event(
                "login_attempt",
                src_ip=src_ip,
                src_port=src_port,
                username=username,
                password=password,
                summary=f"Fake SSH login attempt for {username}",
            )
            # Honeypot her giriş denemesini başarısız gösterir.
            await self.write(writer, "Permission denied, please try again.\r\n")
        except (BrokenPipeError, ConnectionResetError):
            # İstemci oturum tamamlanmadan koparsa ayrı olay olarak işaretlenir.
            await self.log_event("client_disconnected", src_ip=src_ip, src_port=src_port)
        except Exception as exc:
            # Beklenmeyen hatalar olay tipine hata sınıfı eklenerek loglanır.
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)
