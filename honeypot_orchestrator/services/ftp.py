from __future__ import annotations

import asyncio

from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


class FTPHoneypot(BaseHoneypotService):
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
        # USER komutu gelene kadar kullanici adi bos tutulur.
        username = ""
        await self.log_event("connection", src_ip=src_ip, src_port=src_port)
        try:
            ftp_profile = self.profile.ftp
            # FTP istemcilerine klasik karsilama banner'i gonderilir.
            await self.write(writer, ftp_profile.banner)
            while True:
                # FTP komutlari satir bazlidir: "USER admin" gibi okunur.
                line = await self.read_line(reader)
                if not line:
                    break
                command, _, argument = line.partition(" ")
                command = command.upper()
                # Her komut, argumaniyla birlikte analiz icin kaydedilir.
                await self.log_event(
                    "ftp_command",
                    src_ip=src_ip,
                    src_port=src_port,
                    profile=self.profile.name,
                    command=command,
                    argument=argument,
                    summary=f"FTP {command}",
                )
                if command == "USER":
                    # Kullanici adi hatirlanir; sonraki PASS ile login_attempt olusturulur.
                    username = argument
                    await self.write(writer, ftp_profile.user_prompt_response)
                elif command == "PASS":
                    # Parola geldiginde giris denemesi olarak ayrica loglanir.
                    await self.log_event(
                        "login_attempt",
                        src_ip=src_ip,
                        src_port=src_port,
                        profile=self.profile.name,
                        username=username,
                        password=argument,
                        summary=f"FTP login attempt for {username}",
                    )
                    await self.write(writer, ftp_profile.login_failed_response)
                elif command == "QUIT":
                    # Istemci cikmak isterse baglanti nazikce sonlandirilir.
                    await self.write(writer, ftp_profile.quit_response)
                    break
                else:
                    # Bu MVP dosya listeleme veya transfer gibi komutlari uygulamaz.
                    await self.write(writer, ftp_profile.fallback_response)
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
