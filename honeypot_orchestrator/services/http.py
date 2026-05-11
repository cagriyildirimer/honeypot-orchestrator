from __future__ import annotations

import asyncio

from honeypot_orchestrator.profiles import HoneypotProfile
from honeypot_orchestrator.services.base import BaseHoneypotService


class HTTPHoneypot(BaseHoneypotService):
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
        try:
            # HTTP isteginin ilk satiri genelde "GET /path HTTP/1.1" bicimindedir.
            request_line = await self.read_line(reader, timeout=10.0)
            headers: dict[str, str] = {}
            while True:
                # Bos satira kadar HTTP header satirlari okunur.
                line = await self.read_line(reader, timeout=5.0)
                if not line:
                    break
                key, _, value = line.partition(":")
                if key and value:
                    headers[key.strip().lower()] = value.strip()

            method, path, _ = _parse_request_line(request_line)
            http_profile = self.profile.http
            # Istek metodu, yol ve User-Agent gibi temel izler loglanir.
            await self.log_event(
                "http_request",
                src_ip=src_ip,
                src_port=src_port,
                method=method,
                path=path,
                profile=self.profile.name,
                template=http_profile.template_name,
                user_agent=headers.get("user-agent", ""),
                summary=f"{method} {path}",
            )
            body = http_profile.body_html
            response = (
                f"HTTP/1.1 {http_profile.default_status}\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Server: {http_profile.server_header}\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            await self.write(writer, response)
        except Exception as exc:
            # Bozuk veya beklenmeyen isteklerde baglanti hatasi olarak iz birakilir.
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)


def _parse_request_line(request_line: str) -> tuple[str, str, str]:
    # Eksik veya bozuk request line geldiginde guvenli varsayilanlar kullanilir.
    parts = request_line.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "UNKNOWN", "/", ""
