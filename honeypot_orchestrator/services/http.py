from __future__ import annotations

import asyncio

from honeypot_orchestrator.services.base import BaseHoneypotService


class HTTPHoneypot(BaseHoneypotService):
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        src_ip, src_port = self.peer(writer)
        try:
            # HTTP isteğinin ilk satırı genelde "GET /path HTTP/1.1" biçimindedir.
            request_line = await self.read_line(reader, timeout=10.0)
            headers: dict[str, str] = {}
            while True:
                # Boş satıra kadar HTTP header satırları okunur.
                line = await self.read_line(reader, timeout=5.0)
                if not line:
                    break
                key, _, value = line.partition(":")
                if key and value:
                    headers[key.strip().lower()] = value.strip()

            method, path, _ = _parse_request_line(request_line)
            # İstek metodu, yol ve User-Agent gibi temel izler loglanır.
            await self.log_event(
                "http_request",
                src_ip=src_ip,
                src_port=src_port,
                method=method,
                path=path,
                user_agent=headers.get("user-agent", ""),
                summary=f"{method} {path}",
            )
            # Gerçek uygulama sunmadan basit bir 200 OK yanıtı döndürür.
            body = "<html><body><h1>It works</h1></body></html>\n"
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{body}"
            )
            await self.write(writer, response)
        except Exception as exc:
            # Bozuk veya beklenmeyen isteklerde bağlantı hatası olarak iz bırakılır.
            await self.log_event(
                "connection_error",
                src_ip=src_ip,
                src_port=src_port,
                error=type(exc).__name__,
            )
        finally:
            await self.close_writer(writer)


def _parse_request_line(request_line: str) -> tuple[str, str, str]:
    # Eksik veya bozuk request line geldiğinde güvenli varsayılanlar kullanılır.
    parts = request_line.split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], parts[1], ""
    return "UNKNOWN", "/", ""
