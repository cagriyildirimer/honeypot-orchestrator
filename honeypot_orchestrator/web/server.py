from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from honeypot_orchestrator.orchestrator import Orchestrator


WEB_DIR = Path(__file__).parent


class WebDashboard:
    def __init__(self, host: str, port: int, orchestrator: Orchestrator) -> None:
        self.host = host
        self.port = port
        self.orchestrator = orchestrator
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            method, target, _ = _parse_request_line(request_line.decode("utf-8", "replace"))
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in {b"\r\n", b"\n", b""}:
                    break

            if method != "GET":
                await self.respond(writer, 405, "text/plain; charset=utf-8", b"Method not allowed")
                return

            parsed = urlparse(target)
            if parsed.path == "/":
                body = (WEB_DIR / "templates" / "index.html").read_bytes()
                await self.respond(writer, 200, "text/html; charset=utf-8", body)
            elif parsed.path == "/static/styles.css":
                body = (WEB_DIR / "static" / "styles.css").read_bytes()
                await self.respond(writer, 200, "text/css; charset=utf-8", body)
            elif parsed.path == "/static/app.js":
                body = (WEB_DIR / "static" / "app.js").read_bytes()
                await self.respond(writer, 200, "application/javascript; charset=utf-8", body)
            elif parsed.path == "/api/status":
                await self.respond_json(
                    writer,
                    {
                        "services": self.orchestrator.service_status(),
                        "log_path": str(self.orchestrator.config.logging.path),
                    },
                )
            elif parsed.path == "/api/events":
                query = parse_qs(parsed.query)
                limit = int(query.get("limit", ["50"])[0])
                await self.respond_json(
                    writer,
                    {"events": read_recent_events(self.orchestrator.config.logging.path, limit)},
                )
            elif parsed.path == "/api/stats":
                records = read_recent_events(self.orchestrator.config.logging.path, 1000)
                by_service = Counter(record.get("service", "unknown") for record in records)
                by_type = Counter(record.get("event_type", "unknown") for record in records)
                await self.respond_json(
                    writer,
                    {
                        "total_recent_events": len(records),
                        "by_service": dict(by_service),
                        "by_type": dict(by_type),
                    },
                )
            else:
                await self.respond(writer, 404, "text/plain; charset=utf-8", b"Not found")
        except Exception as exc:
            body = f"Internal server error: {type(exc).__name__}".encode("utf-8")
            await self.respond(writer, 500, "text/plain; charset=utf-8", body)
        finally:
            writer.close()
            await writer.wait_closed()

    async def respond_json(self, writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        await self.respond(writer, 200, "application/json; charset=utf-8", body)

    async def respond(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        content_type: str,
        body: bytes,
    ) -> None:
        reason = {
            200: "OK",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(status, "OK")
        headers = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        writer.write(headers + body)
        await writer.drain()


def read_recent_events(path: Path, limit: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    records = []
    for line in lines[-max(1, min(limit, 500)) :]:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(records))


def _parse_request_line(request_line: str) -> tuple[str, str, str]:
    parts = request_line.strip().split()
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    return "GET", "/", "HTTP/1.1"
