from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

from honeypot_orchestrator.event_logger import JSONLEventLogger


class BaseHoneypotService(ABC):
    def __init__(self, name: str, host: str, port: int, logger: JSONLEventLogger) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.logger = logger
        # asyncio.start_server dondugunde aktif TCP sunucusu burada tutulur.
        self._server: asyncio.AbstractServer | None = None

    @property
    def running(self) -> bool:
        # Web paneli bu property ile servisin gercekten dinleyip dinlemedigini gosterir.
        return self._server is not None and self._server.is_serving()

    async def start(self) -> None:
        if self.running:
            return
        # Her yeni istemci baglantisi once _connection_callback metoduna gider.
        self._server = await asyncio.start_server(
            self._connection_callback,
            host=self.host,
            port=self.port,
        )
        await self.log_event("service_started", summary=f"{self.name} listening.")

    async def stop(self) -> None:
        # Zaten kapaliysa tekrar kapatma denemesi yapilmaz.
        if self._server is None:
            return
        # Yeni baglanti kabulunu durdurur ve mevcut sunucu soketini kapatir.
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        await self.log_event("service_stopped", summary=f"{self.name} stopped.")

    async def log_event(self, event_type: str, **fields: Any) -> None:
        # Servis adini ve olay tipini standart alanlar olarak her kayda ekler.
        await self.logger.log(
            {
                "service": self.name,
                "event_type": event_type,
                **fields,
            }
        )

    def peer(self, writer: asyncio.StreamWriter) -> tuple[str, int]:
        # Baglanan istemcinin IP ve kaynak port bilgisini socket uzerinden alir.
        peername = writer.get_extra_info("peername")
        if isinstance(peername, tuple) and len(peername) >= 2:
            return str(peername[0]), int(peername[1])
        return "unknown", 0

    async def write(self, writer: asyncio.StreamWriter, data: str) -> None:
        # Metin cevabi byte'a cevirip istemciye gonderir.
        writer.write(data.encode("utf-8", errors="replace"))
        # drain, tamponun gercekten gonderilmesini bekler.
        await writer.drain()

    async def write_bytes(self, writer: asyncio.StreamWriter, data: bytes) -> None:
        writer.write(data)
        await writer.drain()

    async def read_line(
        self,
        reader: asyncio.StreamReader,
        timeout: float = 20.0,
        limit: int = 4096,
    ) -> str:
        # Istemciden tek satir okur; timeout ile sonsuza kadar beklemeyi onler.
        data = await asyncio.wait_for(reader.readline(), timeout=timeout)
        # Cok uzun girdiler loglari sisirmesin diye limit kadar veri islenir.
        return data[:limit].decode("utf-8", errors="replace").strip()

    async def close_writer(self, writer: asyncio.StreamWriter) -> None:
        # Baglantiyi temiz kapatir; kopmus istemcilerden gelen hatalari sessizce gecer.
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass

    async def _connection_callback(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        from honeypot_orchestrator.defense import is_blacklisted, record_suspicious_event

        peer_ip, peer_port = self.peer(writer)
        if is_blacklisted(peer_ip):
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        record_suspicious_event(peer_ip)

        try:
            await self.handle_client(reader, writer)
        except Exception as exc:
            await self.log_event(
                "connection_error",
                src_ip=peer_ip,
                src_port=peer_port,
                error=type(exc).__name__,
            )

    @abstractmethod
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        raise NotImplementedError


class BaseUDPHoneypotService(ABC):
    def __init__(self, name: str, host: str, port: int, logger: JSONLEventLogger) -> None:
        self.name = name
        self.host = host
        self.port = port
        self.logger = logger
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: asyncio.DatagramProtocol | None = None

    @property
    def running(self) -> bool:
        return self._transport is not None

    async def start(self) -> None:
        if self.running:
            return
        loop = asyncio.get_running_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: self.create_protocol(),
            local_addr=(self.host, self.port),
        )
        await self.log_event("service_started", summary=f"{self.name} listening (UDP).")

    async def stop(self) -> None:
        if self._transport is None:
            return
        self._transport.close()
        self._transport = None
        self._protocol = None
        await self.log_event("service_stopped", summary=f"{self.name} stopped.")

    async def log_event(self, event_type: str, **fields: Any) -> None:
        await self.logger.log(
            {
                "service": self.name,
                "event_type": event_type,
                **fields,
            }
        )

    @abstractmethod
    def create_protocol(self) -> asyncio.DatagramProtocol:
        raise NotImplementedError
