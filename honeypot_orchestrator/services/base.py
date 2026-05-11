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
        # Her yeni istemci baglantisi alt siniftaki handle_client metoduna gider.
        self._server = await asyncio.start_server(
            self.handle_client,
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

    @abstractmethod
    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        raise NotImplementedError
