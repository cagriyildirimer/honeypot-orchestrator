from __future__ import annotations

import asyncio
from typing import Any

from honeypot_orchestrator.config import AppConfig
from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.services.base import BaseHoneypotService
from honeypot_orchestrator.services.ftp import FTPHoneypot
from honeypot_orchestrator.services.http import HTTPHoneypot
from honeypot_orchestrator.services.ssh import FakeSSHHoneypot
from honeypot_orchestrator.services.telnet import TelnetHoneypot
from honeypot_orchestrator.web.server import WebDashboard


class Orchestrator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        # Butun servisler ayni JSONL logger'i kullanir; olaylar tek dosyada toplanir.
        self.logger = JSONLEventLogger(config.logging.path)
        # Tum servisler adlarina gore burada saklanir; panel istediklerini ayaga kaldirir.
        self.services = self._build_services()
        self._service_lock = asyncio.Lock()
        # Web paneli orkestratorden servis durumunu ve log yolunu okuyacak sekilde baglanir.
        self.web_dashboard = WebDashboard(config.web.host, config.web.port, self)

    async def start(self) -> None:
        # Bu yeni akista uygulama acilisinda yalnizca web paneli dinlemeye baslar.
        if self.config.web.enabled:
            await self.web_dashboard.start()

        # Baslangic olayi log dosyasina yazilir; panelde de gorulebilir.
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "started",
                "summary": "Honeypot orchestrator started.",
            }
        )
        self.print_startup_summary()

    async def stop(self) -> None:
        # Kapanisin basladigini loglayarak sonradan inceleme icin iz birakir.
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "stopping",
                "summary": "Honeypot orchestrator stopping.",
            }
        )

        # Panel aciksa once onu kapatir.
        if self.config.web.enabled:
            await self.web_dashboard.stop()

        # Calisan servisler ters sirada kapatilir.
        for service in reversed(list(self.services.values())):
            await service.stop()

    def service_status(self) -> list[dict[str, object]]:
        # Web API'nin dondurdugu sade servis durum listesini uretir.
        return [
            {
                "name": service.name,
                "host": service.host,
                "port": service.port,
                "running": service.running,
                "enabled": True,
            }
            for service in self.services.values()
        ]

    async def start_service(self, name: str) -> dict[str, Any]:
        async with self._service_lock:
            service = self._get_service(name)
            if service.running:
                return self._service_payload(service, "already_running")
            await service.start()
            await self.logger.log(
                {
                    "service": "orchestrator",
                    "event_type": "service_action",
                    "summary": f"Started {name} from dashboard.",
                    "target_service": name,
                    "action": "start",
                }
            )
            return self._service_payload(service, "started")

    async def stop_service(self, name: str) -> dict[str, Any]:
        async with self._service_lock:
            service = self._get_service(name)
            if not service.running:
                return self._service_payload(service, "already_stopped")
            await service.stop()
            await self.logger.log(
                {
                    "service": "orchestrator",
                    "event_type": "service_action",
                    "summary": f"Stopped {name} from dashboard.",
                    "target_service": name,
                    "action": "stop",
                }
            )
            return self._service_payload(service, "stopped")

    def print_startup_summary(self) -> None:
        # Terminalde kullanicinin web panelin hangi adreste acildigini hizlica gormesini saglar.
        print("Honeypot Orchestrator started")
        if self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        print("Services are controlled from the dashboard.")

    def _build_services(self) -> dict[str, BaseHoneypotService]:
        # Config'teki servis adini ilgili Python sinifina esleyen kucuk kayit tablosu.
        registry = {
            "http": HTTPHoneypot,
            "ssh": FakeSSHHoneypot,
            "ftp": FTPHoneypot,
            "telnet": TelnetHoneypot,
        }
        services: dict[str, BaseHoneypotService] = {}
        for name, service_config in self.config.services.items():
            # enabled: false olan servisler dinlemeye acilmaz.
            if not service_config.enabled:
                continue
            service_cls = registry.get(name)
            # Taninmayan servis adlari hata vermeden atlanir.
            if service_cls is None:
                continue
            # Her servis kendi portunda dinler ama ortak logger'a olay yazar.
            services[name] = service_cls(
                name=name,
                host=service_config.host,
                port=service_config.port,
                logger=self.logger,
            )
        return services

    def _get_service(self, name: str) -> BaseHoneypotService:
        service = self.services.get(name)
        if service is None:
            raise KeyError(name)
        return service

    def _service_payload(self, service: BaseHoneypotService, action: str) -> dict[str, Any]:
        return {
            "action": action,
            "service": {
                "name": service.name,
                "host": service.host,
                "port": service.port,
                "running": service.running,
                "enabled": True,
            },
        }
