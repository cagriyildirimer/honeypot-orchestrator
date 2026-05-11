from __future__ import annotations

import asyncio

from honeypot_orchestrator.config import AppConfig
from honeypot_orchestrator.event_logger import JSONLEventLogger
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
        # config.yaml icindeki enabled servislerden gercek servis nesneleri olusturulur.
        self.services = self._build_services()
        # Web paneli orkestratorden servis durumunu ve log yolunu okuyacak sekilde baglanir.
        self.web_dashboard = WebDashboard(config.web.host, config.web.port, self)

    async def start(self) -> None:
        # Once honeypot servisleri dinlemeye baslar.
        for service in self.services:
            await service.start()

        # Web paneli istege baglidir; config.web.enabled false ise hic acilmaz.
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

        # Servisleri ters sirada kapatmak, baslatma sirasinin simetrik kapanmasini saglar.
        for service in reversed(self.services):
            await service.stop()

    def service_status(self) -> list[dict[str, object]]:
        # Web API'nin dondurdugu sade servis durum listesini uretir.
        return [
            {
                "name": service.name,
                "host": service.host,
                "port": service.port,
                "running": service.running,
            }
            for service in self.services
        ]

    def print_startup_summary(self) -> None:
        # Terminalde kullanicinin hangi portlarin acildigini hizlica gormesini saglar.
        print("Honeypot Orchestrator started")
        if self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        for service in self.services:
            print(f"{service.name}: {service.host}:{service.port}")

    def _build_services(self) -> list[object]:
        # Config'teki servis adini ilgili Python sinifina esleyen kucuk kayit tablosu.
        registry = {
            "http": HTTPHoneypot,
            "ssh": FakeSSHHoneypot,
            "ftp": FTPHoneypot,
            "telnet": TelnetHoneypot,
        }
        services = []
        for name, service_config in self.config.services.items():
            # enabled: false olan servisler dinlemeye acilmaz.
            if not service_config.enabled:
                continue
            service_cls = registry.get(name)
            # Taninmayan servis adlari hata vermeden atlanir.
            if service_cls is None:
                continue
            # Her servis kendi portunda dinler ama ortak logger'a olay yazar.
            services.append(
                service_cls(
                    name=name,
                    host=service_config.host,
                    port=service_config.port,
                    logger=self.logger,
                )
            )
        return services
