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
        # Bütün servisler aynı JSONL logger'ı kullanır; olaylar tek dosyada toplanır.
        self.logger = JSONLEventLogger(config.logging.path)
        # config.yaml içindeki enabled servislerden gerçek servis nesneleri oluşturulur.
        self.services = self._build_services()
        # Web paneli orkestratörden servis durumunu ve log yolunu okuyacak şekilde bağlanır.
        self.web_dashboard = WebDashboard(config.web.host, config.web.port, self)

    async def start(self) -> None:
        # Önce honeypot servisleri dinlemeye başlar.
        for service in self.services:
            await service.start()

        # Web paneli isteğe bağlıdır; config.web.enabled false ise hiç açılmaz.
        if self.config.web.enabled:
            await self.web_dashboard.start()

        # Başlangıç olayı log dosyasına yazılır; panelde de görülebilir.
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "started",
                "summary": "Honeypot orchestrator started.",
            }
        )
        self.print_startup_summary()

    async def stop(self) -> None:
        # Kapanışın başladığını loglayarak sonradan inceleme için iz bırakır.
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "stopping",
                "summary": "Honeypot orchestrator stopping.",
            }
        )

        # Panel açıksa önce onu kapatır.
        if self.config.web.enabled:
            await self.web_dashboard.stop()

        # Servisleri ters sırada kapatmak, başlatma sırasının simetrik kapanmasını sağlar.
        for service in reversed(self.services):
            await service.stop()

    def service_status(self) -> list[dict[str, object]]:
        # Web API'nin döndürdüğü sade servis durum listesini üretir.
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
        # Terminalde kullanıcının hangi portların açıldığını hızlıca görmesini sağlar.
        print("Honeypot Orchestrator started")
        if self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        for service in self.services:
            print(f"{service.name}: {service.host}:{service.port}")

    def _build_services(self) -> list[object]:
        # Config'teki servis adını ilgili Python sınıfına eşleyen küçük kayıt tablosu.
        registry = {
            "http": HTTPHoneypot,
            "ssh": FakeSSHHoneypot,
            "ftp": FTPHoneypot,
            "telnet": TelnetHoneypot,
        }
        services = []
        for name, service_config in self.config.services.items():
            # enabled: false olan servisler dinlemeye açılmaz.
            if not service_config.enabled:
                continue
            service_cls = registry.get(name)
            # Tanınmayan servis adları hata vermeden atlanır.
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
