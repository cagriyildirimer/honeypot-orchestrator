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
        self.logger = JSONLEventLogger(config.logging.path)
        self.services = self._build_services()
        self.web_dashboard = WebDashboard(config.web.host, config.web.port, self)

    async def start(self) -> None:
        for service in self.services:
            await service.start()

        if self.config.web.enabled:
            await self.web_dashboard.start()

        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "started",
                "summary": "Honeypot orchestrator started.",
            }
        )
        self.print_startup_summary()

    async def stop(self) -> None:
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "stopping",
                "summary": "Honeypot orchestrator stopping.",
            }
        )

        if self.config.web.enabled:
            await self.web_dashboard.stop()

        for service in reversed(self.services):
            await service.stop()

    def service_status(self) -> list[dict[str, object]]:
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
        print("Honeypot Orchestrator started")
        if self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        for service in self.services:
            print(f"{service.name}: {service.host}:{service.port}")

    def _build_services(self) -> list[object]:
        registry = {
            "http": HTTPHoneypot,
            "ssh": FakeSSHHoneypot,
            "ftp": FTPHoneypot,
            "telnet": TelnetHoneypot,
        }
        services = []
        for name, service_config in self.config.services.items():
            if not service_config.enabled:
                continue
            service_cls = registry.get(name)
            if service_cls is None:
                continue
            services.append(
                service_cls(
                    name=name,
                    host=service_config.host,
                    port=service_config.port,
                    logger=self.logger,
                )
            )
        return services
