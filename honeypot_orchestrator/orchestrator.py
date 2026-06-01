from __future__ import annotations

import asyncio

from honeypot_orchestrator.config import AppConfig
from honeypot_orchestrator.event_logger import JSONLEventLogger
from honeypot_orchestrator.profiles import HoneypotProfile, get_profile, list_profiles, load_profile
from honeypot_orchestrator.services import PROFILE_AWARE_SERVICE_TYPES, SERVICE_REGISTRY
from honeypot_orchestrator.services.base import BaseHoneypotService
from honeypot_orchestrator.web.server import WebDashboard


class Orchestrator:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.profile = load_profile(config.profile)
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

        await self._apply_profile(self.profile, emit_log=False)

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

    def service_status(self, display_host: str | None = None) -> list[dict[str, object]]:
        # Web API'nin dondurdugu sade servis durum listesini uretir.
        visible_services = set(self.profile.services)
        return [
            {
                "name": service.name,
                "host": service.host,
                "display_host": self._display_host(service.host, display_host),
                "template": self._service_template_name(service.name),
                "port": service.port,
                "running": service.running,
                "enabled": True,
            }
            for service in self.services.values()
            if service.name in visible_services
        ]

    def profile_status(self) -> dict[str, object]:
        configured_services = self._configured_profile_services(self.profile)
        return {
            "current": {
                "name": self.profile.name,
                "display_name": self.profile.display_name,
                "services": configured_services,
            },
            "available": list_profiles(),
        }

    async def set_profile(self, name: str) -> dict[str, object]:
        async with self._service_lock:
            profile = get_profile(name)
            if profile is None:
                raise KeyError(name)
            await self._apply_profile(profile, emit_log=True)
            return self.profile_status()

    def print_startup_summary(self) -> None:
        # Terminalde kullanicinin web panelin hangi adreste acildigini hizlica gormesini saglar.
        print("Honeypot Orchestrator started")
        if self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        print(f"Active profile: {self.profile.display_name}")
        print("Profile listeners are applied automatically.")

    def _build_services(self) -> dict[str, BaseHoneypotService]:
        services: dict[str, BaseHoneypotService] = {}
        for name, service_config in self.config.services.items():
            # enabled: false olan servisler dinlemeye acilmaz.
            if not service_config.enabled:
                continue
            service_cls = SERVICE_REGISTRY.get(name)
            # Taninmayan servis adlari hata vermeden atlanir.
            if service_cls is None:
                continue
            # Her servis kendi portunda dinler ama ortak logger'a olay yazar.
            services[name] = self._create_service(
                service_cls=service_cls,
                name=name,
                host=service_config.host,
                port=service_config.port,
            )
        return services

    def _display_host(self, host: str, display_host: str | None) -> str:
        if host in {"0.0.0.0", "::", ""} and display_host:
            return display_host
        return host

    def _service_template_name(self, service_name: str) -> str:
        if service_name == "http":
            return self.profile.http.template_name
        if service_name == "ssh":
            return self.profile.ssh.template_name
        if service_name == "ftp":
            return self.profile.ftp.template_name
        if service_name == "telnet":
            return self.profile.telnet.template_name
        return service_name

    def _configured_profile_services(self, profile: HoneypotProfile) -> list[str]:
        return [service_name for service_name in profile.services if service_name in self.services]

    async def _apply_profile(self, profile: HoneypotProfile, *, emit_log: bool) -> None:
        previous_profile = self.profile
        previously_running = {
            service_name for service_name, service in self.services.items() if service.running
        }
        target_services = set(self._configured_profile_services(profile))
        started_services: list[str] = []
        stopped_services: list[str] = []

        self.profile = profile
        self._sync_service_profiles(profile)
        try:
            for service_name, service in self.services.items():
                if service.running and service_name not in target_services:
                    await service.stop()
                    stopped_services.append(service_name)

            for service_name in self._configured_profile_services(profile):
                service = self.services.get(service_name)
                if service is None or service.running:
                    continue
                await service.start()
                started_services.append(service_name)
        except Exception:
            await self._rollback_profile_change(
                previous_profile=previous_profile,
                previously_running=previously_running,
                started_services=started_services,
                stopped_services=stopped_services,
            )
            raise

        if emit_log:
            await self.logger.log(
                {
                    "service": "orchestrator",
                    "event_type": "profile_changed",
                    "summary": f"Active profile switched to {profile.display_name}.",
                    "profile": profile.name,
                    "started_services": started_services,
                    "stopped_services": stopped_services,
                }
            )

    async def _rollback_profile_change(
        self,
        *,
        previous_profile: HoneypotProfile,
        previously_running: set[str],
        started_services: list[str],
        stopped_services: list[str],
    ) -> None:
        for service_name in reversed(started_services):
            service = self.services.get(service_name)
            if service is not None and service.running:
                try:
                    await service.stop()
                except OSError:
                    continue

        self.profile = previous_profile
        self._sync_service_profiles(previous_profile)

        for service_name in stopped_services:
            service = self.services.get(service_name)
            if service is None or service_name not in previously_running or service.running:
                continue
            try:
                await service.start()
            except OSError:
                continue

    def _sync_service_profiles(self, profile: HoneypotProfile) -> None:
        for service_name in ("http", "ssh", "ftp", "telnet", "smb"):
            service = self.services.get(service_name)
            if service is not None and hasattr(service, "set_profile"):
                service.set_profile(profile)

    def _create_service(
        self,
        service_cls: type[BaseHoneypotService],
        name: str,
        host: str,
        port: int,
    ) -> BaseHoneypotService:
        kwargs = {
            "name": name,
            "host": host,
            "port": port,
            "logger": self.logger,
        }
        if issubclass(service_cls, PROFILE_AWARE_SERVICE_TYPES):
            kwargs["profile"] = self.profile
        return service_cls(**kwargs)
