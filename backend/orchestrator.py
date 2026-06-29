from __future__ import annotations

import asyncio
import json
from datetime import datetime, UTC
from sqlalchemy import select
from database.models import SystemSettings
from database.database import async_session

from core.config import AppConfig
from core.event_logger import JSONLEventLogger
from system.profiles import HoneypotProfile, get_profile, list_profiles, load_profile
from services import PROFILE_AWARE_SERVICE_TYPES, SERVICE_REGISTRY, ServiceInstance, ServiceType
from services.base import BaseHoneypotService
from web.server import WebDashboard
from system.net_tuner import apply_profile_network_settings
from system.packet_mangler import PacketMangler

async def _get_db_state(session) -> dict:
    try:
        res = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "orchestrator_state"))
        row = res.scalars().first()
        if row:
            return json.loads(row.setting_value)
    except Exception as e:
        print(f"Error reading orchestrator state from DB: {e}")
    return {
        "active_profile": "empty",
        "service_overrides": {},
        "running_services": []
    }

async def _write_db_state(session, state: dict) -> None:
    try:
        res = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == "orchestrator_state"))
        row = res.scalars().first()
        now = datetime.now(UTC)
        val_str = json.dumps(state)
        if row:
            row.setting_value = val_str
            row.updated_at = now
        else:
            session.add(SystemSettings(setting_key="orchestrator_state", setting_value=val_str, updated_at=now))
        await session.commit()
    except Exception as e:
        print(f"Error writing orchestrator state to DB: {e}")

class Orchestrator:
    def __init__(self, config: AppConfig, mode: str = "all") -> None:
        self.mode = mode
        self.config = config
        self.profile = load_profile(config.profile)
        # Butun servisler ayni JSONL logger'i kullanir; olaylar tek dosyada toplanir.
        self.logger = JSONLEventLogger(config.logging.path)
        # Tum servisler adlarina gore burada saklanir; panel istediklerini ayaga kaldirir.
        self.services = self._build_services()
        self._service_lock = asyncio.Lock()
        # Web paneli orkestratorden servis durumunu ve log yolunu okuyacak sekilde baglanir.
        self.web_dashboard = WebDashboard(config.web.host, config.web.port, self)
        # OS obfuscation icin packet mangler servisi baslatilir
        self.packet_mangler = PacketMangler()
        self._sync_task: asyncio.Task | None = None

    async def start(self) -> None:
        # Bu yeni akista uygulama acilisinda yalnizca web paneli dinlemeye baslar.
        if self.mode in ("all", "web") and self.config.web.enabled:
            await self.web_dashboard.start()

        if self.mode in ("all", "daemon", "system"):
            self.packet_mangler.start()
        if self.mode in ("all", "daemon", "system", "decoy"):
            await self._apply_profile(self.profile, emit_log=False)
            self._sync_task = asyncio.create_task(self._db_sync_loop())

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
        if self._sync_task is not None:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None

        # Güvenlik duvarı kurallarını temizler.
        if self.mode in ("all", "daemon", "system"):
            from system.net_tuner import cleanup_firewall
            cleanup_firewall()
            self.packet_mangler.stop()

        # Kapanisin basladigini loglayarak sonradan inceleme icin iz birakir.
        await self.logger.log(
            {
                "service": "orchestrator",
                "event_type": "stopping",
                "summary": "Honeypot orchestrator stopping.",
            }
        )

        # Panel aciksa once onu kapatir.
        if self.mode in ("all", "web") and self.config.web.enabled:
            await self.web_dashboard.stop()

        # Calisan servisler ters sirada kapatilir.
        if self.mode in ("all", "daemon", "decoy"):
            for service in reversed(list(self.services.values())):
                await service.stop()

    async def service_status(self, display_host: str | None = None) -> list[dict[str, object]]:
        # In web mode, read running services from DB
        running_services = set()
        active_profile_name = self.profile.name
        if self.mode == "web":
            async with async_session() as session:
                state = await _get_db_state(session)
                running_services = set(state.get("running_services", []))
                active_profile_name = state.get("active_profile", "empty")
        else:
            running_services = {name for name, s in self.services.items() if s.running}

        profile = get_profile(active_profile_name) or self.profile
        visible_services = set(profile.services)
        return [
            {
                "name": service.name,
                "host": service.host,
                "display_host": self._display_host(service.host, display_host),
                "template": self._service_template_name(service.name),
                "port": service.port,
                "running": service.name in running_services,
                "enabled": True,
            }
            for service in self.services.values()
            if service.name in visible_services
        ]

    async def profile_status(self) -> dict[str, object]:
        active_profile_name = self.profile.name
        if self.mode == "web":
            async with async_session() as session:
                state = await _get_db_state(session)
                active_profile_name = state.get("active_profile", "empty")

        profile = get_profile(active_profile_name) or self.profile
        configured_services = [service_name for service_name in profile.services if service_name in self.services]
        return {
            "current": {
                "name": profile.name,
                "display_name": profile.display_name,
                "services": configured_services,
            },
            "available": list_profiles(),
        }

    async def set_profile(self, name: str) -> dict[str, object]:
        profile = get_profile(name)
        if profile is None:
            raise KeyError(name)

        async with async_session() as session:
            state = await _get_db_state(session)
            state["active_profile"] = name
            state["service_overrides"] = {}  # Clear overrides when profile changes
            await _write_db_state(session, state)

        if self.mode in ("all", "daemon"):
            async with self._service_lock:
                await self._apply_profile(profile, emit_log=True)

        return await self.profile_status()

    async def start_service(self, name: str) -> bool:
        if name not in self.services:
            return False

        async with async_session() as session:
            state = await _get_db_state(session)
            state.setdefault("service_overrides", {})[name] = True
            await _write_db_state(session, state)

        if self.mode in ("all", "daemon", "system", "decoy"):
            service = self.services[name]
            if not service.running or self.mode == "system":
                if self.mode in ("all", "daemon", "decoy"):
                    await service.start()
                
                await self.logger.log({
                    "service": "orchestrator",
                    "event_type": "service_started",
                    "summary": f"Service {name} manually started.",
                })
        return True

    async def stop_service(self, name: str) -> bool:
        if name not in self.services:
            return False

        async with async_session() as session:
            state = await _get_db_state(session)
            state.setdefault("service_overrides", {})[name] = False
            await _write_db_state(session, state)

        if self.mode in ("all", "daemon", "system", "decoy"):
            service = self.services[name]
            if service.running:
                await service.stop()
                running = {n for n, s in self.services.items() if s.running}
                await apply_profile_network_settings(
                    self.profile.name, self.logger, self.services,
                    running, self.config.web.port, self.config.web.enabled,
                )
                await self.logger.log({
                    "service": "orchestrator",
                    "event_type": "service_stopped",
                    "summary": f"Service {name} manually stopped.",
                })
        return True

    def print_startup_summary(self) -> None:
        # Terminalde kullanicinin web panelin hangi adreste acildigini hizlica gormesini saglar.
        print(f"Honeypot Orchestrator started in {self.mode} mode")
        if self.mode in ("all", "web") and self.config.web.enabled:
            print(f"Dashboard: http://{self.config.web.host}:{self.config.web.port}")
        if self.mode in ("all", "daemon"):
            print(f"Active profile: {self.profile.display_name}")
            print("Profile listeners are applied automatically.")

    def _build_services(self) -> dict[str, ServiceInstance]:
        services: dict[str, ServiceInstance] = {}
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
        if service_name.startswith("http"):
            return self.profile.http.template_name
        if service_name.startswith("ssh"):
            return self.profile.ssh.template_name
        if service_name.startswith("ftp"):
            return self.profile.ftp.template_name
        if service_name.startswith("telnet"):
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
        if self.mode in ("all", "daemon", "system"):
            self.packet_mangler.set_profile(profile.name)
        self._sync_service_profiles(profile)
        if self.mode in ("all", "daemon", "system"):
            await apply_profile_network_settings(
                profile.name,
                self.logger,
                self.services,
                target_services,
                self.config.web.port,
                self.config.web.enabled,
            )
        if self.mode in ("all", "daemon", "decoy"):
            try:
                for service_name, service in self.services.items():
                    if service.running and service_name not in target_services:
                        await service.stop()
                        stopped_services.append(service_name)

                for service_name in self._configured_profile_services(profile):
                    service = self.services.get(service_name)
                    if service is None or service.running:
                        continue
                    try:
                        await service.start()
                        started_services.append(service_name)
                    except OSError as err:
                        await self.logger.log(
                            {
                                "service": "orchestrator",
                                "event_type": "service_bind_warning",
                                "summary": f"Could not start {service_name} on port {service.port}: {err}",
                                "error": str(err),
                            }
                        )
                        print(f"Warning: Could not start {service_name} on port {service.port}: {err}")
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
        if self.mode in ("all", "daemon", "decoy"):
            for service_name in reversed(started_services):
                service = self.services.get(service_name)
                if service is not None and service.running:
                    try:
                        await service.stop()
                    except OSError:
                        continue

        self.profile = previous_profile
        self._sync_service_profiles(previous_profile)
        if self.mode in ("all", "daemon", "system"):
            await apply_profile_network_settings(
                previous_profile.name,
                self.logger,
                self.services,
                previously_running,
                self.config.web.port,
                self.config.web.enabled,
            )

        if self.mode in ("all", "daemon", "decoy"):
            for service_name in stopped_services:
                service = self.services.get(service_name)
                if service is None or service_name not in previously_running or service.running:
                    continue
                try:
                    await service.start()
                except OSError:
                    continue

    def _sync_service_profiles(self, profile: HoneypotProfile) -> None:
        for service in self.services.values():
            if hasattr(service, "set_profile"):
                service.set_profile(profile)

    def _create_service(
        self,
        service_cls: ServiceType,
        name: str,
        host: str,
        port: int,
    ) -> ServiceInstance:
        kwargs = {
            "name": name,
            "host": host,
            "port": port,
            "logger": self.logger,
        }
        if issubclass(service_cls, PROFILE_AWARE_SERVICE_TYPES):
            kwargs["profile"] = self.profile
        return service_cls(**kwargs)

    async def _db_sync_loop(self) -> None:
        # Wait a few seconds for DB to initialize
        await asyncio.sleep(5)
        last_profile_name = self.profile.name
        last_overrides = {}

        while True:
            try:
                async with async_session() as session:
                    state = await _get_db_state(session)
                    db_profile_name = state.get("active_profile", "empty")
                    db_overrides = state.get("service_overrides", {})
                    
                    # Detect profile or override changes
                    if db_profile_name != last_profile_name or db_overrides != last_overrides:
                        print(f"Sync Loop: Detected profile/override change in DB (Profile: {db_profile_name}, Overrides: {db_overrides})")
                        profile = get_profile(db_profile_name)
                        if profile:
                            async with self._service_lock:
                                target_services = set(self._configured_profile_services(profile))
                                
                                # Apply manual overrides
                                for svc_name, enabled in db_overrides.items():
                                    if enabled:
                                        target_services.add(svc_name)
                                    else:
                                        target_services.discard(svc_name)

                                self.profile = profile
                                self._sync_service_profiles(profile)
                                
                                if self.mode in ("all", "daemon", "system"):
                                    self.packet_mangler.set_profile(profile.name)
                                    # Apply sysctl/iptables
                                    await apply_profile_network_settings(
                                        profile.name,
                                        self.logger,
                                        self.services,
                                        target_services, # use target_services instead of running because system mode doesn't track running
                                        self.config.web.port,
                                        self.config.web.enabled,
                                    )

                                if self.mode in ("all", "daemon", "decoy"):
                                    # Stop services that shouldn't run
                                    for s_name, service in self.services.items():
                                        if service.running and s_name not in target_services:
                                            await service.stop()

                                    # Start services that should run
                                    for s_name in target_services:
                                        service = self.services.get(s_name)
                                        if service and not service.running:
                                            try:
                                                await service.start()
                                            except OSError as err:
                                                print(f"Warning: Could not start {s_name}: {err}")

                            last_profile_name = db_profile_name
                            last_overrides = dict(db_overrides)
                    
                    if self.mode in ("all", "daemon", "decoy"):
                        # Update running services back to DB
                        running_list = [name for name, s in self.services.items() if s.running]
                        if state.get("running_services") != running_list:
                            state["running_services"] = running_list
                            await _write_db_state(session, state)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Sync Loop Error: {e}")
            
            try:
                await asyncio.sleep(3)
            except asyncio.CancelledError:
                break
