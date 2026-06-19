from __future__ import annotations

import argparse
import asyncio
import platform
import signal
from collections.abc import Callable

from core.config import load_config
from orchestrator import Orchestrator
from database.database import init_db



from sqlalchemy import select
from database.database import async_session
from database.models import SystemSettings
from core.crypto_utils import encrypt_value

async def sync_api_keys(config) -> None:
    # Migrate TI keys from config to DB if they exist and DB is empty
    try:
        async with async_session() as session:
            for key_name, plain_val in [
                ("ti_abuseipdb_key", config.threat_intel.abuseipdb_key),
                ("ti_greynoise_key", config.threat_intel.greynoise_key)
            ]:
                if not plain_val:
                    continue
                
                # Check if it already exists in DB
                result = await session.execute(select(SystemSettings).where(SystemSettings.setting_key == key_name))
                existing = result.scalars().first()
                if not existing:
                    print(f"Migrating {key_name} to encrypted DB storage...")
                    encrypted = encrypt_value(plain_val)
                    session.add(SystemSettings(setting_key=key_name, setting_value=encrypted))
            await session.commit()
    except Exception as e:
        print(f"Failed to sync API keys: {e}")

async def run(config_path: str, mode: str = "all") -> None:
    # Veritabani tablolarini asenkron olarak olusturur.
    await init_db()
    
    if mode == "ti":
        config = load_config(config_path)
        await sync_api_keys(config)
        from ti_worker import run_ti_worker
        await run_ti_worker(config_path)
        return

    # YAML ayar dosyasini okuyup uygulamanin calisma ayarlarina donusturur.
    config = load_config(config_path)
    await sync_api_keys(config)
    # Tum honeypot servislerini ve web panelini yonetecek ana sinifi hazirlar.
    orchestrator = Orchestrator(config, mode=mode)
    # Program kapanana kadar beklemek icin kullanilan asenkron durdurma sinyali.
    stop_event = asyncio.Event()

    def request_shutdown() -> None:
        # Ctrl+C veya sistem kapatma sinyali geldiginde bekleyen donguyu uyandirir.
        stop_event.set()

    loop = asyncio.get_running_loop()
    try:
        restore_handlers = _install_shutdown_handlers(loop, request_shutdown)
    except NotImplementedError:
        restore_handlers = None

    try:
        await orchestrator.start()
        # Servisler calisirken burada beklenir; sinyal gelince finally bloguna gecilir.
        await stop_event.wait()
    finally:
        if restore_handlers is not None:
            restore_handlers()
        # Portlari serbest birakmak ve son loglari yazmak icin kontrollu kapanis yapar.
        await orchestrator.stop()


def main() -> None:
    # Komut satirindan --config parametresini alir; verilmezse config.yaml kullanilir.
    parser = argparse.ArgumentParser(description="Start the honeypot orchestrator.")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file. Defaults to config.yaml.",
    )
    parser.add_argument(
        "--mode",
        choices=["all", "daemon", "web", "ti", "system", "decoy"],
        default="all",
        help="Run mode: 'all' (default), 'daemon', 'system' (controller only), 'decoy' (traps only), 'web' (API), or 'ti' (threat intel worker).",
    )
    args = parser.parse_args()
    # Asenkron run fonksiyonunu Python'un event loop'u icinde calistirir.
    try:
        asyncio.run(run(args.config, mode=args.mode))
    except KeyboardInterrupt:
        # Ctrl+C artik temiz kapanis istedigi icin burada sessizce cikilir.
        pass


def _install_shutdown_handlers(
    loop: asyncio.AbstractEventLoop,
    request_shutdown: Callable[[], None],
) -> Callable[[], None]:
    def schedule_shutdown(*_: object) -> None:
        loop.call_soon_threadsafe(request_shutdown)

    if platform.system() == "Windows":
        signals = [signal.SIGINT]
        if hasattr(signal, "SIGBREAK"):
            signals.append(signal.SIGBREAK)
        previous_handlers = {sig: signal.getsignal(sig) for sig in signals}
        for sig in signals:
            signal.signal(sig, schedule_shutdown)

        def restore_handlers() -> None:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)

        return restore_handlers

    signals = [signal.SIGINT, signal.SIGTERM]
    for sig in signals:
        # Isletim sistemi sinyallerini duzgun kapanis fonksiyonuna baglar.
        loop.add_signal_handler(sig, schedule_shutdown)

    def restore_handlers() -> None:
        for sig in signals:
            loop.remove_signal_handler(sig)

    return restore_handlers


if __name__ == "__main__":
    main()
