from __future__ import annotations

import argparse
import asyncio
import signal

from honeypot_orchestrator.config import load_config
from honeypot_orchestrator.orchestrator import Orchestrator


async def run(config_path: str) -> None:
    # YAML ayar dosyasını okuyup uygulamanın çalışma ayarlarına dönüştürür.
    config = load_config(config_path)
    # Tüm honeypot servislerini ve web panelini yönetecek ana sınıfı hazırlar.
    orchestrator = Orchestrator(config)
    # Program kapanana kadar beklemek için kullanılan asenkron durdurma sinyali.
    stop_event = asyncio.Event()

    def request_shutdown() -> None:
        # Ctrl+C veya sistem kapatma sinyali geldiğinde bekleyen döngüyü uyandırır.
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        # İşletim sistemi sinyallerini düzgün kapanış fonksiyonuna bağlar.
        loop.add_signal_handler(sig, request_shutdown)

    await orchestrator.start()
    try:
        # Servisler çalışırken burada beklenir; sinyal gelince finally bloğuna geçilir.
        await stop_event.wait()
    finally:
        # Portları serbest bırakmak ve son logları yazmak için kontrollü kapanış yapar.
        await orchestrator.stop()


def main() -> None:
    # Komut satırından --config parametresini alır; verilmezse config.yaml kullanılır.
    parser = argparse.ArgumentParser(description="Start the honeypot orchestrator.")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file. Defaults to config.yaml.",
    )
    args = parser.parse_args()
    # Asenkron run fonksiyonunu Python'un event loop'u içinde çalıştırır.
    asyncio.run(run(args.config))


if __name__ == "__main__":
    main()
