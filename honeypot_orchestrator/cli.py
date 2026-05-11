from __future__ import annotations

import argparse
import asyncio
import signal

from honeypot_orchestrator.config import load_config
from honeypot_orchestrator.orchestrator import Orchestrator


async def run(config_path: str) -> None:
    config = load_config(config_path)
    orchestrator = Orchestrator(config)
    stop_event = asyncio.Event()

    def request_shutdown() -> None:
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, request_shutdown)

    await orchestrator.start()
    try:
        await stop_event.wait()
    finally:
        await orchestrator.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the honeypot orchestrator.")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to the YAML config file. Defaults to config.yaml.",
    )
    args = parser.parse_args()
    asyncio.run(run(args.config))


if __name__ == "__main__":
    main()
