from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServiceConfig:
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class WebConfig:
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class LoggingConfig:
    path: Path


@dataclass(frozen=True)
class AppConfig:
    host: str
    logging: LoggingConfig
    web: WebConfig
    services: dict[str, ServiceConfig]


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    raw = parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    base_host = str(raw.get("host", "127.0.0.1"))

    logging_raw = _as_dict(raw.get("logging"))
    web_raw = _as_dict(raw.get("web"))
    services_raw = _as_dict(raw.get("services"))

    services = {
        name: ServiceConfig(
            enabled=bool(value.get("enabled", True)),
            host=str(value.get("host", base_host)),
            port=int(value["port"]),
        )
        for name, value in services_raw.items()
    }

    return AppConfig(
        host=base_host,
        logging=LoggingConfig(path=Path(logging_raw.get("path", "logs/events.jsonl"))),
        web=WebConfig(
            enabled=bool(web_raw.get("enabled", True)),
            host=str(web_raw.get("host", base_host)),
            port=int(web_raw.get("port", 8000)),
        ),
        services=services,
    )


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Expected config section to be a mapping.")
    return value


def parse_simple_yaml(content: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in content.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"Invalid config line: {raw_line}")

        while stack and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]
        key = key.strip()
        value = value.strip()
        if not value:
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            current[key] = _parse_scalar(value)

    return root


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value
