from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServiceConfig:
    # Tek bir honeypot servisinin açık/kapalı durumu ve dinleyeceği adres bilgisi.
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class WebConfig:
    # Web panelinin çalışıp çalışmayacağını ve hangi adreste dinleyeceğini tutar.
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class LoggingConfig:
    # Olay kayıtlarının yazılacağı JSONL dosyasının yolu.
    path: Path


@dataclass(frozen=True)
class AppConfig:
    host: str
    logging: LoggingConfig
    web: WebConfig
    services: dict[str, ServiceConfig]


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    # Proje dış bağımlılık istemediği için sınırlı bir YAML okuyucu kullanıyor.
    raw = parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    # Servislerde host belirtilmezse kök host değeri varsayılan olarak kullanılır.
    base_host = str(raw.get("host", "127.0.0.1"))

    logging_raw = _as_dict(raw.get("logging"))
    web_raw = _as_dict(raw.get("web"))
    services_raw = _as_dict(raw.get("services"))

    services = {
        name: ServiceConfig(
            # Her servis için enabled verilmezse açık kabul edilir.
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
    # Eksik config bölümleri boş sözlük gibi davranır.
    if value is None:
        return {}
    # Beklenen yapı key/value haritasıdır; liste veya düz değer kabul edilmez.
    if not isinstance(value, dict):
        raise ValueError("Expected config section to be a mapping.")
    return value


def parse_simple_yaml(content: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    # Stack, girintiye göre hangi iç sözlüğe yazdığımızı takip eder.
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in content.splitlines():
        # Boş satırları ve yorum satırlarını görmezden gelir.
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"Invalid config line: {raw_line}")

        # Girinti azaldığında üst config bölümüne geri çıkılır.
        while stack and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]
        key = key.strip()
        value = value.strip()
        if not value:
            # "services:" gibi değersiz satırlar yeni bir alt sözlük başlatır.
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            # "port: 8080" gibi satırların değeri uygun Python tipine çevrilir.
            current[key] = _parse_scalar(value)

    return root


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    # Tırnaklı değerlerde dış tırnaklar atılır.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    lowered = value.lower()
    # YAML'deki true/false değerleri Python bool tipine çevrilir.
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        # Sayısal port gibi değerleri int yapar; olmazsa metin olarak bırakır.
        return int(value)
    except ValueError:
        return value
