from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ServiceConfig:
    # Tek bir honeypot servisinin acik/kapali durumu ve dinleyecegi adres bilgisi.
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class WebConfig:
    # Web panelinin calisip calismayacagini ve hangi adreste dinleyecegini tutar.
    enabled: bool
    host: str
    port: int


@dataclass(frozen=True)
class LoggingConfig:
    # Olay kayitlarinin yazilacagi JSONL dosyasinin yolu.
    path: Path


@dataclass(frozen=True)
class AppConfig:
    host: str
    logging: LoggingConfig
    web: WebConfig
    services: dict[str, ServiceConfig]


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    # Proje dis bagimlilik istemedigi icin sinirli bir YAML okuyucu kullaniyor.
    raw = parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    # Servislerde host belirtilmezse kok host degeri varsayilan olarak kullanilir.
    base_host = str(raw.get("host", "127.0.0.1"))

    logging_raw = _as_dict(raw.get("logging"))
    web_raw = _as_dict(raw.get("web"))
    services_raw = _as_dict(raw.get("services"))

    services = {
        name: ServiceConfig(
            # Her servis icin enabled verilmezse acik kabul edilir.
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
    # Eksik config bolumleri bos sozluk gibi davranir.
    if value is None:
        return {}
    # Beklenen yapi key/value haritasidir; liste veya duz deger kabul edilmez.
    if not isinstance(value, dict):
        raise ValueError("Expected config section to be a mapping.")
    return value


def parse_simple_yaml(content: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    # Stack, girintiye gore hangi ic sozluge yazdigimizi takip eder.
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in content.splitlines():
        # Bos satirlari ve yorum satirlarini gormezden gelir.
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"Invalid config line: {raw_line}")

        # Girinti azaldiginda ust config bolumune geri cikilir.
        while stack and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]
        key = key.strip()
        value = value.strip()
        if not value:
            # "services:" gibi degersiz satirlar yeni bir alt sozluk baslatir.
            child: dict[str, Any] = {}
            current[key] = child
            stack.append((indent, child))
        else:
            # "port: 8080" gibi satirlarin degeri uygun Python tipine cevrilir.
            current[key] = _parse_scalar(value)

    return root


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    # Tirnakli degerlerde dis tirnaklar atilir.
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    lowered = value.lower()
    # YAML'deki true/false degerleri Python bool tipine cevrilir.
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        # Sayisal port gibi degerleri int yapar; olmazsa metin olarak birakir.
        return int(value)
    except ValueError:
        return value
