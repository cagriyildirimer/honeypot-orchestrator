from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "0.1.0"


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
class AuthConfig:
    # Web paneli girisi icin kullanici adi ve parola bilgisini tutar.
    username: str
    password: str


@dataclass(frozen=True)
class LoggingConfig:
    # Olay kayitlarinin yazilacagi JSONL dosyasinin yolu.
    path: Path


@dataclass(frozen=True)
class AppConfig:
    host: str
    profile: str
    logging: LoggingConfig
    web: WebConfig
    auth: AuthConfig
    services: dict[str, ServiceConfig]


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    # Proje dis bagimlilik istemedigi icin sinirli bir YAML okuyucu kullaniyor.
    raw = parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    # Servislerde host belirtilmezse kok host degeri varsayilan olarak kullanilir.
    base_host = _env_str("HONEYPOT_HOST", str(raw.get("host", "127.0.0.1")))

    logging_raw = _as_dict(raw.get("logging"))
    web_raw = _as_dict(raw.get("web"))
    auth_raw = _as_dict(raw.get("auth"))
    services_raw = _as_dict(raw.get("services"))

    services = {
        name: ServiceConfig(
            # Her servis icin enabled verilmezse acik kabul edilir.
            enabled=_env_bool(_service_env_key(name, "ENABLED"), bool(value.get("enabled", True))),
            host=_env_str(_service_env_key(name, "HOST"), str(value.get("host", base_host))),
            port=_env_int(_service_env_key(name, "PORT"), int(value["port"])),
        )
        for name, value in services_raw.items()
    }

    config = AppConfig(
        host=base_host,
        profile=_env_str("HONEYPOT_PROFILE", str(raw.get("profile", "linux_server"))),
        logging=LoggingConfig(
            path=Path(_env_str("HONEYPOT_LOG_PATH", str(logging_raw.get("path", "logs/events.jsonl"))))
        ),
        web=WebConfig(
            enabled=_env_bool("HONEYPOT_WEB_ENABLED", bool(web_raw.get("enabled", True))),
            host=_env_str("HONEYPOT_WEB_HOST", str(web_raw.get("host", base_host))),
            port=_env_int("HONEYPOT_WEB_PORT", int(web_raw.get("port", 8000))),
        ),
        auth=AuthConfig(
            username=_env_str("HONEYPOT_AUTH_USERNAME", str(auth_raw.get("username", "admin"))),
            password=_env_str("HONEYPOT_AUTH_PASSWORD", str(auth_raw.get("password", "admin"))),
        ),
        services=services,
    )
    _validate_config(config)
    return config


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


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _service_env_key(service_name: str, field: str) -> str:
    normalized = service_name.upper().replace("-", "_")
    return f"HONEYPOT_SERVICE_{normalized}_{field}"


def _validate_config(config: AppConfig) -> None:
    from profiles import PROFILES

    if not (1 <= config.web.port <= 65535):
        raise ValueError(f"Invalid web port: {config.web.port}")

    for service_name, service in config.services.items():
        if not (1 <= service.port <= 65535):
            raise ValueError(f"Invalid port for service {service_name}: {service.port}")

    # Web paneli her zaman açık olduğu için tüm etkin servislerle çakışması kontrol edilir
    if config.web.enabled:
        for service_name, service in config.services.items():
            if service.enabled and service.port == config.web.port:
                if _hosts_conflict(config.web.host, service.host):
                    raise ValueError(
                        f"Port conflict detected between web ({config.web.host}:{config.web.port}) "
                        f"and service {service_name} ({service.host}:{service.port})."
                    )

    # Her profil için kendi içindeki servislerin çakışması kontrol edilir
    for profile_name, profile in PROFILES.items():
        bind_targets: list[tuple[str, str, int]] = []
        for service_name in profile.services:
            service = config.services.get(service_name)
            if service and service.enabled:
                bind_targets.append((service_name, service.host, service.port))

        for index, (left_name, left_host, left_port) in enumerate(bind_targets):
            for right_name, right_host, right_port in bind_targets[index + 1 :]:
                if left_port != right_port:
                    continue
                if _hosts_conflict(left_host, right_host):
                    raise ValueError(
                        f"Port conflict detected in profile '{profile_name}' between {left_name} ({left_host}:{left_port}) "
                        f"and {right_name} ({right_host}:{right_port})."
                    )


def _hosts_conflict(left: str, right: str) -> bool:
    left_normalized = left.strip() or "0.0.0.0"
    right_normalized = right.strip() or "0.0.0.0"
    wildcard_hosts = {"0.0.0.0", "::"}
    return (
        left_normalized == right_normalized
        or left_normalized in wildcard_hosts
        or right_normalized in wildcard_hosts
    )
