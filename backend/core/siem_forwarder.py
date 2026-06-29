import asyncio
import json
import socket
import logging
import aiohttp
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)

class SIEMForwarder:
    def __init__(self):
        self.configs = []
        self._http_session = None
        self._tcp_writers = {}

    def _normalize_configs(self, config_data):
        if isinstance(config_data, dict) and isinstance(config_data.get("configs"), list):
            raw_configs = config_data.get("configs", [])
        elif isinstance(config_data, list):
            raw_configs = config_data
        elif isinstance(config_data, dict):
            raw_configs = [config_data] if config_data.get("host") else []
        else:
            raw_configs = []

        configs = []
        for index, item in enumerate(raw_configs):
            if not isinstance(item, dict):
                continue
            config_id = str(item.get("id") or f"siem-{index + 1}")
            name = str(item.get("name") or item.get("host") or f"SIEM {index + 1}").strip()
            host = str(item.get("host") or "").strip()
            protocol = str(item.get("protocol") or "udp").lower()
            if protocol not in {"udp", "tcp", "http"}:
                protocol = "udp"
            scope = str(item.get("scope") or "all").lower()
            if scope not in {"all", "alerts"}:
                scope = "all"
            try:
                port = int(item.get("port", 514))
            except (TypeError, ValueError):
                port = 514
            port = max(1, min(port, 65535))
            configs.append({
                "id": config_id,
                "name": name or f"SIEM {index + 1}",
                "enabled": bool(item.get("enabled", False)),
                "host": host,
                "port": port,
                "protocol": protocol,
                "scope": scope,
            })
        return configs

    async def update_config(self, config_dict):
        self.configs = self._normalize_configs(config_dict)
        new_keys = {
            (c.get("id"), c.get("host"), c.get("port"), c.get("protocol"))
            for c in self.configs
            if c.get("enabled")
        }

        for key, writer in list(self._tcp_writers.items()):
            if key not in new_keys:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                self._tcp_writers.pop(key, None)

        needs_http = any(c.get("enabled") and c.get("protocol") == "http" for c in self.configs)
        if needs_http and self._http_session is None:
            self._http_session = aiohttp.ClientSession()
        elif not needs_http and self._http_session:
            await self._http_session.close()
            self._http_session = None

    async def forward(self, event: dict):
        for config in list(self.configs):
            await self.forward_to(config, event)

    async def forward_to(self, config: dict, event: dict):
        if not config.get("enabled") or not config.get("host"):
            return

        if config.get("scope") == "alerts":
            critical_types = ["login_attempt", "exploit_attempt", "command_execution"]
            if event.get("event_type") not in critical_types:
                return

        # Prepare syslog style JSON payload
        payload = json.dumps(event) + "\n"
        data = payload.encode('utf-8')

        try:
            host = config["host"]
            port = int(config["port"])
            protocol = config["protocol"]
            if protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.sendto(data, (host, port))
                sock.close()
            elif protocol == "tcp":
                key = (config.get("id"), host, port, protocol)
                writer = self._tcp_writers.get(key)
                if writer is None:
                    _, writer = await asyncio.open_connection(host, port)
                    self._tcp_writers[key] = writer
                
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception as write_err:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    self._tcp_writers.pop(key, None)
                    raise write_err
            elif protocol == "http":
                if self._http_session:
                    url = self._http_url(host, port)
                    async with self._http_session.post(url, json=event, timeout=5) as resp:
                        pass
        except Exception as e:
            logger.error(f"SIEM forwarding failed: {e}")

    def _http_url(self, host: str, port: int) -> str:
        if host.startswith(("http://", "https://")):
            parsed = urlsplit(host)
            if parsed.port is not None:
                return host
            netloc = parsed.netloc
            if netloc:
                netloc = f"{netloc}:{port}"
                return urlunsplit((parsed.scheme, netloc, parsed.path or "", parsed.query, parsed.fragment))
            return host
        return f"http://{host}:{port}"

siem_forwarder = SIEMForwarder()
