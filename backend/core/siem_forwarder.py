import asyncio
import json
import socket
import logging
import aiohttp

logger = logging.getLogger(__name__)

class SIEMForwarder:
    def __init__(self):
        self.enabled = False
        self.host = ""
        self.port = 514
        self.protocol = "udp"  # udp, tcp, http
        self.scope = "all"  # all, alerts
        self._http_session = None

    async def update_config(self, config_dict):
        self.enabled = config_dict.get("enabled", False)
        self.host = config_dict.get("host", "")
        self.port = int(config_dict.get("port", 514))
        self.protocol = config_dict.get("protocol", "udp").lower()
        self.scope = config_dict.get("scope", "all")
        
        if self.protocol == "http" and self._http_session is None:
            self._http_session = aiohttp.ClientSession()
        elif self.protocol != "http" and self._http_session:
            await self._http_session.close()
            self._http_session = None

    async def forward(self, event: dict):
        if not self.enabled or not self.host:
            return

        if self.scope == "alerts":
            critical_types = ["login_attempt", "exploit_attempt", "command_execution"]
            if event.get("event_type") not in critical_types:
                return

        # Prepare syslog style JSON payload
        payload = json.dumps(event) + "\n"
        data = payload.encode('utf-8')

        try:
            if self.protocol == "udp":
                # Async UDP requires specific loop operations, but standard socket is okay for fire-and-forget
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.sendto(data, (self.host, self.port))
                sock.close()
            elif self.protocol == "tcp":
                reader, writer = await asyncio.open_connection(self.host, self.port)
                writer.write(data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            elif self.protocol == "http":
                if self._http_session:
                    url = f"http://{self.host}:{self.port}"
                    if not self.host.startswith("http"):
                        url = f"http://{self.host}:{self.port}"
                    else:
                        url = f"{self.host}:{self.port}"
                    async with self._http_session.post(url, json=event, timeout=5) as resp:
                        pass
        except Exception as e:
            logger.error(f"SIEM forwarding failed: {e}")

siem_forwarder = SIEMForwarder()
