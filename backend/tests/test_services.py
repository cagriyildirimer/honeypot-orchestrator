import pytest
import asyncio
from unittest.mock import AsyncMock
from services.base import BaseHoneypotService

class DummyService(BaseHoneypotService):
    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

@pytest.mark.asyncio
async def test_base_service_toggle():
    mock_logger = AsyncMock()
    service = DummyService("dummy_service", "127.0.0.1", 9999, mock_logger)
    
    assert service.name == "dummy_service"
    assert service.host == "127.0.0.1"
    assert service.port == 9999
    assert service.is_running() is False
    
    await service.start()
    assert service.is_running() is True
    
    await service.stop()
    assert service.is_running() is False
