import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from orchestrator import Orchestrator
from core.config import AppConfig

@pytest.fixture
def mock_config():
    # A simple mock configuration object
    class MockConfig:
        host = "127.0.0.1"
        profile = "empty"
        services = {}
        class WebConfig:
            enabled = True
            port = 8000
            host = "127.0.0.1"
        web = WebConfig()
        class LoggingConfig:
            path = "logs/test.jsonl"
        logging = LoggingConfig()
    return MockConfig()

@pytest.mark.asyncio
async def test_orchestrator_initialization(mock_config):
    # Mocking external dependencies used in __init__
    with patch('core.event_logger.DBEventLogger', autospec=True):
        orch = Orchestrator(mock_config)
        assert orch.config == mock_config
        assert orch._active_profile == "empty"
        assert len(orch.services) == 0

@pytest.mark.asyncio
async def test_start_and_stop_service(mock_config):
    with patch('core.event_logger.DBEventLogger', autospec=True), \
         patch('orchestrator.Orchestrator.set_profile', new_callable=AsyncMock):
        orch = Orchestrator(mock_config)
        
        # We don't have any real services in the mock config, so start_service should return False
        result = await orch.start_service("nonexistent_service")
        assert result is False
        
        # Likewise for stop_service
        result = await orch.stop_service("nonexistent_service")
        assert result is False
