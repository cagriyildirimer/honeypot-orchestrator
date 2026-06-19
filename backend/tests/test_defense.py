import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from defense import record_suspicious_event, _suspicious_counters, _rate_limits

@pytest.fixture(autouse=True)
def reset_globals():
    _suspicious_counters.clear()
    _rate_limits.clear()
    yield
    _suspicious_counters.clear()
    _rate_limits.clear()

@pytest.mark.asyncio
async def test_record_suspicious_event():
    with patch("defense.is_whitelisted", new_callable=AsyncMock) as mock_wl, \
         patch("defense.add_to_blacklist", new_callable=AsyncMock) as mock_bl, \
         patch("defense.is_auto_blacklist_enabled", new_callable=AsyncMock) as mock_auto:
         
         mock_wl.return_value = False
         mock_auto.return_value = True
         
         ip = "192.168.1.100"
         # Send 99 events with time separated
         with patch("time.time") as mock_time:
             for i in range(99):
                 mock_time.return_value = 1000.0 + (i * 0.2)
                 await record_suspicious_event(ip)
                 
             mock_bl.assert_not_called()
             
             # Send the 100th event
             mock_time.return_value = 1000.0 + (100 * 0.2)
             await record_suspicious_event(ip)
             mock_bl.assert_called_once_with(ip, "Automated ban: reached 100 suspicious events")
