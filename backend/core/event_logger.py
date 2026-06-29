from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from database.database import async_session
from database.models import Event
from core.siem_forwarder import siem_forwarder

def sanitize_null_bytes(val: Any) -> Any:
    if isinstance(val, str):
        return val.replace("\x00", "")
    elif isinstance(val, dict):
        return {k: sanitize_null_bytes(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_null_bytes(x) for x in val]
    return val


class DBEventLogger:
    def __init__(self, path: Any = None) -> None:
        self.queue: asyncio.Queue[dict[str, Any]] | None = None
        self._task: asyncio.Task | None = None

    async def log(self, event: dict[str, Any]) -> None:
        if self.queue is None:
            self.queue = asyncio.Queue()
            self._task = asyncio.create_task(self._process_queue())
        await self.queue.put(event)

    async def _process_queue(self) -> None:
        batch: list[dict[str, Any]] = []
        while True:
            try:
                if not batch:
                    item = await self.queue.get()
                    batch.append(sanitize_null_bytes(item))
                
                while not self.queue.empty() and len(batch) < 100:
                    try:
                        item = self.queue.get_nowait()
                        batch.append(sanitize_null_bytes(item))
                    except asyncio.QueueEmpty:
                        break
                
                async with async_session() as session:
                    events = []
                    for event in batch:
                        service = event.get("service", "unknown")
                        event_type = event.get("event_type", "unknown")
                        src_ip = event.get("src_ip")
                        src_port = event.get("src_port")
                        summary = event.get("summary")
                        details = {
                            k: v for k, v in event.items() 
                            if k not in ("service", "event_type", "src_ip", "src_port", "summary", "timestamp")
                        }
                        
                        events.append(Event(
                            timestamp=datetime.now(UTC),
                            service=service,
                            event_type=event_type,
                            src_ip=src_ip,
                            src_port=src_port,
                            summary=summary,
                            details=details
                        ))
                    
                    session.add_all(events)
                    await session.commit()
                
                # SIEM Forwarding
                for event in batch:
                    # Copy the event to avoid mutating the original
                    forward_evt = event.copy()
                    forward_evt["timestamp"] = datetime.now(UTC).isoformat()
                    asyncio.create_task(siem_forwarder.forward(forward_evt))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in DBEventLogger queue: {e}")
                await asyncio.sleep(1)
            finally:
                for _ in range(len(batch)):
                    try:
                        self.queue.task_done()
                    except ValueError:
                        pass
                batch.clear()

JSONLEventLogger = DBEventLogger  # Geriye donuk uyumluluk icin alias
