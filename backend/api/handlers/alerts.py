import asyncio
import json
from collections import defaultdict
from api.router import router
from database.database import async_session
from sqlalchemy import select
from database.models import Event

class AlertStreamer:
    def __init__(self):
        self.clients = set()
        self.last_id = 0
        self._task = None

    async def start(self):
        if not self._task:
            self._task = asyncio.create_task(self._poll_events())

    async def _poll_events(self):
        # Initialize last_id
        try:
            async with async_session() as session:
                result = await session.execute(select(Event.id).order_by(Event.id.desc()).limit(1))
                row = result.scalar_one_or_none()
                if row:
                    self.last_id = row
        except Exception as e:
            print(f"AlertStreamer init error: {e}")

        while True:
            await asyncio.sleep(2.0)
            if not self.clients:
                continue

            try:
                async with async_session() as session:
                    result = await session.execute(
                        select(Event).where(Event.id > self.last_id).order_by(Event.id.asc())
                    )
                    events = result.scalars().all()

                if not events:
                    continue

                self.last_id = events[-1].id

                # Group by IP
                ip_events = defaultdict(list)
                for e in events:
                    if e.src_ip:
                        ip_events[e.src_ip].append(e)

                alerts = []
                for ip, evs in ip_events.items():
                    count = len(evs)
                    if count > 5:
                        # Aggregated alert
                        alerts.append({
                            "type": "aggregated",
                            "src_ip": ip,
                            "count": count,
                            "summary": f"Yüksek yoğunluklu şüpheli aktivite (Port Tarama/Flood) tespit edildi: {count} istek."
                        })
                    else:
                        # Individual alerts for critical events
                        for e in evs:
                            alerts.append({
                                "type": "individual",
                                "src_ip": ip,
                                "event_type": e.event_type,
                                "service": e.service,
                                "summary": e.summary or f"{e.service} üzerinde {e.event_type} tespit edildi."
                            })

                if alerts:
                    payload = json.dumps({"alerts": alerts})
                    # Broadcast to all clients
                    for q in list(self.clients):
                        try:
                            q.put_nowait(payload)
                        except asyncio.QueueFull:
                            pass

            except Exception as e:
                print(f"Error polling events for alerts: {e}")

streamer = AlertStreamer()

@router.get("/api/alerts/stream")
async def alerts_stream_handler(server, request):
    await streamer.start()
    
    queue = asyncio.Queue(maxsize=100)
    streamer.clients.add(queue)

    async def event_generator():
        try:
            while True:
                # Send a ping every 15 seconds to keep connection alive
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield data
                except asyncio.TimeoutError:
                    yield json.dumps({"type": "ping"})
        except asyncio.CancelledError:
            pass
        finally:
            streamer.clients.discard(queue)

    return {"stream": True, "generator": event_generator()}
