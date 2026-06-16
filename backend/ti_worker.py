import asyncio
import time
from typing import Any

from sqlalchemy import select  # type: ignore
from sqlalchemy.sql import func  # type: ignore
from database import async_session
from models import Event
from config import load_config
from threat_intel import enrich_top_ips

async def run_ti_worker(config_path: str = "config.yaml"):
    """
    Arka planda calisarak son 24 saatte en cok saldiran IP'leri bulur 
    ve Threat Intel onbellegine ekler.
    """
    config = load_config(config_path)
    print("Threat Intel Worker started. Running every 3 minutes...")
    
    while True:
        try:
            # 1. Son 24 saatteki loglari tara, top 50 IP'yi bul
            from datetime import datetime, timedelta, timezone
            
            async with async_session() as session:
                cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
                stmt = (
                    select(Event.src_ip, func.count(Event.id))
                    .where(Event.src_ip.isnot(None), Event.timestamp >= cutoff)
                    .group_by(Event.src_ip)
                    .order_by(func.count(Event.id).desc())
                    .limit(50)
                )
                result = await session.execute(stmt)
                top_ips = {row[0]: row[1] for row in result.all() if row[0]}

            if top_ips:
                print(f"TI Worker: Analyzing {len(top_ips)} top IP addresses...")
                # 2. IP'leri zenginlestir (eksik olanlar icin API istekleri atilacak)
                await enrich_top_ips(top_ips, honeypot_host=config.host)
                print("TI Worker: Enrichment complete.")
            else:
                print("TI Worker: No active IP addresses found in the last 24 hours.")

        except Exception as e:
            print(f"TI Worker error: {e}")

        # Her 3 dakikada bir tekrarla
        await asyncio.sleep(180)

if __name__ == "__main__":
    asyncio.run(run_ti_worker())
