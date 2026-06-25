from __future__ import annotations
from typing import Any
from collections import Counter
from datetime import datetime, UTC, timedelta
from http import HTTPStatus

from api.router import router
from web.utils import read_recent_events
from core.mitre import map_event_to_mitre, MITRE_TECHNIQUES, MITRE_TACTICS
from core.geo import bulk_lookup

@router.get("/api/analyze")
async def handle_get_analyze(self, request: dict[str, Any]) -> dict[str, Any]:
    # Query the last 5000 events
    events = await read_recent_events(self.orchestrator.config.logging.path, 5000)
    
    # 1. MITRE ATT&CK Matrix Aggregation
    techniques_counts = {tech_id: 0 for tech_id in MITRE_TECHNIQUES}
    tactic_attackers = {tactic_name: Counter() for tactic_name in MITRE_TACTICS}
    for event in events:
        tech_id = map_event_to_mitre(event)
        if tech_id and tech_id in techniques_counts:
            techniques_counts[tech_id] += 1
            tactic_name = MITRE_TECHNIQUES[tech_id]["tactic"]
            src_ip = event.get("src_ip")
            if src_ip:
                tactic_attackers[tactic_name][src_ip] += 1
            
    techniques_list = []
    for tech_id, info in MITRE_TECHNIQUES.items():
        techniques_list.append({
            "id": tech_id,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "count": techniques_counts[tech_id]
        })

    tactics_list = []
    for tactic_name, desc in MITRE_TACTICS.items():
        tactics_list.append({
            "name": tactic_name,
            "description": desc
        })

    # 2. Country Breakdown (GeoIP Aggregation)
    ips = [event["src_ip"] for event in events if event.get("src_ip")]
    # Fetch geo details in bulk
    geo_data = {}
    if ips:
        try:
            geo_data = bulk_lookup(list(set(ips)))
        except Exception as e:
            print(f"Error in bulk_lookup on analyze handler: {e}")
            
    country_counts = Counter()
    for ip in ips:
        info = geo_data.get(ip, {})
        country_name = info.get("country", "Unknown")
        country_code = info.get("countryCode", "XX")
        country_counts[(country_name, country_code)] += 1

    country_breakdown = []
    for (name, code), count in country_counts.most_common(15):
        country_breakdown.append({
            "country": name,
            "country_code": code,
            "count": count
        })

    # 3. Threat Timeline (Hourly volumes in the last 24 hours)
    now = datetime.now(UTC)
    timeline_buckets = []
    for i in range(23, -1, -1):
        t = now - timedelta(hours=i)
        timeline_buckets.append({
            "hour": t.strftime("%H:00"),
            "date_hour": t.strftime("%m-%d %H:00"),
            "timestamp": int(t.replace(minute=0, second=0, microsecond=0).timestamp()),
            "count": 0
        })

    for event in events:
        ts_str = event.get("timestamp")
        if not ts_str:
            continue
        try:
            # Parse '2026-06-25 08:30:15 UTC' format
            dt = datetime.strptime(ts_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            diff = now - dt
            hours_ago = int(diff.total_seconds() // 3600)
            if 0 <= hours_ago < 24:
                timeline_buckets[23 - hours_ago]["count"] += 1
        except Exception:
            continue

    tactic_attackers_payload = {}
    for tactic_name, counter in tactic_attackers.items():
        tactic_attackers_payload[tactic_name] = [
            {"ip": ip, "count": count} for ip, count in counter.most_common(5)
        ]

    payload = {
        "tactics": tactics_list,
        "techniques": techniques_list,
        "country_breakdown": country_breakdown,
        "timeline": timeline_buckets,
        "tactic_attackers": tactic_attackers_payload,
        "total_events_analyzed": len(events)
    }

    return self._json_response(payload)
