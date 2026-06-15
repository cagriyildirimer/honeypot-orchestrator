import asyncio
import json
import sys
import os
from pathlib import Path
from datetime import datetime, UTC

# Add parent dir to path so we can import from backend
sys.path.append(str(Path(__file__).parent.parent))

from database import engine, async_session, Base, init_db
from models import Event, User, Session, Whitelist, Blacklist
from web.server import ROLE_ADMIN, ROLE_VIEWER

async def migrate_events(log_dir: Path):
    print("Migrating events...")
    events_path = log_dir / "events.jsonl"
    if not events_path.exists():
        print("No events.jsonl found.")
        return

    with open(events_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    batch_size = 1000
    batch = []
    
    async with async_session() as session:
        for i, line in enumerate(lines):
            try:
                data = json.loads(line)
                ts_str = data.pop("timestamp", None)
                if ts_str:
                    try:
                        ts = datetime.strptime(ts_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
                    except:
                        ts = datetime.now(UTC)
                else:
                    ts = datetime.now(UTC)

                event = Event(
                    timestamp=ts,
                    service=data.pop("service", "unknown"),
                    event_type=data.pop("event_type", "unknown"),
                    src_ip=data.pop("src_ip", None),
                    src_port=data.pop("src_port", None),
                    summary=data.pop("summary", None),
                    details=data if data else None
                )
                batch.append(event)

                if len(batch) >= batch_size:
                    session.add_all(batch)
                    await session.commit()
                    print(f"Migrated {i+1} events...")
                    batch.clear()
            except Exception as e:
                print(f"Error parsing line: {e}")
        
        if batch:
            session.add_all(batch)
            await session.commit()
            print(f"Migrated {len(lines)} events.")


async def migrate_users(log_dir: Path):
    print("Migrating users...")
    users_path = log_dir / "web_users.json"
    if not users_path.exists():
        print("No web_users.json found.")
        return

    with open(users_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            users = data.get("users", {})
        except:
            return

    async with async_session() as session:
        for username, info in users.items():
            if isinstance(info, dict):
                password = info.get("password", "")
                role = info.get("role", ROLE_VIEWER)
            else:
                password = info
                role = ROLE_ADMIN

            user = User(username=username, password_hash=password, role=role)
            session.add(user)
        await session.commit()
    print("Users migrated.")


async def migrate_sessions(log_dir: Path):
    print("Migrating sessions...")
    sessions_path = log_dir / "web_sessions.json"
    if not sessions_path.exists():
        print("No web_sessions.json found.")
        return

    with open(sessions_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except:
            return

    async with async_session() as session:
        for sid, info in data.items():
            if isinstance(info, str):
                username = info
                role = ROLE_VIEWER
                ts = datetime.now(UTC)
            else:
                username = info.get("username", "")
                role = info.get("role", ROLE_VIEWER)
                try:
                    ts = datetime.fromtimestamp(info.get("created_at", datetime.now().timestamp()), UTC)
                except:
                    ts = datetime.now(UTC)

            s = Session(session_id=sid, username=username, role=role, created_at=ts)
            session.add(s)
        await session.commit()
    print("Sessions migrated.")


async def migrate_defense(log_dir: Path):
    print("Migrating whitelist/blacklist...")
    whitelist_path = log_dir / "whitelist.json"
    blacklist_path = log_dir / "blacklist.json"

    async with async_session() as session:
        if whitelist_path.exists():
            with open(whitelist_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f).get("entries", [])
                    for item in data:
                        session.add(Whitelist(
                            ip=item.get("ip", ""),
                            description=item.get("description", ""),
                            timestamp=datetime.now(UTC)
                        ))
                except:
                    pass

        if blacklist_path.exists():
            with open(blacklist_path, "r", encoding="utf-8") as f:
                try:
                    data = json.load(f).get("entries", [])
                    for item in data:
                        session.add(Blacklist(
                            ip=item.get("ip", ""),
                            description=item.get("description", ""),
                            timestamp=datetime.now(UTC)
                        ))
                except:
                    pass
        await session.commit()
    print("Defense lists migrated.")


async def main():
    print("Initializing Database...")
    await init_db()

    # Locate logs directory
    base_dir = Path(__file__).parent.parent.parent
    log_dir = base_dir / "logs"

    if not log_dir.exists():
        print(f"Log directory not found at {log_dir}")
        return

    await migrate_events(log_dir)
    await migrate_users(log_dir)
    await migrate_sessions(log_dir)
    await migrate_defense(log_dir)
    print("Migration complete!")

if __name__ == "__main__":
    asyncio.run(main())
