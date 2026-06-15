import re
from pathlib import Path

def patch_server():
    p = Path("c:/Users/cagri/honeypot-orchestrator/backend/web/server.py")
    content = p.read_text(encoding="utf-8")

    # 1. Imports
    if "from database import async_session" not in content:
        content = content.replace("import uuid\n", "import uuid\nfrom database import async_session\nfrom models import Event, User, Session as DBSession\nfrom sqlalchemy import select, delete, desc\n")

    # 2. Init -> move loads to start()
    content = content.replace(
        "self._sessions: dict[str, dict[str, Any]] = self._load_sessions()",
        "self._sessions: dict[str, dict[str, Any]] = {}"
    )
    content = content.replace(
        "self._reload_users()",
        "# self._reload_users() moved to start()"
    )
    
    start_func_old = """    async def start(self) -> None:
        # Tarayici istekleri handle_client metoduna yonlendirilir.
        self._server = await asyncio.start_server(self.handle_client, self.host, self.port)"""
    start_func_new = """    async def start(self) -> None:
        self._sessions = await self._load_sessions()
        await self._reload_users()
        # Tarayici istekleri handle_client metoduna yonlendirilir.
        self._server = await asyncio.start_server(self.handle_client, self.host, self.port)"""
    content = content.replace(start_func_old, start_func_new)

    # 3. Fix _build_overview_payload to be async
    content = content.replace("def _build_overview_payload(self, request: dict[str, Any]) -> dict[str, Any]:", "async def _build_overview_payload(self, request: dict[str, Any]) -> dict[str, Any]:")
    content = content.replace("return self._json_response(self._build_overview_payload(request))", "return self._json_response(await self._build_overview_payload(request))")

    # 4. Await read_recent_events
    content = re.sub(r'read_recent_events\((.*?)\)', r'await read_recent_events(\1)', content)
    # Revert if we added double awaits
    content = content.replace('await await read_recent_events', 'await read_recent_events')
    content = content.replace('def await read_recent_events', 'async def read_recent_events')

    # 5. Fix _save_sessions
    content = content.replace("def _save_sessions(self) -> None:", "async def _save_sessions(self) -> None:")
    content = content.replace("self._save_sessions()", "await self._save_sessions()")

    # 6. Fix _reload_users inside _save_sessions
    content = content.replace("        self._reload_users()", "        await self._reload_users()")

    # 7. Fix _reload_users def
    content = content.replace("def _reload_users(self) -> None:", "async def _reload_users(self) -> None:")
    content = content.replace("self._users = _load_users(", "self._users = await _load_users(")

    # 8. Fix _save_users calls
    content = content.replace("_save_users(", "await _save_users(")
    # Fix def _save_users
    content = content.replace("def await _save_users", "async def _save_users")

    # 9. Rewrite _load_sessions
    load_sessions_old = """    def _load_sessions(self) -> dict[str, dict[str, Any]]:
        try:
            if self._sessions_path.exists():
                with open(self._sessions_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    sessions = {}
                    for k, v in data.items():
                        if isinstance(v, str):
                            sessions[k] = {"username": v, "created_at": time.time()}
                        else:
                            sessions[k] = v
                    return sessions
        except Exception:
            pass
        return {}"""
    load_sessions_new = """    async def _load_sessions(self) -> dict[str, dict[str, Any]]:
        try:
            async with async_session() as session:
                result = await session.execute(select(DBSession))
                sessions = {}
                for r in result.scalars().all():
                    sessions[r.session_id] = {
                        "username": r.username,
                        "role": r.role,
                        "created_at": r.created_at.timestamp() if r.created_at else time.time()
                    }
                return sessions
        except Exception as e:
            print(f"DB load sessions error: {e}")
            return {}"""
    content = content.replace(load_sessions_old, load_sessions_new)

    # 10. Rewrite _save_sessions
    save_sessions_old = """    async def _save_sessions(self) -> None:
        try:
            with open(self._sessions_path, "w", encoding="utf-8") as f:
                json.dump(self._sessions, f)
        except Exception:
            pass
        await self._reload_users()"""
    save_sessions_new = """    async def _save_sessions(self) -> None:
        try:
            async with async_session() as session:
                await session.execute(delete(DBSession))
                now = datetime.now(UTC)
                for sid, data in self._sessions.items():
                    session.add(DBSession(
                        session_id=sid, 
                        username=data.get("username", "unknown"),
                        role=data.get("role", ROLE_VIEWER),
                        created_at=now
                    ))
                await session.commit()
        except Exception as e:
            print(f"DB save sessions error: {e}")
        await self._reload_users()"""
    content = content.replace(save_sessions_old, save_sessions_new)

    # 11. Rewrite _load_users
    load_users_regex = r"def _load_users\(path: Path, default_users: dict\[str, dict\[str, str\]\]\) -> dict\[str, dict\[str, str\]\]:.*?return cleaned"
    load_users_new = """async def _load_users(path: Path, default_users: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    cleaned: dict[str, dict[str, str]] = {}
    needs_save = False

    try:
        async with async_session() as session:
            result = await session.execute(select(User))
            records = result.scalars().all()
            for r in records:
                cleaned[r.username] = {"password": r.password_hash, "role": r.role}
    except Exception as e:
        print(f"DB load users error: {e}")

    for username, user in default_users.items():
        if username not in cleaned:
            cleaned[username] = dict(user)
            needs_save = True

    for username, user_info in cleaned.items():
        password = user_info["password"]
        if not password.startswith("pbkdf2_sha256$"):
            user_info["password"] = _hash_password(password)
            needs_save = True

    if needs_save:
        await _save_users(path, cleaned)

    return cleaned"""
    content = re.sub(load_users_regex, load_users_new, content, flags=re.DOTALL)

    # 12. Rewrite _save_users
    save_users_regex = r"async def _save_users\(path: Path, users: dict\[str, dict\[str, str\]\]\) -> None:.*?path\.write_text\(.*?encoding=\"utf-8\"\)"
    save_users_new = """async def _save_users(path: Path, users: dict[str, dict[str, str]]) -> None:
    try:
        async with async_session() as session:
            await session.execute(delete(User))
            for username, data in users.items():
                session.add(User(
                    username=username,
                    password_hash=data["password"],
                    role=data["role"]
                ))
            await session.commit()
    except Exception as e:
        print(f"DB save users error: {e}")"""
    content = re.sub(save_users_regex, save_users_new, content, flags=re.DOTALL)

    # 13. Rewrite read_recent_events
    read_events_regex = r"async def read_recent_events\(path: Path, limit: int\) -> list\[dict\[str, Any\]\]:.*?return list\(reversed\(records\)\)"
    read_events_new = """async def read_recent_events(path: Path, limit: int) -> list[dict[str, Any]]:
    try:
        async with async_session() as session:
            stmt = select(Event).order_by(desc(Event.timestamp)).limit(max(1, min(limit, 10000)))
            result = await session.execute(stmt)
            records = []
            for r in result.scalars().all():
                event_data = {
                    "id": r.id,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if r.timestamp else "",
                    "service": r.service,
                    "event_type": r.event_type,
                    "src_ip": r.src_ip,
                    "src_port": r.src_port,
                    "summary": r.summary,
                }
                if r.details:
                    event_data.update(r.details)
                records.append(event_data)
            return list(reversed(records))
    except Exception as e:
        print(f"DB read events error: {e}")
        return []"""
    content = re.sub(read_events_regex, read_events_new, content, flags=re.DOTALL)

    p.write_text(content, encoding="utf-8")
    print("Patched server.py successfully!")

if __name__ == "__main__":
    patch_server()
