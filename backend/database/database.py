import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# PostgreSQL URL, defaults to sqlite for local tests if not set
_db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tests", "logs", "honeypot.db"))
_sqlite_uri = _db_path.replace("\\", "/")
DATABASE_URL = os.environ.get(
    "HONEYPOT_DB_URL", f"sqlite+aiosqlite:///{_sqlite_uri}"
)

# Create async engine
from sqlalchemy.pool import NullPool
engine_args = {}
if "sqlite" in DATABASE_URL:
    engine_args["connect_args"] = {"check_same_thread": False}
if os.environ.get("HONEYPOT_TESTING") == "true":
    engine_args["poolclass"] = NullPool

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    **engine_args
)

# Async session factory
async_session = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session

async def init_db() -> None:
    # Optional: creates all tables based on Base metadata
    # Useful for simple deployments without Alembic migrations
    import asyncio
    from . import models  # noqa: F401 (Register models to Base.metadata to prevent circular imports)
    
    max_retries = 15
    retry_delay = 2
    for attempt in range(1, max_retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            break
        except Exception as e:
            if attempt == max_retries:
                print(f"Database initialization failed after {max_retries} attempts: {e}")
                raise
            print(f"Database connection failed (attempt {attempt}/{max_retries}), retrying in {retry_delay}s: {e}")
            await asyncio.sleep(retry_delay)
