import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# PostgreSQL URL, defaults to sqlite for local tests if not set
DATABASE_URL = os.environ.get(
    "HONEYPOT_DB_URL", "sqlite+aiosqlite:///logs/honeypot.db"
)

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    # SQLite-specific arguments; ignored by asyncpg
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
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
    import database.models as models  # Register models to Base.metadata to prevent circular imports
    
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
