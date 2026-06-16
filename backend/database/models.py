import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON, Text, Boolean
from database.database import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.utcnow, index=True)
    service = Column(String, index=True)
    event_type = Column(String, index=True)
    src_ip = Column(String, index=True, nullable=True)
    src_port = Column(Integer, nullable=True)
    summary = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="viewer")

class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String, primary_key=True, index=True)
    username = Column(String, index=True, nullable=False)
    role = Column(String, default="viewer")
    created_at = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)

class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)

class Blacklist(Base):
    __tablename__ = "blacklist"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)

class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    ip = Column(String, primary_key=True, index=True)
    data = Column(JSON, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)

class SystemSettings(Base):
    __tablename__ = "system_settings"

    setting_key = Column(String, primary_key=True, index=True)
    setting_value = Column(String, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)
