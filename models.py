"""
SQLAlchemy ORM Database Schema Definitions
"""

from sqlalchemy import Column, Integer, String, Float, JSON, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()

class IncidentLog(Base):
    __tablename__ = "incident_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False, index=True) # URL, QR, EMAIL, UPI, MULTI
    target = Column(String(1000), nullable=False)
    risk_score = Column(Float, nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True) # LOW, MEDIUM, HIGH, CRITICAL
    raw_signals = Column(JSON, nullable=False)
    xai_breakdown = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class ThreatFeed(Base):
    __tablename__ = "threat_feeds"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(30), nullable=False) # IP, DOMAIN, HASH, UPI
    ioc_value = Column(String(500), nullable=False, unique=True, index=True)
    category = Column(String(100), nullable=False)
    source = Column(String(100), nullable=False)
    confidence = Column(Float, default=100.0)
    created_at = Column(DateTime, default=datetime.utcnow)

class AuditTrail(Base):
    __tablename__ = "audit_trails"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), default="SYSTEM_ANALYST")
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
