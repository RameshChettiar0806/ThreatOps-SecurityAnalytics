"""ORM models for ThreatOps."""

from sqlalchemy import Column, DateTime, Integer, String, Text
from database import Base


class Log(Base):
    """Represents a parsed log record with MITRE mappings."""

    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(100), nullable=False)
    destination_ip = Column(String(100), nullable=False)
    protocol = Column(String(50), nullable=False)
    event_description = Column(Text, nullable=False)
    attack_type = Column(String(100), nullable=False)
    mitre_attack_id = Column(String(50), nullable=False)
    mitre_attack_name = Column(String(255), nullable=False)
    mitre_d3fend_technique = Column(String(255), nullable=False)
