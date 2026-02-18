"""ORM models for ThreatOps matching DBMS schema."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Numeric, 
    Boolean, Enum, ForeignKey, Index, CheckConstraint, TIMESTAMP
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

# Use absolute imports for Vercel compatibility
try:
    from threatops.database import Base
except ImportError:
    # Fallback for local development
    from database import Base


class User(Base):
    """User authentication and RBAC."""
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum('Admin', 'Analyst', 'Manager', 'Engineer', 'Responder', 'Hunter'), nullable=False)
    email = Column(String(100))
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    last_login = Column(TIMESTAMP, nullable=True)
    is_active = Column(Boolean, default=True)

    # Relationships
    raw_logs = relationship("RawLog", back_populates="uploader")
    audit_logs = relationship("AuditLog", back_populates="user")


class RawLog(Base):
    """Raw security event logs."""
    __tablename__ = "raw_logs"

    log_id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    protocol = Column(Enum('TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 
                           'SSH', 'FTP', 'SMTP', 'RDP', 'SMB', 'WMI', 
                           'RPC', 'LDAP'), nullable=False)
    port = Column(Integer, CheckConstraint('port BETWEEN 1 AND 65535'))
    event_description = Column(Text, nullable=False)
    severity = Column(Enum('Low', 'Medium', 'High', 'Critical'), nullable=False)
    uploaded_by = Column(Integer, ForeignKey('users.user_id', ondelete='SET NULL'))
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    # Relationships
    uploader = relationship("User", back_populates="raw_logs")
    correlations = relationship("ThreatCorrelation", back_populates="log", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_timestamp', 'timestamp'),
        Index('idx_severity', 'severity'),
        Index('idx_source_ip', 'source_ip'),
    )


class MitreAttackTechnique(Base):
    """MITRE ATT&CK Techniques."""
    __tablename__ = "mitre_attack_techniques"

    technique_id = Column(String(50), primary_key=True)
    technique_name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False)
    description = Column(Text)
    severity = Column(Enum('Low', 'Medium', 'High', 'Critical'), nullable=False)

    # Relationships
    correlations = relationship("ThreatCorrelation", back_populates="technique")

    __table_args__ = (
        Index('idx_tactic', 'tactic'),
    )


class MitreDefendCountermeasure(Base):
    """MITRE D3FEND Countermeasures."""
    __tablename__ = "mitre_defend_countermeasures"

    countermeasure_id = Column(String(50), primary_key=True)
    countermeasure_name = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False)
    description = Column(Text)
    implementation_cost = Column(Numeric(10, 2), CheckConstraint('implementation_cost >= 0'))
    effectiveness_rating = Column(Enum('Low', 'Medium', 'High', 'Very High'), nullable=False)

    # Relationships
    correlations = relationship("ThreatCorrelation", back_populates="countermeasure")


class ThreatCorrelation(Base):
    """Links logs to MITRE frameworks."""
    __tablename__ = "threat_correlation"

    correlation_id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey('raw_logs.log_id', ondelete='CASCADE'), nullable=False)
    technique_id = Column(String(50), ForeignKey('mitre_attack_techniques.technique_id'), nullable=False)
    countermeasure_id = Column(String(50), ForeignKey('mitre_defend_countermeasures.countermeasure_id'))
    confidence_score = Column(Numeric(3, 2), CheckConstraint('confidence_score BETWEEN 0 AND 1'))
    correlated_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    correlated_by = Column(Integer, ForeignKey('users.user_id', ondelete='SET NULL'))

    # Relationships
    log = relationship("RawLog", back_populates="correlations")
    technique = relationship("MitreAttackTechnique", back_populates="correlations")
    countermeasure = relationship("MitreDefendCountermeasure", back_populates="correlations")
    alerts = relationship("Alert", back_populates="correlation", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_log_id', 'log_id'),
        Index('idx_technique', 'technique_id'),
    )


class Alert(Base):
    """Generated threat alerts."""
    __tablename__ = "alerts"

    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    correlation_id = Column(Integer, ForeignKey('threat_correlation.correlation_id', ondelete='CASCADE'), nullable=False)
    alert_type = Column(Enum('Intrusion', 'Data Breach', 'Malware', 'DDoS', 
                             'Privilege Escalation', 'Reconnaissance'), nullable=False)
    severity = Column(Enum('Low', 'Medium', 'High', 'Critical'), nullable=False)
    status = Column(Enum('Open', 'In Progress', 'Resolved', 'False Positive'), default='Open')
    assigned_to = Column(Integer, ForeignKey('users.user_id', ondelete='SET NULL'))
    description = Column(Text)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())
    resolved_at = Column(TIMESTAMP, nullable=True)

    # Relationships
    correlation = relationship("ThreatCorrelation", back_populates="alerts")

    __table_args__ = (
        Index('idx_status', 'status'),
        Index('idx_severity', 'severity'),
        Index('idx_created', 'created_at'),
    )


class AuditLog(Base):
    """System audit trail."""
    __tablename__ = "audit_logs"

    audit_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.user_id', ondelete='SET NULL'))
    action_type = Column(Enum('LOGIN', 'LOGOUT', 'QUERY_EXECUTION', 'CSV_UPLOAD', 
                              'ALERT_CREATION', 'USER_MANAGEMENT', 'DATA_MODIFICATION'), nullable=False)
    action_details = Column(Text)
    ip_address = Column(String(45))
    timestamp = Column(TIMESTAMP, server_default=func.current_timestamp())
    status = Column(Enum('Success', 'Failure'), default='Success')

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index('idx_user', 'user_id'),
        Index('idx_timestamp', 'timestamp'),
        Index('idx_action', 'action_type'),
    )
