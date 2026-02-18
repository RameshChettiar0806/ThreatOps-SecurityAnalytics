"""Database setup for ThreatOps with Supabase PostgreSQL support."""

import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv

# Load .env file
env_path = Path(__file__).parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

# Get database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+mysqlconnector://root:root@localhost:3306/threatops",
)

# Convert postgres:// to postgresql:// (some services use postgres://)
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

# Detect if using PostgreSQL or MySQL
is_postgres = DATABASE_URL.startswith('postgresql://')

# Engine configuration
engine_config = {
    "echo": False,
    "pool_pre_ping": True,
}

# PostgreSQL/Supabase specific configuration
if is_postgres:
    engine_config["connect_args"] = {
        "connect_timeout": 10,
        "sslmode": "require",  # Supabase requires SSL
    }
    # Connection pooling for PostgreSQL
    engine_config["pool_size"] = 5
    engine_config["max_overflow"] = 10
    engine_config["pool_recycle"] = 3600  # Recycle connections after 1 hour
else:
    # MySQL configuration
    engine_config["connect_args"] = {
        "connect_timeout": 10,
    }
    # Connection pooling for MySQL
    engine_config["pool_size"] = 5
    engine_config["max_overflow"] = 10
    engine_config["pool_recycle"] = 280  # Recycle before MySQL timeout (8 hours)

engine = create_engine(DATABASE_URL, **engine_config)

# Session factory
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency for getting database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
