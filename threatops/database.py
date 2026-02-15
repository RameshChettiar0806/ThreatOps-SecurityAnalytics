"""Database setup for ThreatOps with enhanced security."""

import os
from pathlib import Path
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv

# Load .env file from parent directory
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Database URL with connection pooling for production
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+mysqlconnector://root:root@localhost:3306/threatops",
)

# Engine configuration
engine_config = {
    "echo": False,
    "pool_pre_ping": True,
    "connect_args": {
        "connect_timeout": 10,
    }
}

# Use NullPool for serverless (Vercel)
if os.getenv("VERCEL"):
    engine_config["poolclass"] = NullPool

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
