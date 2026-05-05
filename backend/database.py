"""Database setup for ThreatOps with PostgreSQL and MySQL support."""

import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from sqlalchemy import create_engine
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
    "postgresql://postgres:postgres@localhost:5432/threatops",
)

# Normalize accidental whitespace from environment files.
if DATABASE_URL:
    DATABASE_URL = DATABASE_URL.strip()

# Convert postgres:// to postgresql:// (some services use postgres://)
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)


def _is_postgres_url(url: str) -> bool:
    """Return True for PostgreSQL URLs, including explicit driver schemes."""
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme.startswith('postgresql') or parsed.scheme == 'postgres'


def _is_mysql_url(url: str) -> bool:
    """Return True for MySQL URLs, including explicit driver schemes."""
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.scheme.startswith('mysql')


def _is_local_host(url: str) -> bool:
    """Return True when the connection target is a local database host."""
    if not url:
        return False
    hostname = (urlparse(url).hostname or '').lower()
    return hostname in {'localhost', '127.0.0.1', '::1', ''}


# Detect active database type
is_postgres = _is_postgres_url(DATABASE_URL)
is_mysql = _is_mysql_url(DATABASE_URL)


def _postgres_query_has_sslmode(url: str) -> bool:
    """Check whether sslmode is already present in the DATABASE_URL query string."""
    if not url:
        return False
    query_params = parse_qs(urlparse(url).query)
    return 'sslmode' in query_params

# Engine configuration
engine_config = {
    "echo": False,
    "pool_pre_ping": True,
}

# Detect if running in serverless environment (Vercel)
is_serverless = os.getenv("VERCEL") is not None

# PostgreSQL/Supabase specific configuration
if is_postgres:
    engine_config["connect_args"] = {
        "connect_timeout": 10,
    }
    # Remote PostgreSQL deployments such as Supabase require SSL.
    if not _is_local_host(DATABASE_URL) and not _postgres_query_has_sslmode(DATABASE_URL):
        engine_config["connect_args"]["sslmode"] = "require"
    # For serverless (Vercel), use NullPool - no connection pooling
    if is_serverless:
        engine_config["poolclass"] = NullPool
    else:
        # Connection pooling for PostgreSQL (local dev)
        engine_config["pool_size"] = 5
        engine_config["max_overflow"] = 10
        engine_config["pool_recycle"] = 3600  # Recycle connections after 1 hour
elif is_mysql:
    engine_config["connect_args"] = {
        "connect_timeout": 10,
    }
    engine_config["pool_size"] = 5
    engine_config["max_overflow"] = 10
    engine_config["pool_recycle"] = 280
else:
    raise ValueError(
        "Unsupported DATABASE_URL. Use a PostgreSQL/Supabase or MySQL connection string."
    )

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
