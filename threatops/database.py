"""Database setup for ThreatOps."""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# The DATABASE_URL can be overridden in environment variables.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "mysql+mysqlconnector://root:password@localhost:3306/threatops",
)

engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
