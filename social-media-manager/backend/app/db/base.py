"""
SQLAlchemy base configuration and engine setup.

This module provides the database engine, session factory, and declarative base
for all SQLAlchemy models in the application.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

# Get database URL from environment variable, default to SQLite for development
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./social_media_manager.db")

# Create engine with appropriate settings for SQLite and PostgreSQL
if DATABASE_URL.startswith("sqlite"):
    # SQLite specific configuration
    # check_same_thread=False is needed for FastAPI compatibility
    # StaticPool for better SQLite concurrency in testing/development
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=True,  # Log SQL statements for development
    )
else:
    # PostgreSQL configuration
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,  # Verify connections before using them
        pool_size=10,  # Number of connections to maintain
        max_overflow=20,  # Additional connections when pool is exhausted
        echo=True,  # Log SQL statements for development
    )

# Create SessionLocal class for database sessions
# autocommit=False: Don't auto-commit transactions
# autoflush=False: Don't auto-flush before queries
# bind: Bind to our engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base class for models to inherit from
Base = declarative_base()


def init_db():
    """
    Initialize database by creating all tables.

    This should be called on application startup to ensure
    all tables exist in the database.
    """
    from . import models  # Import models to register them with Base
    Base.metadata.create_all(bind=engine)
