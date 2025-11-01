"""
Database session management.

This module provides database session utilities and dependencies
for FastAPI endpoints.
"""

from typing import Generator
from sqlalchemy.orm import Session
from .base import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI endpoints to get database session.

    Creates a new SQLAlchemy session for each request and ensures
    it's properly closed after the request is complete.

    Yields:
        Session: SQLAlchemy database session

    Example:
        @app.get("/items")
        def read_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
