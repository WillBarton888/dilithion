"""
API Dependencies
FastAPI dependencies for authentication, database sessions, etc.
"""

from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from typing import Optional

from app.core.security import api_key_auth
from app.core.exceptions import AuthenticationError
from app.db.session import get_db


async def verify_api_key(x_api_key: str = Header(...)) -> str:
    """
    FastAPI dependency to verify API key from request header.

    Usage:
        @app.get("/protected")
        async def protected_endpoint(api_key: str = Depends(verify_api_key)):
            # Endpoint logic

    Args:
        x_api_key: API key from X-API-Key header

    Returns:
        The verified API key

    Raises:
        HTTPException: 403 if API key invalid
    """
    try:
        api_key_auth.verify_api_key(x_api_key)
        return x_api_key
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )


# Database session dependency (already in session.py, imported here for convenience)
def get_database() -> Session:
    """Get database session"""
    return get_db()
