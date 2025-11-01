from typing import Any, Optional
from fastapi import status

class AppException(Exception):
    """Base application exception"""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_type: str = "ApplicationError",
        details: Optional[Any] = None
    ):
        self.message = message
        self.status_code = status_code
        self.error_type = error_type
        self.details = details
        super().__init__(self.message)

class DatabaseError(AppException):
    """Database operation errors"""
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_type="DatabaseError",
            details=details
        )

class ValidationError(AppException):
    """Input validation errors"""
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(
            message=message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_type="ValidationError",
            details=details
        )

class AuthenticationError(AppException):
    """Authentication errors"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_type="AuthenticationError"
        )

class AuthorizationError(AppException):
    """Authorization errors"""
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            status_code=status.HTTP_403_FORBIDDEN,
            error_type="AuthorizationError"
        )

class PlatformAPIError(AppException):
    """External platform API errors"""
    def __init__(self, platform: str, message: str, details: Optional[Any] = None):
        super().__init__(
            message=f"{platform} API error: {message}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_type="PlatformAPIError",
            details=details
        )

class RateLimitError(AppException):
    """Rate limit exceeded errors"""
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(
            message=message,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_type="RateLimitError"
        )

class ComplianceError(AppException):
    """Platform ToS compliance errors"""
    def __init__(self, message: str, platform: str):
        super().__init__(
            message=f"Compliance error for {platform}: {message}",
            status_code=status.HTTP_403_FORBIDDEN,
            error_type="ComplianceError"
        )
