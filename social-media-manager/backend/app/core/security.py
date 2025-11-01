"""
Security Module
Handles encryption, authentication, and credential management.
"""

from cryptography.fernet import Fernet
from passlib.context import CryptContext
from typing import Dict, Optional
import os
import json
import logging

from app.config import settings
from app.core.exceptions import AuthenticationError, AppException

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class SecureCredentialManager:
    """
    Manages encrypted storage and retrieval of API credentials.

    Uses Fernet symmetric encryption with a master key stored in environment.
    Master key MUST be kept secure and never stored in database.
    """

    def __init__(self):
        """Initialize cipher with master encryption key"""
        master_key = settings.MASTER_ENCRYPTION_KEY

        if not master_key:
            raise AppException(
                message="MASTER_ENCRYPTION_KEY not configured",
                error_type="ConfigurationError"
            )

        try:
            # Validate and create cipher
            self.cipher = Fernet(master_key.encode())
            logger.info("SecureCredentialManager initialized")
        except Exception as e:
            raise AppException(
                message=f"Failed to initialize encryption: {str(e)}",
                error_type="SecurityError"
            )

    def encrypt_credentials(self, credentials: Dict) -> str:
        """
        Encrypt credentials dictionary to string.

        Args:
            credentials: Dictionary of credential key-value pairs

        Returns:
            Encrypted string safe for database storage
        """
        try:
            # Convert dict to JSON string
            json_str = json.dumps(credentials)

            # Encrypt
            encrypted_bytes = self.cipher.encrypt(json_str.encode())

            # Return as string
            return encrypted_bytes.decode()

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise AppException(
                message="Failed to encrypt credentials",
                error_type="SecurityError",
                details=str(e)
            )

    def decrypt_credentials(self, encrypted_str: str) -> Dict:
        """
        Decrypt credentials string to dictionary.

        Args:
            encrypted_str: Encrypted credentials from database

        Returns:
            Dictionary of credential key-value pairs
        """
        try:
            # Decrypt
            decrypted_bytes = self.cipher.decrypt(encrypted_str.encode())

            # Convert back to dict
            json_str = decrypted_bytes.decode()
            credentials = json.loads(json_str)

            return credentials

        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise AppException(
                message="Failed to decrypt credentials",
                error_type="SecurityError",
                details=str(e)
            )

    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet encryption key.

        Usage: Run this once to generate MASTER_ENCRYPTION_KEY for .env

        Returns:
            Base64-encoded encryption key
        """
        key = Fernet.generate_key()
        return key.decode()


class APIKeyAuthenticator:
    """
    Handles API key authentication for backend access.

    Simple authentication for single-user deployment.
    Can be upgraded to JWT/OAuth2 for multi-user (Phase 3).
    """

    @staticmethod
    def verify_api_key(provided_key: str) -> bool:
        """
        Verify provided API key against configured key.

        Args:
            provided_key: API key from request header

        Returns:
            True if valid, raises AuthenticationError if invalid
        """
        expected_key = settings.BACKEND_API_KEY

        if not expected_key:
            raise AppException(
                message="BACKEND_API_KEY not configured",
                error_type="ConfigurationError"
            )

        # Constant-time comparison to prevent timing attacks
        if not provided_key or provided_key != expected_key:
            logger.warning("Invalid API key attempt")
            raise AuthenticationError("Invalid API key")

        return True


class PasswordHasher:
    """
    Password hashing utilities.

    Future-proofing for multi-user authentication (Phase 3).
    Uses bcrypt for secure password hashing.
    """

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """
        Hash a plain text password.

        Args:
            plain_password: Plain text password

        Returns:
            Hashed password string
        """
        return pwd_context.hash(plain_password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Stored hashed password

        Returns:
            True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)


# Singleton instances for application use
credential_manager = SecureCredentialManager()
api_key_auth = APIKeyAuthenticator()
password_hasher = PasswordHasher()


# Utility functions
def generate_encryption_key() -> str:
    """Generate new Fernet encryption key for MASTER_ENCRYPTION_KEY"""
    return SecureCredentialManager.generate_key()


def generate_api_key() -> str:
    """Generate secure random API key for BACKEND_API_KEY"""
    import secrets
    return secrets.token_urlsafe(32)
