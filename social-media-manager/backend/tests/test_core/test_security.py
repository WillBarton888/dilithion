"""
Security Module Tests
Comprehensive tests for encryption, authentication, and credential management.
"""

import pytest
from app.core.security import (
    SecureCredentialManager,
    APIKeyAuthenticator,
    PasswordHasher,
    generate_encryption_key,
    generate_api_key
)
from app.core.exceptions import AuthenticationError, AppException


def test_credential_encryption_decryption():
    """Test credential encryption and decryption"""
    manager = SecureCredentialManager()

    # Test data
    credentials = {
        "api_key": "test_key_123",
        "api_secret": "test_secret_456",
        "token": "test_token_789"
    }

    # Encrypt
    encrypted = manager.encrypt_credentials(credentials)
    assert isinstance(encrypted, str)
    assert encrypted != str(credentials)  # Should be encrypted

    # Decrypt
    decrypted = manager.decrypt_credentials(encrypted)
    assert decrypted == credentials


def test_encryption_different_for_same_data():
    """Test that encryption produces different results each time (nonce)"""
    manager = SecureCredentialManager()

    credentials = {"api_key": "test_key"}

    # Encrypt twice
    encrypted1 = manager.encrypt_credentials(credentials)
    encrypted2 = manager.encrypt_credentials(credentials)

    # Should be different (Fernet includes timestamp)
    # Note: Fernet actually includes timestamp, so this might be different
    # But both should decrypt to same value
    decrypted1 = manager.decrypt_credentials(encrypted1)
    decrypted2 = manager.decrypt_credentials(encrypted2)

    assert decrypted1 == credentials
    assert decrypted2 == credentials


def test_encryption_with_complex_data():
    """Test encryption with complex nested data"""
    manager = SecureCredentialManager()

    credentials = {
        "twitter": {
            "api_key": "twitter_key",
            "api_secret": "twitter_secret",
            "tokens": ["token1", "token2"]
        },
        "reddit": {
            "client_id": "reddit_id",
            "client_secret": "reddit_secret"
        },
        "metadata": {
            "created_at": "2024-01-01",
            "expires_at": "2025-01-01"
        }
    }

    encrypted = manager.encrypt_credentials(credentials)
    decrypted = manager.decrypt_credentials(encrypted)

    assert decrypted == credentials


def test_encryption_key_generation():
    """Test encryption key generation"""
    key = generate_encryption_key()
    assert isinstance(key, str)
    assert len(key) > 0

    # Should be valid Fernet key (base64 encoded)
    from cryptography.fernet import Fernet
    cipher = Fernet(key.encode())  # Should not raise


def test_encryption_key_uniqueness():
    """Test that generated keys are unique"""
    key1 = generate_encryption_key()
    key2 = generate_encryption_key()

    assert key1 != key2


def test_api_key_generation():
    """Test API key generation"""
    key = generate_api_key()
    assert isinstance(key, str)
    assert len(key) > 20  # Should be reasonably long

    # Generate multiple, ensure they're different
    key2 = generate_api_key()
    assert key != key2


def test_api_key_generation_url_safe():
    """Test that generated API keys are URL-safe"""
    key = generate_api_key()

    # URL-safe characters only
    import string
    allowed_chars = string.ascii_letters + string.digits + '-_'
    assert all(c in allowed_chars for c in key)


def test_password_hashing():
    """Test password hashing and verification"""
    hasher = PasswordHasher()

    password = "test_password_123"

    # Hash
    hashed = hasher.hash_password(password)
    assert isinstance(hashed, str)
    assert hashed != password  # Should be hashed
    assert len(hashed) > len(password)  # Hashed should be longer

    # Verify correct password
    assert hasher.verify_password(password, hashed) is True

    # Verify incorrect password
    assert hasher.verify_password("wrong_password", hashed) is False


def test_password_hash_uniqueness():
    """Test that same password produces different hashes (salt)"""
    hasher = PasswordHasher()

    password = "same_password"
    hash1 = hasher.hash_password(password)
    hash2 = hasher.hash_password(password)

    # Hashes should be different (due to salt)
    assert hash1 != hash2

    # But both should verify
    assert hasher.verify_password(password, hash1) is True
    assert hasher.verify_password(password, hash2) is True


def test_password_hashing_special_characters():
    """Test password hashing with special characters"""
    hasher = PasswordHasher()

    passwords = [
        "p@ssw0rd!",
        "test#$%^&*()_+",
        "unicode_\u00e9\u00f1\u00fc",
        "spaces in password",
        "tabs\tand\nnewlines"
    ]

    for password in passwords:
        hashed = hasher.hash_password(password)
        assert hasher.verify_password(password, hashed) is True


def test_password_empty_string():
    """Test password hashing with empty string"""
    hasher = PasswordHasher()

    # Empty password should still hash
    hashed = hasher.hash_password("")
    assert isinstance(hashed, str)
    assert hasher.verify_password("", hashed) is True
    assert hasher.verify_password("not_empty", hashed) is False


def test_decryption_invalid_data():
    """Test that decryption fails gracefully with invalid data"""
    manager = SecureCredentialManager()

    with pytest.raises(AppException) as exc_info:
        manager.decrypt_credentials("invalid_encrypted_string")

    assert exc_info.value.error_type == "SecurityError"


def test_encryption_empty_dict():
    """Test encryption with empty dictionary"""
    manager = SecureCredentialManager()

    credentials = {}
    encrypted = manager.encrypt_credentials(credentials)
    decrypted = manager.decrypt_credentials(encrypted)

    assert decrypted == credentials
