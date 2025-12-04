# Copyright (c) 2025 The Dilithion Core developers
# Distributed under the MIT software license

"""Utility functions and assertion helpers for Dilithion functional tests

Based on Bitcoin Core's test_framework/util.py patterns
"""

import time
import json
from typing import Any, Callable, Optional


class AssertionError(Exception):
    """Custom assertion error for better test failure messages"""
    pass


def assert_equal(thing1: Any, thing2: Any, message: str = "") -> None:
    """Assert that two values are equal

    Args:
        thing1: First value to compare
        thing2: Second value to compare
        message: Optional error message

    Raises:
        AssertionError: If values are not equal
    """
    if thing1 != thing2:
        if message:
            raise AssertionError(
                f"{message}\nExpected: {thing2}\nActual: {thing1}"
            )
        else:
            raise AssertionError(f"Expected: {thing2}, Actual: {thing1}")


def assert_not_equal(thing1: Any, thing2: Any, message: str = "") -> None:
    """Assert that two values are not equal

    Args:
        thing1: First value to compare
        thing2: Second value to compare
        message: Optional error message

    Raises:
        AssertionError: If values are equal
    """
    if thing1 == thing2:
        if message:
            raise AssertionError(
                f"{message}\nValues should not be equal: {thing1}"
            )
        else:
            raise AssertionError(f"Values should not be equal: {thing1}")


def assert_greater_than(thing1: Any, thing2: Any, message: str = "") -> None:
    """Assert that thing1 > thing2

    Args:
        thing1: First value
        thing2: Second value
        message: Optional error message

    Raises:
        AssertionError: If thing1 <= thing2
    """
    if thing1 <= thing2:
        if message:
            raise AssertionError(
                f"{message}\n{thing1} should be greater than {thing2}"
            )
        else:
            raise AssertionError(f"{thing1} should be greater than {thing2}")


def assert_greater_than_or_equal(thing1: Any, thing2: Any, message: str = "") -> None:
    """Assert that thing1 >= thing2

    Args:
        thing1: First value
        thing2: Second value
        message: Optional error message

    Raises:
        AssertionError: If thing1 < thing2
    """
    if thing1 < thing2:
        if message:
            raise AssertionError(
                f"{message}\n{thing1} should be >= {thing2}"
            )
        else:
            raise AssertionError(f"{thing1} should be >= {thing2}")


def assert_raises_rpc_error(
    expected_code: Optional[int],
    expected_message: str,
    func: Callable,
    *args,
    **kwargs
) -> None:
    """Assert that RPC call raises expected error

    Args:
        expected_code: Expected RPC error code (or None to skip check)
        expected_message: Expected substring in error message
        func: Function to call
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func

    Raises:
        AssertionError: If error not raised or doesn't match expected
    """
    try:
        func(*args, **kwargs)
        raise AssertionError(f"Expected RPC error was not raised")
    except Exception as e:
        error_message = str(e)

        # Check error message contains expected substring
        if expected_message not in error_message:
            raise AssertionError(
                f"Expected error message containing '{expected_message}', "
                f"got: {error_message}"
            )

        # Check error code if specified
        if expected_code is not None:
            # Try to extract error code from exception
            if hasattr(e, 'code'):
                actual_code = e.code
                if actual_code != expected_code:
                    raise AssertionError(
                        f"Expected error code {expected_code}, "
                        f"got {actual_code}"
                    )


def assert_is_hex_string(string: str) -> None:
    """Assert that string is valid hexadecimal

    Args:
        string: String to check

    Raises:
        AssertionError: If string is not valid hex
    """
    try:
        int(string, 16)
    except ValueError:
        raise AssertionError(f"'{string}' is not a valid hex string")


def assert_is_hash_string(string: str, length: int = 64) -> None:
    """Assert that string is valid hash (hex string of specific length)

    Args:
        string: String to check
        length: Expected length (default 64 for SHA-256)

    Raises:
        AssertionError: If string is not valid hash
    """
    assert_is_hex_string(string)
    if len(string) != length:
        raise AssertionError(
            f"Expected hash length {length}, got {len(string)}"
        )


def wait_until(
    predicate: Callable[[], bool],
    timeout: float = 10.0,
    interval: float = 0.1,
    label: str = "condition"
) -> None:
    """Wait until predicate returns True or timeout occurs

    Args:
        predicate: Function that returns bool
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds
        label: Description of condition for error message

    Raises:
        AssertionError: If timeout occurs before predicate returns True
    """
    start_time = time.time()

    while True:
        if predicate():
            return

        if time.time() - start_time >= timeout:
            raise AssertionError(
                f"Timeout waiting for {label} after {timeout} seconds"
            )

        time.sleep(interval)


def ensure_for(
    predicate: Callable[[], bool],
    duration: float = 2.0,
    interval: float = 0.1,
    label: str = "condition"
) -> None:
    """Ensure predicate remains True for duration

    Args:
        predicate: Function that returns bool
        duration: Time to check in seconds
        interval: Time between checks in seconds
        label: Description of condition for error message

    Raises:
        AssertionError: If predicate returns False during duration
    """
    start_time = time.time()

    while time.time() - start_time < duration:
        if not predicate():
            elapsed = time.time() - start_time
            raise AssertionError(
                f"{label} failed after {elapsed:.1f} seconds"
            )

        time.sleep(interval)


def satoshi_round(amount: float) -> float:
    """Round float to satoshi precision (8 decimal places)

    Args:
        amount: Amount to round

    Returns:
        Rounded amount with 8 decimal places
    """
    return round(amount, 8)


def hex_str_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes

    Args:
        hex_str: Hexadecimal string

    Returns:
        Bytes representation
    """
    return bytes.fromhex(hex_str)


def bytes_to_hex_str(byte_data: bytes) -> str:
    """Convert bytes to hex string

    Args:
        byte_data: Bytes to convert

    Returns:
        Hexadecimal string
    """
    return byte_data.hex()


def str_to_b64str(string: str) -> str:
    """Convert string to base64

    Args:
        string: String to convert

    Returns:
        Base64 encoded string
    """
    import base64
    return base64.b64encode(string.encode()).decode()


def format_value(value: Any) -> str:
    """Format value for display in test output

    Args:
        value: Value to format

    Returns:
        Formatted string representation
    """
    if isinstance(value, dict):
        return json.dumps(value, indent=2)
    elif isinstance(value, (list, tuple)):
        return json.dumps(value)
    else:
        return str(value)


class Decimal:
    """Simple decimal implementation for precise amount handling"""

    def __init__(self, value):
        if isinstance(value, str):
            self.value = float(value)
        else:
            self.value = float(value)

    def __eq__(self, other):
        if isinstance(other, Decimal):
            return satoshi_round(self.value) == satoshi_round(other.value)
        return satoshi_round(self.value) == satoshi_round(float(other))

    def __lt__(self, other):
        if isinstance(other, Decimal):
            return self.value < other.value
        return self.value < float(other)

    def __le__(self, other):
        return self == other or self < other

    def __gt__(self, other):
        if isinstance(other, Decimal):
            return self.value > other.value
        return self.value > float(other)

    def __ge__(self, other):
        return self == other or self > other

    def __add__(self, other):
        if isinstance(other, Decimal):
            return Decimal(self.value + other.value)
        return Decimal(self.value + float(other))

    def __sub__(self, other):
        if isinstance(other, Decimal):
            return Decimal(self.value - other.value)
        return Decimal(self.value - float(other))

    def __mul__(self, other):
        if isinstance(other, Decimal):
            return Decimal(self.value * other.value)
        return Decimal(self.value * float(other))

    def __truediv__(self, other):
        if isinstance(other, Decimal):
            return Decimal(self.value / other.value)
        return Decimal(self.value / float(other))

    def __abs__(self):
        return Decimal(abs(self.value))

    def __neg__(self):
        return Decimal(-self.value)

    def __str__(self):
        return f"{self.value:.8f}"

    def __repr__(self):
        return f"Decimal('{self.value:.8f}')"

    def __float__(self):
        return self.value


# Constants
COIN = 100000000  # 1 DIL in satoshis
CENT = 1000000    # 0.01 DIL in satoshis
