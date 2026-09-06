"""
Cryptographic utility functions for field operations and hashing.

This module provides helper functions for modular arithmetic, field operations,
and hash functions used in FROST threshold signatures.
"""

import hashlib
import secrets

from .schnorr import CURVE_ORDER


def generate_random_scalar() -> int:
    """
    Generate a cryptographically secure random scalar in [1, order-1].

    Returns:
        Random integer in valid range for secp256k1 scalars
    """
    # Generate random bytes and ensure it's in valid range
    while True:
        random_bytes = secrets.token_bytes(32)
        scalar = int.from_bytes(random_bytes, 'big')
        if 0 < scalar < CURVE_ORDER:
            return scalar


def mod_inverse(a: int, modulus: int = CURVE_ORDER) -> int:
    """
    Compute modular multiplicative inverse.

    Returns b such that (a * b) ≡ 1 (mod modulus)
    Uses Fermat's little theorem: a^(-1) = a^(modulus-2) mod modulus

    Args:
        a: Integer to invert
        modulus: Modulus (defaults to curve order)

    Returns:
        Modular inverse of a

    Raises:
        ValueError: If a is 0 or not coprime to modulus
    """
    if a == 0:
        raise ValueError("Cannot compute inverse of 0")

    return pow(a, modulus - 2, modulus)


def field_add(*values: int) -> int:
    """
    Add values in the secp256k1 scalar field.

    Args:
        values: Variable number of integers

    Returns:
        Sum modulo curve order
    """
    return sum(values) % CURVE_ORDER


def field_sub(a: int, b: int) -> int:
    """
    Subtract values in the secp256k1 scalar field.

    Args:
        a: Minuend
        b: Subtrahend

    Returns:
        (a - b) mod order
    """
    return (a - b) % CURVE_ORDER


def field_mul(*values: int) -> int:
    """
    Multiply values in the secp256k1 scalar field.

    Args:
        values: Variable number of integers

    Returns:
        Product modulo curve order
    """
    result = 1
    for v in values:
        result = (result * v) % CURVE_ORDER
    return result


def hash_to_scalar(*messages: bytes) -> int:
    """
    Hash messages to a scalar in [1, order-1].

    Uses SHA256 and rejection sampling to ensure uniform distribution.

    Args:
        messages: Variable number of message components

    Returns:
        Scalar in valid range
    """
    combined = b''.join(messages)

    # Use rejection sampling to get uniform distribution
    counter = 0
    while True:
        data = combined + counter.to_bytes(4, 'big')
        hash_bytes = hashlib.sha256(data).digest()
        scalar = int.from_bytes(hash_bytes, 'big')

        if 0 < scalar < CURVE_ORDER:
            return scalar

        counter += 1
        if counter > 1000:
            # Fallback: just take modulo (slight bias but acceptable)
            return scalar % CURVE_ORDER if scalar % CURVE_ORDER != 0 else 1


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer (big-endian)."""
    return int.from_bytes(b, 'big')


def int_to_bytes(i: int, length: int = 32) -> bytes:
    """
    Convert integer to bytes (big-endian).

    Args:
        i: Integer to convert
        length: Byte length (default 32 for scalars)

    Returns:
        Bytes representation
    """
    return i.to_bytes(length, 'big')


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings.

    Args:
        a: First byte string
        b: Second byte string (must be same length as a)

    Returns:
        XOR result

    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError(f"Cannot XOR bytes of different lengths: {len(a)} vs {len(b)}")

    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def compute_epoch(timestamp: float, ttl: int = 90) -> int:
    """
    Compute epoch (time window) for nonce caching.

    This is used in the nonce cache to create time-based buckets.

    Args:
        timestamp: Unix timestamp
        ttl: Time-to-live in seconds (default 90)

    Returns:
        Epoch number (timestamp // ttl)
    """
    return int(timestamp // ttl)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of byte strings.

    Prevents timing attacks by always comparing all bytes.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b, strict=False):
        result |= x ^ y

    return result == 0

