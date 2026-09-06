"""
BIP-340 Schnorr signature operations using libsecp256k1 (coincurve).

This module wraps coincurve for BIP-340 Schnorr signatures over secp256k1.
"""

import hashlib

from coincurve import PrivateKey, PublicKey

# secp256k1 curve order
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# secp256k1 field prime
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a random keypair for secp256k1.

    Returns:
        Tuple of (private_key, public_key) as bytes
        - private_key: 32 bytes
        - public_key: 33 bytes (compressed SEC format)
    """
    privkey = PrivateKey()
    pubkey = privkey.public_key

    return privkey.secret, pubkey.format(compressed=True)


def pubkey_from_privkey(privkey_bytes: bytes) -> bytes:
    """
    Derive public key from private key.

    Args:
        privkey_bytes: 32-byte private key

    Returns:
        33-byte compressed public key
    """
    privkey = PrivateKey(privkey_bytes)
    return privkey.public_key.format(compressed=True)


def point_add(point1: bytes, point2: bytes) -> bytes:
    """
    Add two elliptic curve points.

    Args:
        point1: 33-byte compressed point
        point2: 33-byte compressed point

    Returns:
        33-byte compressed sum point
    """
    pub1 = PublicKey(point1)
    pub2 = PublicKey(point2)

    # Combine public keys (point addition)
    combined = PublicKey.combine_keys([pub1, pub2])
    return combined.format(compressed=True)


def point_mul(scalar: int, point: bytes | None = None) -> bytes:
    """
    Multiply a point by a scalar, or compute scalar * G if point is None.

    Args:
        scalar: Integer scalar
        point: Optional 33-byte compressed point (if None, uses generator G)

    Returns:
        33-byte compressed result point
    """
    # Ensure scalar is in valid range
    scalar = scalar % CURVE_ORDER

    if scalar == 0:
        raise ValueError("Scalar cannot be zero")

    # Convert scalar to 32-byte private key format
    scalar_bytes = scalar.to_bytes(32, 'big')

    if point is None:
        # scalar * G (generator point)
        privkey = PrivateKey(scalar_bytes)
        return privkey.public_key.format(compressed=True)
    else:
        # scalar * point
        pubkey = PublicKey(point)
        # Use tweak_mul for scalar multiplication
        result = pubkey.multiply(scalar_bytes)
        return result.format(compressed=True)


def tagged_hash(tag: str, *messages: bytes) -> bytes:
    """
    BIP-340 tagged hash construction.

    tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)

    Args:
        tag: Tag string (e.g., "BIP0340/challenge")
        messages: Variable number of message components to hash

    Returns:
        32-byte hash digest
    """
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + b''.join(messages)).digest()


def challenge_hash(R: bytes, pubkey: bytes, message: bytes) -> int:
    """
    Compute BIP-340 challenge hash.

    c = H(R || PK || m) where H is tagged hash with "BIP0340/challenge"

    Args:
        R: 33-byte compressed nonce commitment
        pubkey: 33-byte compressed public key
        message: Message bytes

    Returns:
        Challenge scalar as integer
    """
    # For BIP-340, we need x-only public keys (32 bytes)
    # Extract x-coordinate from compressed format
    R_x = PublicKey(R).format(compressed=False)[1:33]  # Skip 0x04 prefix, take x
    pk_x = PublicKey(pubkey).format(compressed=False)[1:33]

    challenge_bytes = tagged_hash("BIP0340/challenge", R_x, pk_x, message)
    return int.from_bytes(challenge_bytes, 'big') % CURVE_ORDER


def sign_schnorr(privkey_bytes: bytes, message: bytes, nonce: int | None = None) -> tuple[bytes, int]:
    """
    Create a Schnorr signature.

    Standard Schnorr signature: (R, s) where s = k + c*x
    - k: nonce scalar
    - c: challenge = H(R || PK || m)
    - x: private key

    Args:
        privkey_bytes: 32-byte private key
        message: Message to sign
        nonce: Optional nonce scalar (if None, generate randomly)

    Returns:
        Tuple of (R, s) where R is 33-byte compressed point, s is integer
    """
    privkey = PrivateKey(privkey_bytes)
    pubkey = privkey.public_key.format(compressed=True)

    x = int.from_bytes(privkey_bytes, 'big')

    # Generate or use provided nonce
    if nonce is None:
        nonce_key = PrivateKey()
        k = int.from_bytes(nonce_key.secret, 'big')
    else:
        k = nonce % CURVE_ORDER

    # R = k * G
    R = point_mul(k)

    # Compute challenge
    c = challenge_hash(R, pubkey, message)

    # Compute signature scalar: s = k + c*x (mod order)
    s = (k + c * x) % CURVE_ORDER

    return R, s


def verify_schnorr(pubkey: bytes, message: bytes, R: bytes, s: int) -> bool:
    """
    Verify a Schnorr signature.

    Verification equation: s*G == R + c*PK
    where c = H(R || PK || m)

    Args:
        pubkey: 33-byte compressed public key
        message: Message that was signed
        R: 33-byte compressed nonce commitment
        s: Signature scalar

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Compute challenge
        c = challenge_hash(R, pubkey, message)

        # Compute left side: s*G
        left = point_mul(s)

        # Compute right side: R + c*PK
        c_pk = point_mul(c, pubkey)
        right = point_add(R, c_pk)

        # Check if they're equal
        return left == right
    except Exception:
        return False


def aggregate_points(points: list[bytes]) -> bytes:
    """
    Aggregate multiple elliptic curve points.

    Args:
        points: List of 33-byte compressed points

    Returns:
        33-byte compressed aggregate point
    """
    if not points:
        raise ValueError("Cannot aggregate empty list of points")

    pubkeys = [PublicKey(p) for p in points]
    combined = PublicKey.combine_keys(pubkeys)
    return combined.format(compressed=True)

