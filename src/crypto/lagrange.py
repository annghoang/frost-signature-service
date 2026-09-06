"""
Lagrange coefficient computation for FROST threshold signatures.

Lagrange interpolation coefficients are used to weight each signer's contribution
in threshold signature schemes.
"""


from .schnorr import CURVE_ORDER


def lagrange_coefficient(i: int, subset: list[int]) -> int:
    """
    Compute Lagrange coefficient λ_i for signer i in subset S.

    Formula: λ_i = Π_{j∈S, j≠i} (j / (j - i)) mod order

    This coefficient weights signer i's contribution such that the threshold
    signature can be verified against the joint public key.

    Args:
        i: Signer ID (must be in subset)
        subset: List of signer IDs participating (must contain i)

    Returns:
        Lagrange coefficient as integer modulo curve order

    Raises:
        ValueError: If i not in subset or subset invalid

    Example:
        For subset [0, 2, 4, 6, 8] and i=0:
        λ_0 = (2/(2-0)) * (4/(4-0)) * (6/(6-0)) * (8/(8-0)) mod order
    """
    if i not in subset:
        raise ValueError(f"Signer {i} not in subset {subset}")

    if len(subset) != len(set(subset)):
        raise ValueError("Subset must contain unique signer IDs")

    # Compute numerator and denominator separately
    numerator = 1
    denominator = 1

    for j in subset:
        if j != i:
            # Numerator: multiply by j
            numerator = (numerator * j) % CURVE_ORDER

            # Denominator: multiply by (j - i)
            diff = (j - i) % CURVE_ORDER
            denominator = (denominator * diff) % CURVE_ORDER

    # Compute modular inverse of denominator
    # Using Fermat's little theorem: a^(-1) = a^(p-2) mod p
    denominator_inv = pow(denominator, CURVE_ORDER - 2, CURVE_ORDER)

    # Result: numerator * denominator^(-1) mod order
    return (numerator * denominator_inv) % CURVE_ORDER


def compute_all_lagrange_coefficients(subset: list[int]) -> dict[int, int]:
    """
    Compute Lagrange coefficients for all signers in subset.

    Args:
        subset: List of signer IDs

    Returns:
        Dictionary mapping signer_id -> lagrange_coefficient

    Example:
        >>> subset = [0, 2, 4, 6, 8]
        >>> coeffs = compute_all_lagrange_coefficients(subset)
        >>> # coeffs = {0: λ_0, 2: λ_2, 4: λ_4, 6: λ_6, 8: λ_8}
    """
    return {i: lagrange_coefficient(i, subset) for i in subset}


def verify_lagrange_sum(subset: list[int]) -> bool:
    """
    Verify that Lagrange coefficients sum to 1 (identity for interpolation).

    This is a mathematical property that should always hold for valid subsets.
    Useful for testing and validation.

    Args:
        subset: List of signer IDs

    Returns:
        True if Σλ_i ≡ 1 (mod order), False otherwise
    """
    coefficients = compute_all_lagrange_coefficients(subset)
    total = sum(coefficients.values()) % CURVE_ORDER

    # The sum should equal 1 (mod order)
    return total == 1


def weighted_sum(values: list[int], subset: list[int]) -> int:
    """
    Compute weighted sum of values using Lagrange coefficients.

    Result: Σ(λ_i * value_i) mod order

    This is used in FROST to aggregate partial signatures:
    s_aggregate = Σ(λ_i * s_i) where s_i are partial signatures

    Args:
        values: List of values to weight (one per signer in subset)
        subset: List of signer IDs (must match length of values)

    Returns:
        Weighted sum modulo curve order

    Raises:
        ValueError: If lengths don't match
    """
    if len(values) != len(subset):
        raise ValueError(f"Values length {len(values)} must match subset length {len(subset)}")

    coefficients = compute_all_lagrange_coefficients(subset)

    result = 0
    for i, value in zip(subset, values, strict=False):
        weighted = (coefficients[i] * value) % CURVE_ORDER
        result = (result + weighted) % CURVE_ORDER

    return result

