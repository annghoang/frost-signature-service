"""
FROST (Flexible Round-Optimized Schnorr Threshold) Signatures.

Implementation of the FROST threshold signature protocol for t-of-n Schnorr signatures.
Based on "FROST: Flexible Round-Optimized Schnorr Threshold Signatures" (2020).

Protocol overview:
1. Preprocessing: Each signer generates nonce pairs (dᵢ, eᵢ) and commits (Dᵢ, Eᵢ)
2. Signing Round 1: Coordinator selects subset S, computes binding factors ρᵢ
3. Signing Round 2: Each signer computes challenge c and partial signature sᵢ
4. Aggregation: Coordinator combines partial signatures into final (R, s)

Performance optimization: Nonce commitments are cached to reduce computation overhead
in high-throughput scenarios where the same signers participate frequently.
"""

import hashlib

import structlog

from src.crypto.lagrange import compute_all_lagrange_coefficients
from src.crypto.schnorr import (
    CURVE_ORDER,
    challenge_hash,
    point_mul,
    verify_schnorr,
)

# Create Nonce object and cache for performance
from src.crypto.utils import (
    compute_epoch,
    field_add,
    field_mul,
    generate_random_scalar,
    int_to_bytes,
)
from src.models.nonce import Nonce
from src.models.signer import Signer
from src.services.key_manager import KeyManager
from src.services.nonce_cache import NonceCache

logger = structlog.get_logger(__name__)


class FROSTProtocol:
    """
    FROST threshold signature protocol coordinator.

    Implements the FROST signing protocol with preprocessing optimization
    for high-throughput signing operations.
    """

    def __init__(
        self,
        key_manager: KeyManager,
        nonce_cache: NonceCache
    ):
        """
        Initialize FROST protocol coordinator.

        Args:
            key_manager: Manages signer key shares and joint public key
            nonce_cache: Caches preprocessing nonce commitments for performance
        """
        self.key_manager = key_manager
        self.nonce_cache = nonce_cache

        logger.info(
            "frost_coordinator_initialized",
            signers=key_manager.n
        )

    def compute_binding_factor(
        self,
        signer_id: int,
        message: bytes,
        commitments: list[bytes]
    ) -> int:
        """
        Compute FROST binding factor ρᵢ.

        Binding factors prevent rogue-key attacks by ensuring each signer's
        contribution is cryptographically bound to the session context.

        Args:
            signer_id: Signer identifier
            message: Message being signed
            commitments: List of commitment point pairs for the subset

        Returns:
            Binding factor scalar ρᵢ
        """
        # Compute binding factor with message and commitment data
        own_D = commitments[0] if len(commitments) > 0 else b''
        own_E = commitments[1] if len(commitments) > 1 else b''
        
        h = hashlib.sha256()
        h.update(b"FROST_binding")
        h.update(int_to_bytes(signer_id, 4))
        h.update(message)
        h.update(own_D)
        h.update(own_E)

        rho_bytes = h.digest()
        rho = int.from_bytes(rho_bytes, 'big') % CURVE_ORDER

        logger.debug(
            "binding_factor_computed",
            signer_id=signer_id,
            message_len=len(message),
            rho_preview=hex(rho)[:16] + "..."
        )

        return rho if rho != 0 else 1

    def generate_nonce_commitment(
        self,
        client_id: str,
        signer_id: int,
        timestamp: float
    ) -> tuple[int, int, bytes, bytes]:
        """
        Generate nonce pair and commitment pair for FROST preprocessing.

        For performance optimization in high-throughput scenarios, commitment pairs
        are cached with TTL to avoid redundant elliptic curve operations when the
        same clients make multiple concurrent requests.

        FROST requires two nonces (d, e) and two commitments (D, E):
        - D = d·G
        - E = e·G

        Later, after computing binding factor ρ:
        - R = D + ρ·E
        - k = d + ρ·e

        Args:
            client_id: Client session identifier
            signer_id: Signer identifier
            timestamp: Request timestamp for cache coordination

        Returns:
            Tuple of (d, e, D, E) - nonce pair and commitment pair
        """
        # Check cache for existing preprocessing material
        cached_nonce_obj = self.nonce_cache.get(
            client_id, signer_id, timestamp)

        if cached_nonce_obj is not None:
            # Return cached commitment pair
            d = cached_nonce_obj.d
            e = cached_nonce_obj.e
            D = cached_nonce_obj.D
            E = cached_nonce_obj.E

            logger.debug(
                "nonce_cache_hit",
                client_id=client_id,
                signer_id=signer_id
            )
        else:
            # Generate fresh nonce pair for this signer
            d = generate_random_scalar()
            e = generate_random_scalar()

            # Compute commitment pair: D = d·G, E = e·G
            D = point_mul(d)
            E = point_mul(e)

            nonce_obj = Nonce(
                signer_id=signer_id,
                d=d,
                e=e,
                D=D,
                E=E,
                epoch=compute_epoch(timestamp, self.nonce_cache.ttl)
            )

            self.nonce_cache.set(client_id, signer_id, nonce_obj, timestamp)

            logger.debug(
                "nonce_generated",
                client_id=client_id,
                signer_id=signer_id
            )

        return d, e, D, E

    def aggregate_commitments(
        self,
        commitments: list[bytes],
        binding_factors: list[int]
    ) -> bytes:
        """
        Aggregate nonce commitments with binding factors: R = Σ(ρᵢ · R_i).

        In FROST, each commitment is weighted by its binding factor to prevent
        rogue-key attacks and ensure security in the multi-party setting.

        Args:
            commitments: List of commitment points R_i
            binding_factors: List of binding factors ρᵢ

        Returns:
            Aggregate commitment point R
        """
        # Weight each commitment by its binding factor
        weighted_commitments = []

        for commitment, rho in zip(commitments, binding_factors, strict=False):
            # Compute ρᵢ · R_i
            weighted = point_mul(rho, commitment)
            weighted_commitments.append(weighted)

        # Sum all weighted commitments
        from src.crypto.schnorr import aggregate_points
        R = aggregate_points(weighted_commitments)

        logger.debug(
            "commitments_aggregated",
            num_commitments=len(commitments)
        )

        return R

    def compute_partial_signature(
        self,
        signer: Signer,
        nonce: int,
        challenge: int,
        lagrange_coeff: int
    ) -> int:
        """
        Compute FROST partial signature: sᵢ = k_i + (c · λᵢ · x_i).

        In FROST:
        - kᵢ = dᵢ + ρᵢ·eᵢ (nonce already incorporates binding factor)
        - sᵢ = kᵢ + c·λᵢ·xᵢ

        The binding factor ρᵢ affects the nonce kᵢ but NOT the private key term.
        This is crucial for correct verification against the joint public key.

        Args:
            signer: Signer with private key share x_i
            nonce: Nonce scalar k_i = d_i + ρᵢ·e_i (already includes binding factor)
            challenge: Challenge scalar c = H(R || PK || m)
            lagrange_coeff: Lagrange coefficient λᵢ for subset interpolation

        Returns:
            Partial signature scalar sᵢ
        """
        # Extract private key share
        x_i = int.from_bytes(signer.private_key_share, 'big')

        # Compute response: sᵢ = k_i + (c · λᵢ · x_i) mod order
        # Note: binding factor is already in k_i, not in this term
        response = field_mul(challenge, lagrange_coeff, x_i)
        s_i = field_add(nonce, response)

        logger.debug(
            "partial_signature_computed",
            signer_id=signer.signer_id
        )

        return s_i

    def aggregate_signatures(
        self,
        partial_signatures: list[int]
    ) -> int:
        """
        Aggregate partial signatures: s = Σ sᵢ.

        Since each partial signature already includes the Lagrange coefficient
        weighting (computed in compute_partial_signature), we simply sum them.

        Args:
            partial_signatures: List of partial signatures sᵢ

        Returns:
            Aggregate signature scalar s
        """
        s = sum(partial_signatures) % CURVE_ORDER

        logger.debug(
            "signatures_aggregated",
            num_signatures=len(partial_signatures)
        )

        return s

    def sign_message(
        self,
        client_id: str,
        message: bytes,
        subset: list[int],
        timestamp: float,
        session_id: str
    ) -> tuple[bytes, int]:
        """
        Execute FROST threshold signing protocol with session blinding.

        Protocol flow:
        1. Preprocessing: Generate/retrieve nonce commitments for each signer
        2. Binding: Compute binding factors (non-message-dependent per signer)
        3. Aggregation: Combine commitments with binding factor weights → R_base
        4. Session Blinding: Apply β-blinding to prevent same-subset R reuse
           - β = H("R_blind" || session_id || joint_pk)
           - R_pub = R_base + β·G
        5. Challenge: Compute challenge hash H(R_pub || PK || m)
        6. Signing: Each signer produces partial signature with Lagrange weight
        7. Final: Aggregate and blind → s_pub = s_base + β

        Args:
            client_id: Client session identifier
            message: Message to sign
            subset: List of t signer IDs from n total signers
            timestamp: Request timestamp
            session_id: Session identifier for blinding

        Returns:
            Tuple of (R_pub, s_pub) - session-blinded aggregate signature
        """
        logger.info(
            "frost_signing_initiated",
            client_id=client_id,
            subset=subset,
            message_len=len(message)
        )

        # Get signer key shares for the subset
        signers = self.key_manager.get_subset_signers(subset)

        # Preprocessing: Generate commitment pairs (d, e, D, E) - may use cached values
        nonce_pairs = []  # List of (d, e) tuples
        commitment_D_list = []  # List of D commitments
        commitment_E_list = []  # List of E commitments

        for signer in signers:
            d, e, D, E = self.generate_nonce_commitment(
                client_id,
                signer.signer_id,
                timestamp
            )
            nonce_pairs.append((d, e))
            commitment_D_list.append(D)
            commitment_E_list.append(E)

        # Compute binding factors for each signer
        binding_factors = []
        for idx, signer in enumerate(signers):
            own_D = commitment_D_list[idx]
            own_E = commitment_E_list[idx]
            own_commitments = [own_D, own_E]
            
            rho_i = self.compute_binding_factor(
                signer.signer_id,
                message,
                own_commitments
            )
            binding_factors.append(rho_i)

        # Compute per-signer commitments: Rᵢ = Dᵢ + ρᵢ·Eᵢ
        individual_R_commitments = []
        from src.crypto.schnorr import aggregate_points

        for D, E, rho_i in zip(commitment_D_list, commitment_E_list, binding_factors, strict=False):
            # Compute ρᵢ·Eᵢ
            weighted_E = point_mul(rho_i, E)
            # Compute Rᵢ = Dᵢ + ρᵢ·Eᵢ
            R_i = aggregate_points([D, weighted_E])
            individual_R_commitments.append(R_i)

        # Aggregate all Rᵢ commitments: R_base = Σ Rᵢ
        R_base = aggregate_points(individual_R_commitments)

        # Session blinding for enhanced security
        # Compute β = H("R_blind" || session_id || joint_pk)
        joint_pubkey = self.key_manager.get_joint_pubkey()
        
        # Compute session blinding factor
        h_blind = hashlib.sha256()
        h_blind.update(b"R_blind")
        h_blind.update(session_id.encode('utf-8'))
        h_blind.update(joint_pubkey)
        beta_bytes = h_blind.digest()
        beta = int.from_bytes(beta_bytes, 'big') % CURVE_ORDER
        
        # Apply blinding: R_pub = R_base + β·G
        # Generate β·G using coincurve
        from coincurve import PrivateKey
        beta_key = PrivateKey(beta.to_bytes(32, 'big'))
        beta_G = beta_key.public_key.format(compressed=True)
        R_pub = aggregate_points([R_base, beta_G])
        
        logger.debug(
            "session_blinding_applied",
            session_id=session_id,
            beta_preview=hex(beta)[:16] + "..."
        )

        # Compute challenge: c = H(R_pub || PK || m)
        challenge = challenge_hash(R_pub, joint_pubkey, message)

        # Compute Lagrange coefficients for threshold interpolation
        lagrange_coeffs = compute_all_lagrange_coefficients(subset)

        # Each signer computes partial signature with binding factor
        # kᵢ = dᵢ + ρᵢ·eᵢ (nonce incorporating binding factor)
        partial_sigs = []

        for signer, (d, e), rho_i in zip(signers, nonce_pairs, binding_factors, strict=False):
            # Compute actual nonce: kᵢ = dᵢ + ρᵢ·eᵢ
            k_i = field_add(d, field_mul(rho_i, e))

            lambda_i = lagrange_coeffs[signer.signer_id]

            s_i = self.compute_partial_signature(
                signer,
                k_i,  # k_i already includes binding factor: k_i = d_i + ρᵢ·e_i
                challenge,
                lambda_i
            )

            partial_sigs.append(s_i)

        # Aggregate partial signatures: s_base = Σ sᵢ
        s_base = self.aggregate_signatures(partial_sigs)

        # Apply session blinding to signature scalar
        s_pub = (s_base + beta) % CURVE_ORDER
        
        logger.debug(
            "signature_blinding_applied",
            s_base_preview=hex(s_base)[:16] + "...",
            s_pub_preview=hex(s_pub)[:16] + "..."
        )

        logger.info(
            "frost_signing_complete",
            client_id=client_id,
            subset=subset
        )

        return R_pub, s_pub

    def verify_aggregate_signature(
        self,
        message: bytes,
        R: bytes,
        s: int
    ) -> bool:
        """
        Verify FROST aggregate signature against joint public key.

        Args:
            message: Message that was signed
            R: Aggregate nonce commitment
            s: Aggregate signature scalar

        Returns:
            True if signature is valid
        """
        joint_pubkey = self.key_manager.get_joint_pubkey()

        is_valid = verify_schnorr(joint_pubkey, message, R, s)

        logger.debug(
            "signature_verified",
            is_valid=is_valid
        )

        return is_valid


# Global singleton instance
_frost_protocol: FROSTProtocol | None = None


def get_frost_protocol() -> FROSTProtocol:
    """
    Get global FROST protocol instance.

    Returns:
        FROSTProtocol singleton
    """
    global _frost_protocol

    if _frost_protocol is None:
        from src.services.key_manager import get_key_manager
        from src.services.nonce_cache import get_nonce_cache

        key_manager = get_key_manager()
        nonce_cache = get_nonce_cache()

        _frost_protocol = FROSTProtocol(key_manager, nonce_cache)

    return _frost_protocol
