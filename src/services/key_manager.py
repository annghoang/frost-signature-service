"""
Key management service for FROST threshold signing.

Manages:
1. Per-signer key shares (private keys for threshold scheme)
2. Joint public key (aggregate of all signers)
3. System configuration message keypair (for privileged operations)
"""

import structlog

from src.api.exceptions import InvalidSignerIDError, KeyManagerError
from src.crypto.schnorr import (
    generate_keypair,
)
from src.models.signer import Signer

logger = structlog.get_logger(__name__)


class KeyManager:
    """
    Manages cryptographic keys for FROST threshold signing.

    In a real FROST implementation, key shares would be derived through a DKG
    (Distributed Key Generation) protocol. For this educational implementation,
    we simplify by generating independent key shares and computing the joint
    public key as their aggregate.

    This demonstrates threshold signature concepts while maintaining
    operational simplicity for the approval service.
    """

    def __init__(self, n: int = 9):
        """
        Initialize key manager with n signers.

        Args:
            n: Number of signers (default 9)
        """
        self.n = n

        # Generate signers with key shares (stores joint_privkey internally)
        self._signers: dict[int, Signer] = {}
        self._joint_privkey: int | None = None  # Will be set by _initialize_signers
        self._initialize_signers()

        # Compute joint public key from joint private key
        self._joint_pubkey = self._compute_joint_pubkey()

        # Generate release flag keypair (the target)
        self._release_flag_privkey, self._release_flag_pubkey = generate_keypair()

        logger.info(
            "key_manager_initialized",
            n=n,
            joint_pubkey_hex=self._joint_pubkey.hex(),
            release_flag_pubkey_hex=self._release_flag_pubkey.hex()
        )

    def _initialize_signers(self) -> None:
        """
        Generate threshold key shares using Shamir's Secret Sharing (simplified).

        Instead of full DKG, we:
        1. Generate a random secret x (the joint private key)
        2. Create a polynomial f(i) of degree t-1 where f(0) = x
        3. Compute shares: x_i = f(i) for each signer i in [1..9]
        4. Derive public key shares: X_i = x_i·G

        Signer IDs are 1-9 (not 0-8 to avoid Lagrange coefficient issues).

        With this approach, any t=5 signers can reconstruct x using Lagrange interpolation:
        x = Σ(λ_i · x_i) where λ_i are Lagrange coefficients

        And the joint public key satisfies:
        PK = x·G = Σ(λ_i · X_i) for any valid subset
        """
        import secrets

        from src.crypto.schnorr import CURVE_ORDER

        # Step 1: Generate random secret x (joint private key)
        joint_privkey = secrets.randbelow(CURVE_ORDER - 1) + 1
        self._joint_privkey = joint_privkey  # Store for computing joint public key

        # Step 2: Generate polynomial coefficients for degree t-1 = 4
        # f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + a_4*x^4
        # where a_0 = joint_privkey (the secret)
        coefficients = [joint_privkey]
        for _ in range(4):  # t-1 = 4 additional coefficients
            coefficients.append(secrets.randbelow(CURVE_ORDER - 1) + 1)

        # Step 3: Compute shares for each signer: x_i = f(i)
        for signer_id in range(1, self.n + 1):
            # Evaluate polynomial at i: f(i) = Σ(a_j * i^j)
            share = 0
            for j, coeff in enumerate(coefficients):
                term = (coeff * pow(signer_id, j, CURVE_ORDER)) % CURVE_ORDER
                share = (share + term) % CURVE_ORDER

            # Derive public key share: X_i = x_i·G
            from coincurve import PrivateKey
            share_bytes = share.to_bytes(32, 'big')
            privkey_obj = PrivateKey(share_bytes)
            pubkey = privkey_obj.public_key.format()

            signer = Signer(
                signer_id=signer_id,
                private_key_share=share_bytes,
                public_key_share=pubkey
            )

            self._signers[signer_id] = signer

            logger.debug(
                "signer_initialized",
                signer_id=signer_id,
                pubkey_hex=pubkey.hex()
            )

    def _compute_joint_pubkey(self) -> bytes:
        """
        Compute joint public key from the joint private key.

        With Shamir's secret sharing, the joint private key is f(0),
        and the joint public key is PK = f(0)·G.

        This is equivalent to Σ(λ_i·X_i) for any valid t-of-n subset,
        which is the key property of threshold signatures.

        Returns:
            33-byte compressed joint public key

        Raises:
            KeyManagerError: If joint private key is not initialized
        """
        if self._joint_privkey is None:
            logger.error("joint_privkey_not_initialized")
            raise KeyManagerError(
                message="Joint private key not initialized",
                details={"operation": "get_joint_pubkey"}
            )

        from coincurve import PrivateKey
        privkey_bytes = self._joint_privkey.to_bytes(32, 'big')
        privkey_obj = PrivateKey(privkey_bytes)
        return privkey_obj.public_key.format()

    def get_signer(self, signer_id: int) -> Signer:
        """
        Get signer by ID.

        Args:
            signer_id: Signer ID (1-9)

        Returns:
            Signer model

        Raises:
            InvalidSignerIDError: If signer_id is invalid
        """
        if signer_id not in self._signers:
            logger.warning("invalid_signer_id_requested", signer_id=signer_id)
            raise InvalidSignerIDError(signer_id=signer_id, valid_range="1-9")

        return self._signers[signer_id]

    def get_all_signers(self) -> list[Signer]:
        """
        Get all signers.

        Returns:
            List of all Signer models (sorted by signer_id)
        """
        return [self._signers[i] for i in sorted(self._signers.keys())]

    def get_subset_signers(self, subset: list[int]) -> list[Signer]:
        """
        Get signers for a specific subset.

        Args:
            subset: List of signer IDs

        Returns:
            List of Signer models in subset order

        Raises:
            ValueError: If any signer_id is invalid
        """
        return [self.get_signer(signer_id) for signer_id in subset]

    def get_joint_pubkey(self) -> bytes:
        """
        Get joint public key.

        Returns:
            33-byte compressed joint public key
        """
        return self._joint_pubkey

    def get_joint_pubkey_hex(self) -> str:
        """
        Get joint public key as hex string.

        Returns:
            Hex-encoded joint public key
        """
        return self._joint_pubkey.hex()

    def get_release_flag_pubkey(self) -> bytes:
        """
        Get release flag public key (the target).

        Returns:
            33-byte compressed public key
        """
        return self._release_flag_pubkey

    def get_release_flag_pubkey_hex(self) -> str:
        """
        Get release flag public key as hex string.

        Returns:
            Hex-encoded public key
        """
        return self._release_flag_pubkey.hex()

    def get_release_flag_privkey(self) -> bytes:
        """
        Get release flag private key (for verification in tests).

        **DO NOT expose this in the API!**

        Returns:
            32-byte private key
        """
        return self._release_flag_privkey

    def is_release_flag_message(self, message: str) -> bool:
        """
        Check if a message is the release flag statement.

        Args:
            message: Message string

        Returns:
            True if message matches release flag pattern
        """
        # Release flag messages must start with "RELEASE-FLAG:"
        return message.startswith("RELEASE-FLAG:")

    def get_signer_info(self, signer_id: int) -> dict:
        """
        Get public info for a signer (no private key).

        Args:
            signer_id: Signer ID

        Returns:
            Dictionary with signer info
        """
        signer = self.get_signer(signer_id)

        return {
            "signer_id": signer.signer_id,
            "pubkey_hex": signer.public_key_share.hex(),
            "last_active": signer.last_active_time.isoformat(),
        }

    def get_system_info(self) -> dict:
        """
        Get public system information.

        Returns:
            Dictionary with system cryptographic parameters
        """
        return {
            "n": self.n,
            "signer_ids": list(range(1, self.n + 1)),
            "joint_pubkey_hex": self.get_joint_pubkey_hex(),
            "release_flag_pubkey_hex": self.get_release_flag_pubkey_hex(),
        }


# Global singleton instance
_key_manager: 'KeyManager | None' = None


def get_key_manager() -> KeyManager:
    """
    Get global key manager instance.

    Returns:
        KeyManager singleton
    """
    global _key_manager
    if _key_manager is None:
        _key_manager = KeyManager(n=9)
    return _key_manager



