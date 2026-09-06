"""Nonce model - per-signer random value used in FROST protocol."""

import time

from pydantic import BaseModel, Field, field_serializer, field_validator


class Nonce(BaseModel):
    """
    Nonce commitment pair for FROST protocol.

    Each signer generates a nonce pair (d, e) and commitment pair (D, E):
    - D = d·G (first commitment)
    - E = e·G (second commitment)

    Later, after computing binding factor ρᵢ:
    - Rᵢ = Dᵢ + ρᵢ·Eᵢ
    - kᵢ = dᵢ + ρᵢ·eᵢ

    PERFORMANCE NOTE: For high-throughput scenarios, commitment pairs are cached
    by (client_id, epoch) within the session optimization TTL window.
    """

    signer_id: int = Field(..., ge=1, le=9, description="Which signer generated this nonce pair")

    d: int = Field(..., gt=0, description="First nonce scalar")

    e: int = Field(..., gt=0, description="Second nonce scalar")

    D: bytes = Field(
        ...,
        min_length=33,
        max_length=33,
        description="First commitment D = d·G (33 bytes compressed point)"
    )

    E: bytes = Field(
        ...,
        min_length=33,
        max_length=33,
        description="Second commitment E = e·G (33 bytes compressed point)"
    )

    created_at: float = Field(
        default_factory=time.time,
        description="Unix timestamp of generation"
    )

    epoch: int = Field(..., description="Time window bucket (timestamp // TTL_SECONDS)")

    @field_serializer('D', 'E')
    def serialize_commitment(self, value: bytes) -> str:
        """Serialize commitment points as hex strings."""
        return value.hex()

    @field_validator('d', 'e')
    @classmethod
    def validate_positive_scalar(cls, v: int) -> int:
        """Ensure nonce scalars are positive."""
        if v <= 0:
            raise ValueError("Nonce scalars must be positive")
        return v

    @property
    def D_point(self):
        """
        Parse D as EC point.

        Returns coincurve PublicKey object for first commitment.
        """
        from coincurve import PublicKey
        return PublicKey(self.D)

    @property
    def E_point(self):
        """
        Parse E as EC point.

        Returns coincurve PublicKey object for second commitment.
        """
        from coincurve import PublicKey
        return PublicKey(self.E)

    class Config:
        """Pydantic model configuration."""
        json_encoders = {
            bytes: lambda v: v.hex()
        }

