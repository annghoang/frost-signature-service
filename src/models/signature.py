"""Aggregate signature model - final output of FROST signing session."""

from datetime import datetime

from pydantic import BaseModel, Field, field_serializer, field_validator


class AggregateSignature(BaseModel):
    """
    Aggregate signature model for FROST threshold signatures.

    Combines contributions from t signers according to FROST protocol with Lagrange weighting.
    Format: (R, s) where R is aggregate nonce, s is aggregate signature scalar.
    """

    R: bytes = Field(
        ...,
        min_length=33,
        max_length=33,
        description="Aggregate nonce commitment (33 bytes compressed point)"
    )

    s: int = Field(..., gt=0, description="Aggregate signature scalar")

    subset: list[int] = Field(
        ...,
        min_length=5,
        max_length=5,
        description="Ordered list of signer IDs that participated"
    )

    message_hash: bytes = Field(
        ...,
        min_length=32,
        max_length=32,
        description="SHA256 hash of signed message (32 bytes)"
    )

    created_at: datetime = Field(
        default_factory=datetime.now,
        description="Signature timestamp"
    )

    @field_validator('subset')
    @classmethod
    def validate_subset(cls, v: list[int]) -> list[int]:
        """
        Validate subset properties.

        - Must contain exactly 5 signers
        - Must be sorted
        - Must contain unique signer IDs
        - All signer IDs must be in range [0, 9)
        """
        if len(v) != 5:
            raise ValueError("Subset must contain exactly 5 signers")

        if v != sorted(v):
            raise ValueError("Subset must be sorted")

        if len(set(v)) != 5:
            raise ValueError("Subset must contain unique signers")

        if not all(1 <= x <= 9 for x in v):
            raise ValueError("Signer IDs must be in range [1, 9]")

        return v

    @field_serializer('R', 'message_hash')
    def serialize_bytes(self, value: bytes) -> str:
        """Serialize bytes as hex string."""
        return value.hex()

    @field_serializer('s')
    def serialize_s(self, value: int) -> str:
        """Serialize scalar as hex string."""
        return hex(value)

    @field_serializer('created_at')
    def serialize_datetime(self, value: datetime) -> str:
        """Serialize datetime as ISO 8601 string."""
        return value.isoformat()

    def to_response(self) -> dict:
        """
        Format signature for API response.

        Returns dictionary with all fields in API-friendly format.
        """
        return {
            "R": self.R.hex(),
            "s": hex(self.s),
            "subset": self.subset,
            "message_hash": self.message_hash.hex(),
            "timestamp": self.created_at.isoformat()
        }

    class Config:
        """Pydantic model configuration."""
        json_encoders = {
            bytes: lambda v: v.hex(),
            int: lambda v: hex(v) if v > 1000 else v,  # Hex for large numbers (scalars)
            datetime: lambda v: v.isoformat()
        }

