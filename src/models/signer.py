"""Signer model - represents one of n=9 council members with a secret key share."""

from datetime import datetime

from pydantic import BaseModel, Field, field_serializer


class Signer(BaseModel):
    """
    Signer model representing one of 9 council members.

    Each signer has a secret key share x_i and corresponding public key share P_i = x_i·G.
    The joint public key is: PK = Σ(λ_i · P_i) for any subset.
    """

    signer_id: int = Field(..., ge=1, le=9, description="Stable identifier (1-9)")

    private_key_share: bytes = Field(
        ...,
        min_length=32,
        max_length=32,
        description="Secret key share x_i (32 bytes)",
        exclude=True  # Never exposed in JSON serialization
    )

    public_key_share: bytes = Field(
        ...,
        min_length=33,
        max_length=33,
        description="Public key share P_i = x_i·G (33 bytes compressed SEC format)"
    )

    last_active_time: datetime = Field(
        default_factory=datetime.now,
        description="Last time signer participated in a session"
    )

    @field_serializer('public_key_share')
    def serialize_public_key(self, value: bytes) -> str:
        """Serialize public key as hex string."""
        return value.hex()

    @field_serializer('last_active_time')
    def serialize_datetime(self, value: datetime) -> str:
        """Serialize datetime as ISO 8601 string."""
        return value.isoformat()

    class Config:
        """Pydantic model configuration."""
        json_encoders = {
            bytes: lambda v: v.hex(),
            datetime: lambda v: v.isoformat()
        }

    def update_activity(self) -> None:
        """Update last_active_time to current time."""
        self.last_active_time = datetime.now()

