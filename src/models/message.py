"""Message model - input data to be signed."""

import hashlib

from pydantic import BaseModel, Field

# The protected release flag message (victory condition)
RELEASE_FLAG_MESSAGE = b"RELEASE_THE_FLAG"


class Message(BaseModel):
    """
    Message model for signing requests.

    Represents the input data to be signed by the threshold signature scheme.
    """

    content: bytes = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Raw message bytes (1-1024 bytes)"
    )

    @property
    def hash(self) -> bytes:
        """
        Compute SHA256 hash of message content.

        Returns:
            32-byte hash digest
        """
        return hashlib.sha256(self.content).digest()

    @property
    def hash_hex(self) -> str:
        """Return hash as hex string for API responses."""
        return self.hash.hex()

    def is_release_flag(self) -> bool:
        """
        Check if this is the protected release flag message.

        The release flag message cannot be signed through normal /sign endpoint.
        It can only be verified via /verify endpoint.

        Returns:
            True if this is the release flag message
        """
        return self.content == RELEASE_FLAG_MESSAGE

    class Config:
        """Pydantic model configuration."""
        json_encoders = {
            bytes: lambda v: v.hex()
        }

