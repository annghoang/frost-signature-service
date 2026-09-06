"""Signing session model - represents a single signing request with protocol state."""

import uuid
from datetime import datetime, timedelta
from enum import Enum

from pydantic import BaseModel, Field

from .message import Message
from .nonce import Nonce
from .signature import AggregateSignature


class SessionState(str, Enum):
    """
    Session state enumeration for FROST protocol phases.

    State transitions:
    INIT → COMMIT: When nonces generated for all 5 signers
    COMMIT → SIGN: When challenge computed and partial signatures requested
    SIGN → COMPLETE: When all 5 partial signatures aggregated successfully
    Any → FAILED: On timeout or error
    """
    INIT = "init"
    COMMIT = "commit"
    SIGN = "sign"
    COMPLETE = "complete"
    FAILED = "failed"


class SigningSession(BaseModel):
    """
    Signing session model representing a single signing request.

    Tracks the complete lifecycle of a FROST threshold signing session
    including protocol state, selected signers, nonces, and final signature.
    """

    session_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique session identifier (UUID)"
    )

    client_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_-]+$',
        description="Client/player identifier"
    )

    message: Message = Field(..., description="Message to sign")

    subset: list[int] = Field(
        ...,
        min_length=5,
        max_length=5,
        description="Selected signer IDs (exactly 5)"
    )

    state: SessionState = Field(
        default=SessionState.INIT,
        description="Current protocol phase"
    )

    nonces: dict[int, Nonce] = Field(
        default_factory=dict,
        description="Per-signer nonces (R_i), keyed by signer_id"
    )

    partial_signatures: dict[int, int] = Field(
        default_factory=dict,
        description="Per-signer partial signatures (z_i), keyed by signer_id"
    )

    aggregate_signature: AggregateSignature | None = Field(
        default=None,
        description="Final aggregate signature (present when state=COMPLETE)"
    )

    created_at: datetime = Field(
        default_factory=datetime.now,
        description="Session start time"
    )

    completed_at: datetime | None = Field(
        default=None,
        description="Session end time (set on COMPLETE or FAILED)"
    )

    @property
    def timeout_at(self) -> datetime:
        """
        Session expiration time.

        Sessions timeout after 60 seconds from creation.
        """
        return self.created_at + timedelta(seconds=60)

    @property
    def is_expired(self) -> bool:
        """Check if session has exceeded timeout."""
        return datetime.now() > self.timeout_at

    def advance_to_commit(self) -> None:
        """
        Transition from INIT to COMMIT state.

        Requires nonces from all 5 signers in subset.

        Raises:
            ValueError: If current state is not INIT or nonces incomplete
        """
        if self.state != SessionState.INIT:
            raise ValueError(f"Cannot transition to COMMIT from {self.state}")

        if len(self.nonces) != 5:
            raise ValueError(f"Need nonces from all 5 signers, have {len(self.nonces)}")

        # Verify we have nonces for all signers in subset
        missing = set(self.subset) - set(self.nonces.keys())
        if missing:
            raise ValueError(f"Missing nonces for signers: {missing}")

        self.state = SessionState.COMMIT

    def advance_to_sign(self) -> None:
        """
        Transition from COMMIT to SIGN state.

        Raises:
            ValueError: If current state is not COMMIT
        """
        if self.state != SessionState.COMMIT:
            raise ValueError(f"Cannot transition to SIGN from {self.state}")

        self.state = SessionState.SIGN

    def complete(self, signature: AggregateSignature) -> None:
        """
        Complete session with aggregate signature.

        Transitions to COMPLETE state and records completion time.

        Args:
            signature: The final aggregate signature

        Raises:
            ValueError: If current state is not SIGN
        """
        if self.state != SessionState.SIGN:
            raise ValueError(f"Cannot complete from {self.state}")

        self.aggregate_signature = signature
        self.completed_at = datetime.now()
        self.state = SessionState.COMPLETE

    def fail(self, reason: str = "Unknown error") -> None:
        """
        Mark session as failed.

        Args:
            reason: Failure reason (for logging)
        """
        self.state = SessionState.FAILED
        self.completed_at = datetime.now()
        # Note: reason could be stored in a separate field if needed

    class Config:
        """Pydantic model configuration."""
        use_enum_values = False  # Keep enum objects
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            bytes: lambda v: v.hex()
        }

