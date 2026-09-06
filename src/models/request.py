"""API request and response models."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ResponseStatus(str, Enum):
    """Response status enum."""
    SUCCESS = "success"
    ERROR = "error"


class ErrorCode(str, Enum):
    """Error code enum for all possible API errors."""
    INVALID_REQUEST = "INVALID_REQUEST"
    FORBIDDEN_MESSAGE = "FORBIDDEN_MESSAGE"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    CONCURRENT_LIMIT_EXCEEDED = "CONCURRENT_LIMIT_EXCEEDED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    SESSION_TIMEOUT = "SESSION_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_MESSAGE = "INVALID_MESSAGE"


class SigningRequest(BaseModel):
    """Request model for POST /approvals/request endpoint."""

    message: str = Field(
        ...,
        min_length=2,
        description="Hex-encoded message to sign (1-1024 bytes decoded)"
    )

    client_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r'^[a-zA-Z0-9_-]+$',
        description="Client identifier for rate limiting and session management"
    )


class SigningResponse(BaseModel):
    """Response model for POST /approvals/request endpoint."""

    status: ResponseStatus = Field(..., description="Response status: 'success' or 'error'")

    data: dict[str, Any] | None = Field(
        default=None,
        description="Response data containing session_id and signature (present on success)"
    )

    error: dict[str, Any] | None = Field(
        default=None,
        description="Error details with code (ErrorCode enum), message, and details"
    )

    metadata: dict[str, Any] = Field(
        ...,
        description="Response metadata (timestamp, request_id)"
    )


class VerifyRequest(BaseModel):
    """Request model for POST /approvals/verify endpoint."""

    message: str = Field(
        ...,
        min_length=2,
        description="Hex-encoded message (must be RELEASE_THE_FLAG)"
    )

    R: str = Field(
        ...,
        min_length=66,
        max_length=66,
        description="Hex-encoded aggregate nonce commitment (33 bytes)"
    )

    s: str = Field(
        ...,
        description="Hex-encoded aggregate signature scalar"
    )


class VerifyResponse(BaseModel):
    """Response model for POST /approvals/verify endpoint."""

    status: ResponseStatus = Field(..., description="Response status: 'success' or 'error'")

    data: dict[str, Any] | None = Field(
        default=None,
        description="Verification result with validity status and optional authorization token"
    )

    error: dict[str, Any] | None = Field(
        default=None,
        description="Error details with code (ErrorCode enum), message, and details"
    )

    metadata: dict[str, Any] = Field(
        ...,
        description="Response metadata (timestamp, request_id)"
    )


class SessionResponse(BaseModel):
    """Response model for GET /approvals/status/{id} endpoint."""

    status: ResponseStatus = Field(..., description="Response status: 'success' or 'error'")

    data: dict[str, Any] | None = Field(
        default=None,
        description="Session data including state and signature if complete"
    )

    error: dict[str, Any] | None = Field(
        default=None,
        description="Error details with code (ErrorCode enum), message, and details"
    )

    metadata: dict[str, Any] = Field(
        ...,
        description="Response metadata (timestamp, request_id)"
    )
