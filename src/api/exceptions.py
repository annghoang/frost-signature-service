"""
Custom exceptions for the TrustGuard Treasury API.

These exceptions provide type-safe error handling and enable
FastAPI's automatic HTTP status code mapping.
"""

from typing import Any


class TrustGuardException(Exception):
    """Base exception for all TrustGuard errors."""

    def __init__(
        self,
        message: str,
        error_code: str,
        details: dict[str, Any] | None = None,
        status_code: int = 500
    ) -> None:
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.status_code = status_code
        super().__init__(message)


class ConcurrentSessionLimitError(TrustGuardException):
    """Raised when client exceeds concurrent session limit."""

    def __init__(
        self,
        client_id: str,
        max_sessions: int = 3,
        retry_after: int = 1
    ) -> None:
        super().__init__(
            message=f"Maximum {max_sessions} concurrent sessions per client",
            error_code="CONCURRENT_LIMIT_EXCEEDED",
            details={
                "client_id": client_id,
                "active_sessions": max_sessions,
                "retry_after": retry_after
            },
            status_code=429
        )


class SessionNotFoundError(TrustGuardException):
    """Raised when requested session does not exist."""

    def __init__(self, session_id: str) -> None:
        super().__init__(
            message="Session not found",
            error_code="SESSION_NOT_FOUND",
            details={"session_id": session_id},
            status_code=404
        )


class SessionTimeoutError(TrustGuardException):
    """Raised when session exceeds timeout limit."""

    def __init__(self, session_id: str, timeout_seconds: int = 60) -> None:
        super().__init__(
            message=f"Session exceeded {timeout_seconds}s timeout",
            error_code="SESSION_TIMEOUT",
            details={"session_id": session_id, "timeout_seconds": timeout_seconds},
            status_code=408
        )


class ForbiddenMessageError(TrustGuardException):
    """Raised when attempting to sign a forbidden message."""

    def __init__(self, message: str = "Cannot sign release flag message via this endpoint") -> None:
        super().__init__(
            message=message,
            error_code="FORBIDDEN_MESSAGE",
            details={},
            status_code=400
        )


class MessageTooLargeError(TrustGuardException):
    """Raised when message exceeds size limit."""

    def __init__(self, size: int, max_size: int = 1024) -> None:
        super().__init__(
            message=f"Message must be between 1 and {max_size} bytes",
            error_code="MESSAGE_TOO_LARGE",
            details={"received_length": size, "max_length": max_size},
            status_code=400
        )


class InvalidRequestError(TrustGuardException):
    """Raised when request validation fails."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="INVALID_REQUEST",
            details=details or {},
            status_code=400
        )


class SignatureVerificationError(TrustGuardException):
    """Raised when signature verification fails."""

    def __init__(self, message: str = "Signature verification failed") -> None:
        super().__init__(
            message=message,
            error_code="VERIFICATION_FAILED",
            details={},
            status_code=200  # Per spec: verification endpoint always returns 200
        )


class InternalServerError(TrustGuardException):
    """Raised for unexpected internal errors."""

    def __init__(self, message: str = "Internal server error", details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="INTERNAL_ERROR",
            details=details or {},
            status_code=500
        )


class InvalidMessageFormatError(TrustGuardException):
    """Raised when message format is invalid (not hex-encoded)."""

    def __init__(self, message: str = "Invalid message: must be hex-encoded") -> None:
        super().__init__(
            message=message,
            error_code="INVALID_MESSAGE_FORMAT",
            details={},
            status_code=400
        )


class InvalidSignatureFormatError(TrustGuardException):
    """Raised when signature components (R, s) have invalid format."""

    def __init__(self, field: str, reason: str) -> None:
        super().__init__(
            message=f"Invalid signature format: {field} - {reason}",
            error_code="INVALID_SIGNATURE_FORMAT",
            details={"field": field, "reason": reason},
            status_code=400
        )


class KeyManagerError(TrustGuardException):
    """Raised for key manager initialization or operation errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            message=message,
            error_code="KEY_MANAGER_ERROR",
            details=details or {},
            status_code=500
        )


class InvalidSignerIDError(TrustGuardException):
    """Raised when an invalid signer ID is provided."""

    def __init__(self, signer_id: int, valid_range: str = "0-8") -> None:
        super().__init__(
            message=f"Invalid signer ID: {signer_id}. Must be in range {valid_range}",
            error_code="INVALID_SIGNER_ID",
            details={"signer_id": signer_id, "valid_range": valid_range},
            status_code=400
        )

