"""
Approval API routes for TrustGuard Treasury threshold signature operations.

Implements POST /approvals/request and GET /approvals/status/{id} endpoints for the
enterprise threshold signature service.
"""

import time
from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Request, Response

from src.api.exceptions import (
    ConcurrentSessionLimitError,
    InternalServerError,
    SessionNotFoundError,
)
from src.models.message import Message
from src.models.request import (
    ErrorCode,
    ResponseStatus,
    SessionResponse,
    SigningRequest,
    SigningResponse,
)
from src.models.session import SessionState, SigningSession
from src.models.signature import AggregateSignature
from src.services.concurrency import ConcurrencyGuard
from src.services.frost import FROSTProtocol, get_frost_protocol
from src.services.key_manager import KeyManager, get_key_manager
from src.services.rate_limit import RATE_LIMIT_STRING, limiter
from src.services.subset_selector import SubsetSelector, get_subset_selector

logger = structlog.get_logger(__name__)

router = APIRouter()

# In-memory session storage using proper Pydantic models
_sessions: dict[str, SigningSession] = {}

concurrency_guard = ConcurrencyGuard(max_concurrent_sessions=3)


@router.post("/approvals/request", response_model=SigningResponse)
@limiter.limit(RATE_LIMIT_STRING)
async def create_signing_session(
    signing_request: SigningRequest,
    request: Request,
    response: Response,
    key_manager: KeyManager = Depends(get_key_manager),
    subset_selector: SubsetSelector = Depends(get_subset_selector),
    frost: FROSTProtocol = Depends(get_frost_protocol)
) -> SigningResponse:
    """
    Initiate a threshold approval request.

    Creates a new signing session using FROST protocol with t-of-n threshold.
    Selects a random subset of signers (with intelligent routing to active members),
    generates signatures, and returns the aggregate result.

    Rate limits: 3 concurrent sessions per client, 8 starts/min sustained.

    Args:
        request: Approval request with message and client identifier
        req: FastAPI request object for client identification
        rate_limiter: Rate limiter service (injected)
        key_manager: Key manager service (injected)
        subset_selector: Subset selector service (injected)
        frost: FROST protocol service (injected)

    Returns:
        SignResponse with session ID, aggregate signature, and council member subset

    Raises:
        HTTPException 400: Invalid message format or release flag attempted
        HTTPException 429: Rate limit exceeded
    """
    # Set status code to 201 for all responses (success and error)
    response.status_code = 201

    timestamp = time.time()

    # Extract client identifier from request
    client_id = signing_request.client_id or (request.client.host if request.client else "unknown")

    logger.info(
        "approval_request_received",
        client_id=client_id,
        message_length=len(signing_request.message)
    )

    # Parse message from hex to bytes
    try:
        message_bytes = bytes.fromhex(signing_request.message)
    except ValueError:
        timestamp_iso = datetime.now().isoformat() + 'Z'
        return SigningResponse(
            status=ResponseStatus.ERROR,
            error={
                "code": ErrorCode.INVALID_REQUEST.value,
                "message": "Invalid message: must be hex-encoded",
                "details": {}
            },
            metadata={"timestamp": timestamp_iso}
        )

    # Create Message model (validates size <= 1024 bytes)
    try:
        message = Message(content=message_bytes)
    except ValueError as e:
        timestamp_iso = datetime.now().isoformat() + 'Z'
        error_msg = str(e)
        if "max_length" in error_msg or len(message_bytes) > 1024:
            error_code = ErrorCode.MESSAGE_TOO_LARGE
            error_message = "Message must be between 1 and 1024 bytes"
            details = {"received_length": len(message_bytes)}
        else:
            error_code = ErrorCode.INVALID_REQUEST
            error_message = f"Invalid message: {error_msg}"
            details = {}

        return SigningResponse(
            status=ResponseStatus.ERROR,
            error={
                "code": error_code.value,
                "message": error_message,
                "details": details
            },
            metadata={"timestamp": timestamp_iso}
        )

    # Check if message is release flag (must be blocked for normal flow)
    if message.is_release_flag():
        logger.warning(
            "release_flag_approval_attempt",
            client_id=client_id
        )
        timestamp_iso = datetime.now().isoformat() + 'Z'
        return SigningResponse(
            status=ResponseStatus.ERROR,
            error={
                "code": ErrorCode.FORBIDDEN_MESSAGE.value,
                "message": "Cannot sign release flag message via this endpoint",
                "details": {}
            },
            metadata={"timestamp": timestamp_iso}
        )

    # Select signer subset (5-of-9 with intelligent routing to available members)
    subset = subset_selector.select_subset(timestamp)

    # Create signing session with proper model
    session = SigningSession(
        client_id=client_id,
        message=message,
        subset=subset,
        state=SessionState.INIT
    )
    session_id = session.session_id

    try:
        async with concurrency_guard.session(client_id):
            logger.debug(
                "council_subset_selected",
                session_id=session_id,
                subset=subset
            )

            # Execute FROST signing protocol
            R, s = frost.sign_message(
                client_id=client_id,
                message=message_bytes,
                subset=subset,
                timestamp=timestamp,
                session_id=session_id
            )

            # Create aggregate signature model
            signature = AggregateSignature(
                R=R,
                s=s,
                subset=subset,
                message_hash=message.hash
            )

            # Complete session with signature
            session.state = SessionState.SIGN  # Advance through states
            session.complete(signature)

            # Store session
            _sessions[session_id] = session

            logger.info(
                "approval_session_complete",
                session_id=session_id,
                client_id=client_id,
                subset=subset
            )

            # Return response (OpenAPI spec compliant with nested structure)
            timestamp_iso = datetime.now().isoformat() + 'Z'

            return SigningResponse(
                status=ResponseStatus.SUCCESS,
                data={
                    "session_id": session_id,
                    "signature": signature.to_response()
                },
                metadata={
                    "timestamp": timestamp_iso,
                    "request_id": f"req_{session_id[:8]}"
                }
            )

    except ConcurrentSessionLimitError:
        # Re-raise to be handled by FastAPI exception handler
        # This provides consistent error responses across the API
        raise

    except Exception as e:
        # Mark session as failed for unexpected errors
        session.fail(str(e))
        _sessions[session_id] = session

        logger.error(
            "approval_session_failed",
            session_id=session_id,
            client_id=client_id,
            error_type=type(e).__name__,
            error_message=str(e),
            exc_info=True  # Include traceback in logs
        )

        # Raise wrapped exception for consistent error handling
        raise InternalServerError(
            message="Approval session failed",
            details={
                "session_id": session_id,
                "error_type": type(e).__name__
            }
        ) from e


@router.get("/approvals/status/{session_id}")
async def get_session_status(session_id: str):
    """
    Retrieve status and details of an approval session.

    Args:
        session_id: UUID of the approval session

    Returns:
        Session status including signature and council member subset

    Raises:
        SessionNotFoundError: When session does not exist
    """
    logger.debug("session_status_requested", session_id=session_id)

    session = _sessions.get(session_id)

    if session is None:
        logger.warning("session_not_found", session_id=session_id)
        raise SessionNotFoundError(session_id=session_id)

    timestamp_iso = datetime.now().isoformat() + 'Z'

    # Build response data
    data: dict[str, Any] = {
        "session_id": session.session_id,
        "client_id": session.client_id,
        "state": session.state.value,
        "message_hash": session.message.hash_hex,
        "created_at": session.created_at.isoformat() + 'Z'
    }

    # Add signature and completed_at if session is complete
    if session.state == SessionState.COMPLETE and session.aggregate_signature:
        data["signature"] = session.aggregate_signature.to_response()
        if session.completed_at:
            data["completed_at"] = session.completed_at.isoformat() + 'Z'

    return SessionResponse(
        status=ResponseStatus.SUCCESS,
        data=data,
        metadata={
            "timestamp": timestamp_iso
        }
    )


def clear_sessions() -> None:
    """Clear all sessions (for testing)."""
    global _sessions
    _sessions.clear()

