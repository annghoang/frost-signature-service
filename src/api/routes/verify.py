"""
Signature verification API route for TrustGuard Treasury.

Implements POST /approvals/verify endpoint for independent verification
of threshold signatures against the council's joint public key.
"""

import os

import structlog
from fastapi import APIRouter, Depends

from src.api.exceptions import InvalidMessageFormatError, InvalidSignatureFormatError
from src.models.request import ErrorCode, ResponseStatus, VerifyRequest, VerifyResponse
from src.services.frost import FROSTProtocol, get_frost_protocol
from src.services.key_manager import KeyManager, get_key_manager
from src.config import get_config

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.post("/approvals/verify", response_model=VerifyResponse)
async def verify_signature(
    request: VerifyRequest,
    frost: FROSTProtocol = Depends(get_frost_protocol),
    key_manager: KeyManager = Depends(get_key_manager)
) -> VerifyResponse:
    """
    Verify a threshold signature against the council's joint public key.

    This endpoint allows independent verification of signatures produced by
    the TrustGuard Treasury approval process. Useful for audit trails and
    third-party verification of high-value transactions.

    Args:
        request: Verification request with message, R, and s components
        frost: FROST protocol service (injected)
        key_manager: Key manager service (injected)

    Returns:
        VerifyResponse indicating if signature is cryptographically valid

    Raises:
        InvalidMessageFormatError: When message is not valid hex-encoded
        InvalidSignatureFormatError: When R or s components are malformed
    """
    logger.info(
        "verification_requested",
        message_length=len(request.message)
    )

    # Parse message from hex to bytes
    try:
        message_bytes = bytes.fromhex(request.message)
    except ValueError as e:
        logger.warning("invalid_message_format", error=str(e))
        raise InvalidMessageFormatError()

    # Special handling for privileged operation signatures
    # Configuration messages require additional validation for security
    from src.models.message import RELEASE_FLAG_MESSAGE
    is_privileged_operation = (message_bytes == RELEASE_FLAG_MESSAGE)

    if is_privileged_operation:
        logger.info(
            "privileged_operation_verification",
            message_length=len(message_bytes)
        )

    # Validate signature components
    try:
        # Parse R (33-byte compressed point as hex)
        if len(request.R) != 66:  # 33 bytes = 66 hex chars
            raise InvalidSignatureFormatError(
                field="R",
                reason="must be 66 hex characters (33 bytes)"
            )

        R_bytes = bytes.fromhex(request.R)

        # Parse s (scalar as hex)
        s_int = int(request.s, 16)

    except ValueError as e:
        logger.warning("invalid_signature_format", error=str(e))
        raise InvalidSignatureFormatError(
            field="s",
            reason=str(e)
        )
    except InvalidSignatureFormatError:
        # Re-raise our custom exception
        raise

    # Verify signature
    is_valid = frost.verify_aggregate_signature(
        message=message_bytes,
        R=R_bytes,
        s=s_int
    )

    # For privileged operations, include additional context on success
    config = get_config()
    additional_info = None
    if is_valid and is_privileged_operation:
        # Load privileged operation token from environment
        # This is the authorization token for system configuration changes
        additional_info = config.PRIVILEGED_TOKEN

        logger.info(
            "privileged_operation_verified",
            message_hash=message_bytes.hex()[:16],
            signature_valid=True
        )
    else:
        logger.info(
            "verification_complete",
            is_valid=is_valid,
            privileged=is_privileged_operation
        )

    from datetime import datetime
    timestamp_iso = datetime.now().isoformat() + 'Z'

    # Build response
    response_data = {
        "valid": is_valid,
        "message_hash": message_bytes.hex() if is_valid else None,
        "joint_pubkey": key_manager._joint_pubkey.hex() if is_valid else None
    }

    # Include privileged operation token if applicable
    if additional_info:
        response_data["authorization_token"] = additional_info
        response_data["message"] = "Privileged operation signature verified successfully"
    elif is_valid:
        response_data["message"] = "Signature verified successfully"
    else:
        response_data["message"] = "Signature verification failed"

    return VerifyResponse(
        status=ResponseStatus.SUCCESS,
        data=response_data,
        metadata={
            "timestamp": timestamp_iso
        }
    )

