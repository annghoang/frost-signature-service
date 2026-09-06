"""
Centralized error handlers for FastAPI application.

These handlers convert exceptions into standardized API responses
following the TrustGuard API contract.
"""

from datetime import datetime

import structlog
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.api.exceptions import TrustGuardException
from src.models.request import ErrorCode, ResponseStatus

logger = structlog.get_logger(__name__)


async def trustguard_exception_handler(
    request: Request,
    exc: TrustGuardException
) -> JSONResponse:
    """
    Handle all TrustGuard custom exceptions.

    Converts TrustGuardException into standardized error response format.
    """
    timestamp_iso = datetime.now().isoformat() + 'Z'

    # Log the error with context
    logger.warning(
        "api_error",
        error_code=exc.error_code,
        status_code=exc.status_code,
        path=request.url.path,
        client_id=exc.details.get("client_id"),
        session_id=exc.details.get("session_id"),
        message=exc.message
    )

    response_body = {
        "status": ResponseStatus.ERROR.value,
        "error": {
            "code": exc.error_code,
            "message": exc.message,
            "details": exc.details
        },
        "metadata": {
            "timestamp": timestamp_iso,
            "request_id": f"req_{id(request)}"
        }
    }

    return JSONResponse(
        status_code=exc.status_code,
        content=response_body
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
) -> JSONResponse:
    """
    Handle Pydantic validation errors from request body/params.

    Converts validation errors into user-friendly error messages.
    """
    timestamp_iso = datetime.now().isoformat() + 'Z'

    logger.warning(
        "validation_error",
        path=request.url.path,
        errors=exc.errors()
    )

    # Format validation errors
    error_details = {
        "validation_errors": [
            {
                "field": ".".join(str(loc) for loc in error["loc"]),
                "message": error["msg"],
                "type": error["type"]
            }
            for error in exc.errors()
        ]
    }

    response_body = {
        "status": ResponseStatus.ERROR.value,
        "error": {
            "code": ErrorCode.INVALID_REQUEST.value,
            "message": "Request validation failed",
            "details": error_details
        },
        "metadata": {
            "timestamp": timestamp_iso,
            "request_id": f"req_{id(request)}"
        }
    }

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,  # Standard for validation errors
        content=response_body
    )


async def generic_exception_handler(
    request: Request,
    exc: Exception
) -> JSONResponse:
    """
    Catch-all handler for unexpected exceptions.

    Logs full error details but returns sanitized response to user.
    """
    timestamp_iso = datetime.now().isoformat() + 'Z'

    # Log full exception for debugging (never expose to client)
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        exc_type=type(exc).__name__,
        exc_message=str(exc),
        exc_info=True  # Includes traceback in logs
    )

    # Sanitized response (don't leak internal details)
    response_body = {
        "status": ResponseStatus.ERROR.value,
        "error": {
            "code": ErrorCode.INTERNAL_ERROR.value,
            "message": "An unexpected error occurred",
            "details": {
                # Only include error type in non-production environments
                # "error_type": type(exc).__name__  # Add this for development
            }
        },
        "metadata": {
            "timestamp": timestamp_iso,
            "request_id": f"req_{id(request)}"
        }
    }

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=response_body
    )

