"""
FROST Threshold Signature Service - Main Application

Production service implementing FROST threshold signatures with t-of-n protocol.
"""

import time
from datetime import datetime

import structlog
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from src.api.error_handlers import (
    generic_exception_handler,
    trustguard_exception_handler,
    validation_exception_handler,
)
from src.api.exceptions import TrustGuardException
from src.api.routes import approvals, health, verify
from src.services.rate_limit import limiter

# Service start time for uptime tracking
SERVICE_START_TIME = time.time()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ]
)

logger = structlog.get_logger(__name__)

app = FastAPI(title="TrustGuard Treasury - Multi-Signature Service", version="2.0.0")

# Attach rate limiter middleware
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc: RateLimitExceeded):
    from src.models.request import ErrorCode, ResponseStatus

    # Calculate retry_after from the rate limit period
    retry_after = getattr(exc, 'retry_after', 60)  # Default to 60 seconds if not set

    return JSONResponse(
        status_code=201,
        content={
            "status": ResponseStatus.ERROR.value,
            "error": {
                "code": ErrorCode.RATE_LIMIT_EXCEEDED.value,
                "message": str(exc.detail),
                "details": {"retry_after": retry_after}
            },
            "metadata": {"timestamp": datetime.utcnow().isoformat() + "Z"}
        }
    )


# Register custom exception handlers (order matters: specific -> general)
# Using decorator pattern to avoid type checker issues
@app.exception_handler(TrustGuardException)
async def handle_trustguard_exception(request, exc):
    return await trustguard_exception_handler(request, exc)


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request, exc):
    return await validation_exception_handler(request, exc)


@app.exception_handler(Exception)
async def handle_generic_exception(request, exc):
    return await generic_exception_handler(request, exc)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(approvals.router, tags=["approvals"])
app.include_router(verify.router, tags=["verification"])
app.include_router(health.router, tags=["health"])

logger.info(
    "frost_service_initialized",
    threshold_t=5,
    total_signers_n=9
)
