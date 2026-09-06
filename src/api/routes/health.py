"""
Health check and metrics API routes.

Implements GET /health and GET /metrics endpoints for service monitoring.
"""

import structlog
from fastapi import APIRouter, Depends

from src.services.nonce_cache import NonceCache, get_nonce_cache

logger = structlog.get_logger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """
    Service health check endpoint.

    Returns basic health status and system information per OpenAPI spec.

    Returns:
        Dictionary with status, version, uptime_seconds, joint_pubkey
    """
    logger.debug("health_check_requested")

    import time

    from src.config import get_config
    from src.main import SERVICE_START_TIME
    from src.services.key_manager import get_key_manager

    uptime = int(time.time() - SERVICE_START_TIME)
    key_manager = get_key_manager()
    config = get_config()

    return {
        "status": "healthy",
        "version": "1.0.0",
        "uptime_seconds": uptime,
        "joint_pubkey": key_manager._joint_pubkey.hex(),
    }


@router.get("/metrics")
async def get_metrics(
    nonce_cache: NonceCache = Depends(get_nonce_cache)
) -> dict:
    """
    Service metrics and statistics.

    Returns operational metrics in flat structure per OpenAPI spec.

    Args:
        nonce_cache: Nonce cache service (injected)

    Returns:
        Dictionary with service metrics: active_sessions, sessions_created_total,
        nonce_cache_size, nonce_cache_hits, rate_limit_violations, response_time_p95_ms
    """
    logger.debug("metrics_requested")

    # Get session storage and concurrency guard
    import time

    from src.api.routes.signing import _sessions, concurrency_guard

    # Count active sessions (not failed or completed < 60s ago)
    active_count = sum(
        1 for session in _sessions.values()
        if session.state.value in ["init", "commit", "sign"]
        or (session.state.value == "complete" and
            session.completed_at and
            (time.time() - session.completed_at.timestamp()) < 60)
    )

    # Get cache stats
    cache_stats = nonce_cache.get_stats()

    # Get concurrency guard stats
    concurrency_stats = concurrency_guard.get_stats()

    return {
        "active_sessions": active_count,
        "sessions_created_total": concurrency_stats.get("sessions_created_total", len(_sessions)),
        "nonce_cache_size": cache_stats.get("size", 0),
        "nonce_cache_hits": cache_stats.get("hits", 0),
        "rate_limit_violations": concurrency_stats.get("violations", 0),
        "response_time_p95_ms": 0.0,  # Placeholder - would need proper tracking
    }

