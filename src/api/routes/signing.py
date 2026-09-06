"""
Backwards-compatibility alias for signing API routes.

This module re-exports the approvals module to maintain backwards compatibility
with the legacy /sign and /session/{id} endpoints. New code should use /approvals/* endpoints.

DEPRECATED: Use src.api.routes.approvals instead.
"""

# Re-export everything from approvals for backwards compatibility
from src.api.routes.approvals import (  # noqa: F401
    _sessions,
    clear_sessions,
    concurrency_guard,
    create_signing_session,
    get_session_status,
    logger,
    router,
)

__all__ = [
    "router",
    "create_signing_session",
    "get_session_status",
    "clear_sessions",
    "_sessions",
    "concurrency_guard",
    "logger"
]
