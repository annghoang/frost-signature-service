"""
Configuration module for FROST-LinSys service.

Loads configuration from environment variables with sensible defaults.
Supports both standard difficulty (60% bias) and expert difficulty (20% bias).
"""

import os
from typing import Literal

import structlog

logger = structlog.get_logger(__name__)


class Config:
    """Service configuration loaded from environment variables."""

    # Subset selection parameters
    # Enterprise naming: "SMART_ROUTING_PREFERENCE" (externally visible)
    # Internal variable: SUBSET_BIAS_PERCENT (technical name)
    # Accepts both names for flexibility
    SMART_ROUTING_PREFERENCE: int = int(
        os.getenv("SMART_ROUTING_PREFERENCE") or
        os.getenv("SUBSET_BIAS_PERCENT") or
        "60"  # Default: standard difficulty
    )

    # Validate bias percentage
    if not (0 <= SMART_ROUTING_PREFERENCE <= 100):
        raise ValueError(
            f"SMART_ROUTING_PREFERENCE must be 0-100, got {SMART_ROUTING_PREFERENCE}"
        )

    # Convert to probability (0.0-1.0)
    SUBSET_BIAS_PROBABILITY: float = SMART_ROUTING_PREFERENCE / 100.0

    # Signer parameters
    N_SIGNERS: int = 9
    THRESHOLD: int = 5
    ACTIVITY_WINDOW_SECONDS: float = 120.0

    # Timing parameters (names maintain enterprise style)
    SESSION_OPTIMIZATION_TTL: int = int(os.getenv("SESSION_OPTIMIZATION_TTL", "90"))
    APPROVAL_TIMEOUT: int = int(os.getenv("APPROVAL_TIMEOUT", "60"))

    # Rate limiting
    MAX_CONCURRENT_SESSIONS: int = int(os.getenv("MAX_CONCURRENT_SESSIONS", "3"))

    # Nonce/commitment cache
    NONCE_CACHE_SIZE: int = int(os.getenv("NONCE_CACHE_SIZE", "10000"))

    # Service metadata
    SERVICE_NAME: str = os.getenv("SERVICE_NAME", "TrustGuard Treasury")
    SERVICE_VERSION: str = os.getenv("SERVICE_VERSION", "1.0.0")

    # Authorization token exposed for privileged verification flows
    # Prefer FLAG for naming consistency; fall back to legacy env vars for compatibility
    PRIVILEGED_TOKEN: str = (
        os.getenv("FLAG")
        or "TOKEN_NOT_CONFIGURED"
    )

    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()


# Singleton instance
_config_instance: Config | None = None


def get_config() -> Config:
    """
    Get configuration singleton.

    Returns:
        Config instance with all settings
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = Config()
    logger.info(
        "config_initialized",
        bias_percent=_config_instance.SMART_ROUTING_PREFERENCE
    )
    return _config_instance


def log_config_summary():
    """Log configuration summary on startup."""
    config = get_config()
    logger.info(
        "service_configuration_loaded",
        smart_routing_preference=config.SMART_ROUTING_PREFERENCE,
        bias_probability=config.SUBSET_BIAS_PROBABILITY,
        n_signers=config.N_SIGNERS,
        threshold=config.THRESHOLD,
        session_optimization_ttl=config.SESSION_OPTIMIZATION_TTL,
        approval_timeout=config.APPROVAL_TIMEOUT,
        max_concurrent_sessions=config.MAX_CONCURRENT_SESSIONS,
    )

