from __future__ import annotations

import os
from slowapi import Limiter
from slowapi.util import get_remote_address

# Rate limit configuration via environment variable
# RATE_LIMIT_PER_MINUTE: Number of requests allowed per minute per IP
# Default: 8/minute (service design), override for testing or scaling
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "8"))

# Rate limit string for decorator usage
RATE_LIMIT_STRING = f"{RATE_LIMIT_PER_MINUTE}/minute"

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[]  # Apply limits per-route for flexibility
)
