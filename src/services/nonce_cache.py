"""
Nonce commitment caching service for FROST threshold signatures.

Implements a TTL-based cache for preprocessing nonce commitments to optimize
performance in high-throughput signing scenarios. By caching nonce material
for a short time window, we avoid redundant elliptic curve operations when
the same clients make multiple concurrent signing requests.

Cache keys are organized by (client_id, epoch, signer_id) where epoch is
determined by timestamp/TTL to provide temporal locality.
"""

import os
import time

import structlog
from cachetools import TTLCache

from src.crypto.utils import compute_epoch

logger = structlog.get_logger(__name__)


class NonceCache:
    """
    TTL-based cache for FROST preprocessing nonce commitments.

    Caches nonce material to reduce computational overhead in signing operations.
    The cache is keyed by (client_id, epoch, signer_id) to provide temporal
    locality while maintaining per-client and per-signer isolation.

    Cache entries automatically expire after the configured TTL, ensuring that
    stale nonce material is not retained indefinitely.
    """

    def __init__(self, ttl: int = 90, maxsize: int = 10000):
        """
        Initialize commitment pair cache for FROST protocol.

        Args:
            ttl: Time-to-live in seconds (default 90s)
            maxsize: Maximum cache entries (default 10000)
        """
        self.ttl = ttl
        self.maxsize = maxsize

        # Cache structure: {(client_id, epoch, signer_id): Nonce(d, e, D, E)}
        # Stores complete commitment pairs for FROST preprocessing
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._cache_hits = 0  # Track cache hits for metrics

        logger.info(
            "nonce_cache_initialized",
            ttl_seconds=ttl,
            max_entries=maxsize
        )

    def _make_key(self, client_id: str, signer_id: int, timestamp: float | None = None) -> tuple[str, int, int]:
        """
        Compute cache key for nonce lookup.

        Keys are organized by (client_id, epoch, signer_id) to provide temporal
        locality. The epoch is derived from the timestamp and TTL, grouping
        requests within the same time window together for cache efficiency.

        Args:
            client_id: Client session identifier
            signer_id: Signer ID (1-9)
            timestamp: Request timestamp (defaults to current time)

        Returns:
            Tuple of (client_id, epoch, signer_id) serving as cache key
        """
        if timestamp is None:
            timestamp = time.time()

        epoch = compute_epoch(timestamp, self.ttl)
        return (client_id, epoch, signer_id)

    def get(self, client_id: str, signer_id: int, timestamp: float | None = None):
        """
        Retrieve cached commitment pair for a signer.

        Checks the cache for existing preprocessing material (d, e, D, E).
        Cache hits improve performance by avoiding redundant elliptic curve operations.

        Args:
            client_id: Client session identifier
            signer_id: Signer ID
            timestamp: Request timestamp for epoch calculation

        Returns:
            Cached Nonce object (d, e, D, E) if available, None otherwise
        """
        key = self._make_key(client_id, signer_id, timestamp)
        nonce = self._cache.get(key)

        if nonce is not None:
            self._cache_hits += 1  # Track cache hit for metrics
            logger.debug(
                "nonce_cache_hit",
                client_id=client_id,
                signer_id=signer_id,
                epoch=key[1]
            )

        return nonce

    def set(self, client_id: str, signer_id: int, nonce, timestamp: float | None = None) -> None:
        """
        Store commitment pair in cache for future reuse.

        Caches preprocessing material (d, e, D, E) with TTL expiration to optimize
        subsequent signing operations within the same time window.

        Args:
            client_id: Client session identifier
            signer_id: Signer ID
            nonce: Nonce object containing (d, e, D, E) commitment pair
            timestamp: Request timestamp for epoch calculation
        """
        key = self._make_key(client_id, signer_id, timestamp)
        self._cache[key] = nonce

        logger.debug(
            "nonce_cached",
            client_id=client_id,
            signer_id=signer_id,
            epoch=key[1],
            ttl_seconds=self.ttl
        )

    def has(self, client_id: str, signer_id: int, timestamp: float | None = None) -> bool:
        """
        Check if a nonce exists for (client_id, epoch, signer_id).

        Args:
            client_id: Client identifier
            signer_id: Signer ID
            timestamp: Optional timestamp for epoch calculation

        Returns:
            True if nonce exists and is not expired
        """
        key = self._make_key(client_id, signer_id, timestamp)
        return key in self._cache

    def invalidate(self, client_id: str, signer_id: int, timestamp: float | None = None) -> None:
        """
        Remove a specific nonce from cache.

        Args:
            client_id: Client identifier
            signer_id: Signer ID
            timestamp: Optional timestamp for epoch calculation
        """
        key = self._make_key(client_id, signer_id, timestamp)
        self._cache.pop(key, None)

        logger.debug(
            "nonce_invalidated",
            client_id=client_id,
            signer_id=signer_id,
            epoch=key[1]
        )

    def clear_client(self, client_id: str) -> None:
        """
        Clear all nonces for a specific client.

        Args:
            client_id: Client identifier
        """
        # Find all keys matching this client_id
        keys_to_remove = [key for key in self._cache.keys() if key[0] == client_id]

        for key in keys_to_remove:
            self._cache.pop(key, None)

        logger.info(
            "client_nonces_cleared",
            client_id=client_id,
            count=len(keys_to_remove)
        )

    def clear_all(self) -> None:
        """Clear all cached nonces."""
        self._cache.clear()
        logger.info("nonce_cache_cleared")

    def get_stats(self) -> dict[str, int]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats including hit count
        """
        return {
            "size": len(self._cache),
            "hits": self._cache_hits,
            "maxsize": self.maxsize,
            "ttl": self.ttl,
        }


# Global singleton instance
_nonce_cache: NonceCache | None = None


def get_nonce_cache() -> NonceCache:
    """
    Get global nonce cache instance.

    Returns:
        NonceCache singleton
    """
    global _nonce_cache
    if _nonce_cache is None:
        # Cache size configurable via environment variable
        # Default: 10000 (for tests/small deployments)
        # Production CTF (1000 players): set NONCE_CACHE_SIZE=100000
        maxsize = int(os.getenv("NONCE_CACHE_SIZE", "10000"))
        _nonce_cache = NonceCache(ttl=90, maxsize=maxsize)
    return _nonce_cache



