from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog

from src.api.exceptions import ConcurrentSessionLimitError

logger = structlog.get_logger(__name__)


class ConcurrencyGuard:
    """Track per-client concurrent sessions using asyncio semaphores."""

    def __init__(self, max_concurrent_sessions: int = 3) -> None:
        self.max_concurrent_sessions = max_concurrent_sessions
        self._locks: dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(max_concurrent_sessions)
        )
        self._lock_registry = asyncio.Lock()
        self._violations = 0
        self._sessions_created_total = 0

    async def acquire(self, client_id: str) -> asyncio.Semaphore:
        async with self._lock_registry:
            semaphore = self._locks[client_id]

        # Try non-blocking acquire to track violations
        if semaphore.locked() and semaphore._value == 0:  # noqa: SLF001
            self._violations += 1
            logger.warning(
                "concurrency_limit_exceeded",
                client_id=client_id,
                max=self.max_concurrent_sessions,
            )
            raise ConcurrentSessionLimitError(
                client_id=client_id,
                max_sessions=self.max_concurrent_sessions
            )

        acquired = await semaphore.acquire()
        if not acquired:
            self._violations += 1
            raise ConcurrentSessionLimitError(
                client_id=client_id,
                max_sessions=self.max_concurrent_sessions
            )

        self._sessions_created_total += 1
        logger.debug(
            "concurrency_acquired",
            client_id=client_id,
            remaining=semaphore._value,  # noqa: SLF001
            max=self.max_concurrent_sessions,
        )
        return semaphore

    async def release(self, client_id: str, semaphore: asyncio.Semaphore) -> None:
        semaphore.release()
        logger.debug(
            "concurrency_released",
            client_id=client_id,
            remaining=semaphore._value,  # noqa: SLF001
            max=self.max_concurrent_sessions,
        )

    @asynccontextmanager
    async def session(self, client_id: str) -> AsyncIterator[None]:
        semaphore = await self.acquire(client_id)
        try:
            yield
        finally:
            await self.release(client_id, semaphore)

    def get_stats(self) -> dict[str, int]:
        """Return concurrency guard statistics."""
        return {
            "violations": self._violations,
            "sessions_created_total": self._sessions_created_total,
        }
