"""
Signer subset selection service.

Selects t signers from n total signers with intelligent routing that prioritizes
recently active council members for faster response times.
"""

import random
import time
from collections import defaultdict
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class SubsetSelector:
    """
    Selects signer subsets with intelligent routing towards recently active signers.

    This optimization increases the likelihood of using the same high-availability
    council members for consecutive approval requests, improving response times.
    """

    def __init__(
        self,
        n: int = 9,
        t: int = 5,
        activity_window: float = 120.0,
        bias_probability: float = 0.60
    ):
        """
        Initialize subset selector.

        Args:
            n: Total number of signers (default 9)
            t: Threshold (number of signers to select, default 5)
            activity_window: Time window for "recent" activity in seconds (default 120s)
            bias_probability: Probability of selecting from recently active signers (default 0.60)
        """
        self.n = n
        self.t = t
        self.activity_window = activity_window
        self.bias_probability = bias_probability

        # Signer IDs are 1-9 (not 0-8)
        self.all_signers = list(range(1, n + 1))

        # Track last activity time for each signer
        # {signer_id: last_active_timestamp}
        self._last_active: dict[int, float] = defaultdict(lambda: 0.0)

        logger.info(
            "subset_selector_initialized",
            n=n,
            t=t,
            activity_window=activity_window,
            bias_probability=bias_probability
        )

    def select_subset(self, timestamp: float | None = None) -> list[int]:
        """
        Select t signers from n with bias towards recently active.

        Algorithm:
        1. Identify "recently active" signers (active within activity_window)
        2. With bias_probability, try to select from recently active signers
        3. Otherwise, select uniformly at random from all signers
        4. Always return exactly t unique signers

        Args:
            timestamp: Current timestamp (defaults to time.time())

        Returns:
            Sorted list of t signer IDs
        """
        if timestamp is None:
            timestamp = time.time()

        # Identify recently active signers
        cutoff = timestamp - self.activity_window
        recently_active = [
            signer_id for signer_id, last_time in self._last_active.items()
            if last_time >= cutoff
        ]

        # Decide whether to use bias
        use_bias = (
            len(recently_active) >= self.t
            and random.random() < self.bias_probability
        )

        if use_bias:
            # Select from recently active signers
            subset = random.sample(recently_active, self.t)
            logger.debug(
                "subset_selected_with_bias",
                subset=subset,
                recently_active_count=len(recently_active),
                bias_probability=self.bias_probability
            )
        else:
            # Select uniformly at random from all signers
            subset = random.sample(self.all_signers, self.t)
            logger.debug(
                "subset_selected_random",
                subset=subset,
                recently_active_count=len(recently_active)
            )

        # Mark these signers as active
        for signer_id in subset:
            self._last_active[signer_id] = timestamp

        return sorted(subset)

    def mark_active(self, signer_ids: list[int], timestamp: float | None = None) -> None:
        """
        Explicitly mark signers as active.

        Args:
            signer_ids: List of signer IDs to mark as active
            timestamp: Timestamp to record (defaults to current time)
        """
        if timestamp is None:
            timestamp = time.time()

        for signer_id in signer_ids:
            if signer_id in self.all_signers:
                self._last_active[signer_id] = timestamp

    def get_recently_active(self, timestamp: float | None = None) -> list[int]:
        """
        Get list of recently active signers.

        Args:
            timestamp: Current timestamp (defaults to time.time())

        Returns:
            List of signer IDs active within activity_window
        """
        if timestamp is None:
            timestamp = time.time()

        cutoff = timestamp - self.activity_window
        return [
            signer_id for signer_id, last_time in self._last_active.items()
            if last_time >= cutoff
        ]

    def get_activity_stats(self, timestamp: float | None = None) -> dict[str, Any]:
        """
        Get activity statistics.

        Args:
            timestamp: Current timestamp

        Returns:
            Dictionary with activity stats
        """
        if timestamp is None:
            timestamp = time.time()

        recently_active = self.get_recently_active(timestamp)

        return {
            "total_signers": self.n,
            "threshold": self.t,
            "recently_active": len(recently_active),
            "recently_active_ids": sorted(recently_active),
            "bias_probability": self.bias_probability,
            "activity_window": self.activity_window,
        }

    def reset_activity(self) -> None:
        """Clear all activity tracking."""
        self._last_active.clear()
        logger.info("activity_tracking_reset")


# Global singleton instance
_subset_selector: 'SubsetSelector | None' = None


def get_subset_selector() -> SubsetSelector:
    """
    Get global subset selector instance.

    Reads configuration from src.config to support both standard (60% bias)
    and expert (20% bias) difficulty modes.

    Returns:
        SubsetSelector singleton
    """
    global _subset_selector
    if _subset_selector is None:
        # Import here to avoid circular dependency
        from src.config import get_config
        config = get_config()

        _subset_selector = SubsetSelector(
            n=config.N_SIGNERS,
            t=config.THRESHOLD,
            activity_window=config.ACTIVITY_WINDOW_SECONDS,
            bias_probability=config.SUBSET_BIAS_PROBABILITY
        )
    return _subset_selector



