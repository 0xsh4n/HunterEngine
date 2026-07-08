"""
Adaptive rate limiter.

Enforces per-host and global request rate limits.
Automatically backs off on 429/WAF responses.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class HostState:
    """Per-host rate limiting state."""
    tokens: float = 0.0
    last_refill: float = field(default_factory=time.monotonic)
    backoff_until: float = 0.0
    consecutive_blocks: int = 0
    total_requests: int = 0
    total_blocked: int = 0


class RateLimiter:
    """
    Token-bucket rate limiter with adaptive backoff.

    - Global RPS cap across all hosts
    - Per-host RPS cap
    - Automatic exponential backoff on 429 / WAF block
    - Burst allowance for short spikes
    """

    WAF_STATUS_CODES = {429, 403, 503}

    def __init__(
        self,
        global_rps: float = 10.0,
        per_host_rps: float = 5.0,
        burst_size: int = 20,
        adaptive: bool = True,
        backoff_factor: float = 2.0,
        backoff_max: float = 120.0,
    ) -> None:
        self.global_rps = global_rps
        self.per_host_rps = per_host_rps
        self.burst_size = burst_size
        self.adaptive = adaptive
        self.backoff_factor = backoff_factor
        self.backoff_max = backoff_max

        self._global_tokens = float(burst_size)
        self._global_last_refill = time.monotonic()
        self._hosts: dict[str, HostState] = defaultdict(HostState)
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        """
        Wait until a request to `host` is allowed.
        Blocks if rate limit or backoff is active.
        """
        async with self._lock:
            now = time.monotonic()
            hs = self._hosts[host]

            # Check backoff
            if hs.backoff_until > now:
                wait = hs.backoff_until - now
                # Release lock while waiting
                self._lock.release()
                await asyncio.sleep(wait)
                await self._lock.acquire()
                now = time.monotonic()

            # Refill global tokens
            elapsed_global = now - self._global_last_refill
            self._global_tokens = min(
                float(self.burst_size),
                self._global_tokens + elapsed_global * self.global_rps,
            )
            self._global_last_refill = now

            # Refill host tokens
            elapsed_host = now - hs.last_refill
            hs.tokens = min(
                float(self.burst_size),
                hs.tokens + elapsed_host * self.per_host_rps,
            )
            hs.last_refill = now

            # Wait for both buckets to have a token
            while self._global_tokens < 1.0 or hs.tokens < 1.0:
                wait_global = (1.0 - self._global_tokens) / self.global_rps if self._global_tokens < 1.0 else 0
                wait_host = (1.0 - hs.tokens) / self.per_host_rps if hs.tokens < 1.0 else 0
                wait_time = max(wait_global, wait_host, 0.01)

                self._lock.release()
                await asyncio.sleep(wait_time)
                await self._lock.acquire()

                now = time.monotonic()
                elapsed_global = now - self._global_last_refill
                self._global_tokens = min(
                    float(self.burst_size),
                    self._global_tokens + elapsed_global * self.global_rps,
                )
                self._global_last_refill = now

                elapsed_host = now - hs.last_refill
                hs.tokens = min(
                    float(self.burst_size),
                    hs.tokens + elapsed_host * self.per_host_rps,
                )
                hs.last_refill = now

            # Consume tokens
            self._global_tokens -= 1.0
            hs.tokens -= 1.0
            hs.total_requests += 1

    def report_response(self, host: str, status_code: int) -> None:
        """
        Report an HTTP response status. Triggers backoff on WAF/rate-limit codes.
        """
        if not self.adaptive:
            return

        hs = self._hosts[host]

        if status_code in self.WAF_STATUS_CODES:
            hs.consecutive_blocks += 1
            hs.total_blocked += 1
            backoff = min(
                self.backoff_factor ** hs.consecutive_blocks,
                self.backoff_max,
            )
            hs.backoff_until = time.monotonic() + backoff
        else:
            hs.consecutive_blocks = max(0, hs.consecutive_blocks - 1)

    def get_stats(self) -> dict[str, dict]:
        """Return per-host rate limit statistics."""
        stats = {}
        for host, hs in self._hosts.items():
            stats[host] = {
                "total_requests": hs.total_requests,
                "total_blocked": hs.total_blocked,
                "consecutive_blocks": hs.consecutive_blocks,
                "in_backoff": hs.backoff_until > time.monotonic(),
            }
        return stats

    async def wait_random_delay(self, min_delay: float = 0.5, max_delay: float = 2.0) -> None:
        """Humanize requests with a random delay."""
        import random
        delay = random.uniform(min_delay, max_delay)
        await asyncio.sleep(delay)
