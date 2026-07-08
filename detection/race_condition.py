"""
Race condition detection.

Tests for time-of-check-time-of-use (TOCTOU) vulnerabilities
by sending concurrent duplicate requests to state-changing endpoints.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.race")

# Endpoints likely vulnerable to race conditions
RACE_INDICATORS = [
    "redeem", "coupon", "voucher", "claim", "transfer",
    "withdraw", "deposit", "purchase", "buy", "checkout",
    "vote", "like", "follow", "invite", "apply",
    "activate", "deactivate", "upgrade", "downgrade",
]


class RaceConditionDetector(BaseDetector):
    """Detect race condition vulnerabilities via concurrent request testing."""

    @property
    def name(self) -> str:
        return "race_condition"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Find state-changing endpoints
        targets = self._find_race_targets(scan_state)
        logger.info(f"Testing {len(targets)} endpoints for race conditions")

        for target in targets[:30]:
            result = await self._test_race(target)
            if result:
                findings.append(result)

        logger.info(f"Race condition detector: {len(findings)} findings")
        return findings

    def _find_race_targets(self, scan_state: Any) -> list[dict]:
        """Identify endpoints likely to be vulnerable to race conditions."""
        targets = []
        seen = set()

        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            path = urlparse(url).path.lower()

            # Only POST/PUT/PATCH (state-changing)
            if method not in ("POST", "PUT", "PATCH"):
                continue

            # Check for race-prone path patterns
            if any(indicator in path for indicator in RACE_INDICATORS):
                if url not in seen:
                    seen.add(url)
                    targets.append(ep)

        return targets

    async def _test_race(self, endpoint: dict) -> Optional[dict]:
        """
        Test an endpoint for race conditions by sending concurrent requests.

        Strategy: fire N identical requests simultaneously and check if
        the server processes more than expected (e.g., double-spend).
        """
        url = endpoint.get("url", "")
        method = endpoint.get("method", "POST").upper()
        concurrency = 10

        # Send concurrent requests
        async def send_one():
            return await self._request(
                method, url,
                json_body={"action": "test"},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )

        tasks = [send_one() for _ in range(concurrency)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        valid_responses = [r for r in responses if not isinstance(r, Exception) and r is not None]
        if len(valid_responses) < 3:
            return None

        status_codes = [r.status_code for r in valid_responses]
        success_count = sum(1 for s in status_codes if 200 <= s < 300)
        lengths = [len(r.content) for r in valid_responses]

        # If all concurrent requests succeeded (when only 1 should)
        # or if response bodies differ, it may indicate a race condition
        if success_count >= concurrency * 0.8:
            # Check if responses look like they all performed the action
            unique_bodies = len(set(r.text[:500] for r in valid_responses if r))

            if unique_bodies <= 2:  # All responses are similar — action may have applied multiple times
                return self._make_finding(
                    title=f"Potential Race Condition on {urlparse(url).path}",
                    description=(
                        f"Sending {concurrency} concurrent requests to {url} resulted in "
                        f"{success_count} successful responses. If this is a one-time action "
                        "(e.g., coupon redemption, transfer), it may have been processed multiple times."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    url=url,
                    method=method,
                    evidence=(
                        f"Concurrent requests: {concurrency}\n"
                        f"Successful: {success_count}\n"
                        f"Status codes: {status_codes}\n"
                        f"Unique response bodies: {unique_bodies}\n"
                        f"Response lengths: {lengths}"
                    ),
                    tags=["race-condition", "toctou", "needs-verification"],
                    impact=(
                        "Race conditions on financial or state-changing endpoints can lead to "
                        "double-spending, multiple coupon redemptions, or duplicate actions."
                    ),
                    remediation=(
                        "Implement proper locking mechanisms (database-level locks, "
                        "optimistic concurrency control, or idempotency keys) on "
                        "state-changing operations."
                    ),
                )

        return None
