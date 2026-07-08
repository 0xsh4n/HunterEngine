"""
Memory-based vulnerability detection.

Uses cross-session memory to identify patterns, correlate
findings from previous scans, and detect vulnerabilities
that only become apparent over multiple interactions.
"""

from __future__ import annotations

import logging
from typing import Any

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.memory_vulns")


class MemoryVulnsDetector(BaseDetector):
    """Detect vulnerabilities using cross-session pattern memory."""

    @property
    def name(self) -> str:
        return "memory_vulns"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        try:
            from memory.pattern_store import PatternStore
            from memory.endpoint_memory import EndpointMemory
            from memory.param_correlator import ParamCorrelator

            pattern_store = PatternStore()
            endpoint_memory = EndpointMemory()
            param_correlator = ParamCorrelator()

            # 1. Check for new endpoints since last scan
            current_endpoints = {ep.get("url", "") for ep in scan_state.endpoints}
            new_endpoints = await endpoint_memory.find_new(current_endpoints)
            if new_endpoints:
                logger.info(f"Found {len(new_endpoints)} new endpoints since last scan")
                for ep_url in list(new_endpoints)[:10]:
                    findings.append(self._make_finding(
                        title=f"New Endpoint Discovered: {ep_url}",
                        description="This endpoint was not seen in previous scans and may represent new attack surface.",
                        severity=Severity.INFO,
                        confidence=0.9,
                        url=ep_url,
                        tags=["memory", "new-endpoint", "recon"],
                    ))

            # 2. Check for disappeared endpoints (may indicate attempted fix)
            disappeared = await endpoint_memory.find_disappeared(current_endpoints)
            if disappeared:
                for ep_url in list(disappeared)[:5]:
                    findings.append(self._make_finding(
                        title=f"Endpoint Removed: {ep_url}",
                        description=(
                            "This endpoint was seen in previous scans but is no longer available. "
                            "This may indicate a security fix or configuration change."
                        ),
                        severity=Severity.INFO,
                        confidence=0.7,
                        url=ep_url,
                        tags=["memory", "removed-endpoint"],
                    ))

            # 3. Parameter correlation — find params that appear across endpoints
            cross_endpoint_params = param_correlator.correlate(scan_state.params)
            for param, urls in cross_endpoint_params.items():
                if len(urls) >= 3:
                    findings.append(self._make_finding(
                        title=f"Parameter '{param}' Used Across {len(urls)} Endpoints",
                        description=(
                            f"The parameter '{param}' appears across multiple endpoints, "
                            "suggesting a shared backend handler that may have a single "
                            "exploitable vulnerability."
                        ),
                        severity=Severity.INFO,
                        confidence=0.5,
                        url=urls[0],
                        evidence=f"Endpoints: {', '.join(urls[:5])}",
                        tags=["memory", "correlation", "shared-param"],
                    ))

            # 4. Store current scan data for future reference
            await endpoint_memory.store(current_endpoints)
            await pattern_store.store_findings(scan_state.findings)

        except ImportError as e:
            logger.debug(f"Memory modules not available: {e}")
        except Exception as e:
            logger.error(f"Memory-based detection failed: {e}")

        logger.info(f"Memory vulns detector: {len(findings)} findings")
        return findings
