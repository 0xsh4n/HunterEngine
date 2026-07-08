"""
CORS misconfiguration detection.

Tests for dangerous Access-Control-Allow-Origin reflections
and overly permissive CORS policies.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.cors")


class CORSDetector(BaseDetector):
    """Detect CORS misconfigurations on target endpoints."""

    @property
    def name(self) -> str:
        return "cors"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Test endpoints and live hosts
        targets = set()
        for h in scan_state.live_hosts:
            targets.add(h.get("url", ""))
        for ep in scan_state.endpoints[:200]:
            targets.add(ep.get("url", ""))

        tasks = [self._test_cors(url) for url in targets if url]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        logger.info(f"CORS detector: {len(findings)} findings")
        return findings

    async def _test_cors(self, url: str) -> list[dict]:
        """Test a URL for CORS misconfigurations."""
        findings = []
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        test_origins = [
            ("https://evil.com", "arbitrary_origin", Severity.HIGH),
            (f"https://evil.{parsed.netloc}", "subdomain_prefix", Severity.HIGH),
            (f"{target_origin}.evil.com", "origin_suffix", Severity.HIGH),
            ("null", "null_origin", Severity.MEDIUM),
            (target_origin, "same_origin_reflected", Severity.INFO),
        ]

        for origin, test_type, severity in test_origins:
            resp = await self._get(url, headers={"Origin": origin})
            if not resp:
                continue

            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "").lower()

            if not acao:
                continue

            is_reflected = acao == origin
            is_wildcard = acao == "*"
            has_credentials = acac == "true"

            if test_type == "same_origin_reflected":
                continue  # Same origin reflection is expected

            if is_reflected and origin != target_origin:
                confidence = 0.95 if has_credentials else 0.8
                findings.append(self._make_finding(
                    title=f"CORS Misconfiguration — {test_type.replace('_', ' ').title()}",
                    description=(
                        f"The server reflects the Origin header '{origin}' in the "
                        f"Access-Control-Allow-Origin response. "
                        f"{'Credentials are also allowed, enabling full cross-origin access.' if has_credentials else ''}"
                    ),
                    severity=severity if has_credentials else Severity.MEDIUM,
                    confidence=confidence,
                    url=url,
                    evidence=(
                        f"Request Origin: {origin}\n"
                        f"Response ACAO: {acao}\n"
                        f"Response ACAC: {acac}"
                    ),
                    tags=["cors", test_type],
                    impact=(
                        "An attacker can read sensitive data cross-origin from any authenticated user "
                        "who visits a malicious page."
                        if has_credentials
                        else "Potentially allows cross-origin data access."
                    ),
                    remediation=(
                        "Implement a strict allowlist of trusted origins. "
                        "Avoid reflecting the Origin header directly. "
                        "Only set Access-Control-Allow-Credentials when necessary."
                    ),
                ))

            elif is_wildcard and has_credentials:
                findings.append(self._make_finding(
                    title="CORS Wildcard with Credentials",
                    description=(
                        "The server returns Access-Control-Allow-Origin: * alongside "
                        "Access-Control-Allow-Credentials: true. While browsers block this "
                        "combination, it signals a misconfigured CORS policy."
                    ),
                    severity=Severity.LOW,
                    confidence=0.7,
                    url=url,
                    tags=["cors", "wildcard"],
                ))

        return findings
