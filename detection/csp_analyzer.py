"""
Content-Security-Policy analysis.

Parses and evaluates CSP headers for weaknesses that could
enable XSS, data exfiltration, or clickjacking.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.csp")

DANGEROUS_SOURCES = {"'unsafe-inline'", "'unsafe-eval'", "data:", "blob:"}
WILDCARD_PATTERNS = {"*", "*.com", "*.net", "*.org", "*.io", "http:", "https:"}


class CSPAnalyzer(BaseDetector):
    """Analyze Content-Security-Policy headers for security weaknesses."""

    @property
    def name(self) -> str:
        return "csp"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        tested = set()
        for host in scan_state.live_hosts:
            url = host.get("url", "")
            if not url or url in tested:
                continue
            tested.add(url)

            result = await self._analyze_csp(url)
            findings.extend(result)

        logger.info(f"CSP analyzer: {len(findings)} findings")
        return findings

    async def _analyze_csp(self, url: str) -> list[dict]:
        """Fetch and analyze CSP header for a URL."""
        findings = []

        resp = await self._get(url)
        if not resp:
            return findings

        csp = resp.headers.get("content-security-policy", "")
        csp_ro = resp.headers.get("content-security-policy-report-only", "")

        # No CSP at all
        if not csp and not csp_ro:
            findings.append(self._make_finding(
                title="Missing Content-Security-Policy Header",
                description=f"No CSP header is set on {url}.",
                severity=Severity.LOW,
                confidence=0.95,
                url=url,
                tags=["csp", "missing-header"],
                impact="Without CSP, the application has no browser-enforced protection against XSS attacks.",
                remediation="Implement a strict Content-Security-Policy header.",
            ))
            # Also check X-Frame-Options
            if not resp.headers.get("x-frame-options"):
                findings.append(self._make_finding(
                    title="Missing Clickjacking Protection",
                    description=f"Neither CSP frame-ancestors nor X-Frame-Options is set on {url}.",
                    severity=Severity.LOW,
                    confidence=0.9,
                    url=url,
                    tags=["clickjacking", "missing-header"],
                    remediation="Add Content-Security-Policy: frame-ancestors 'self' or X-Frame-Options: DENY.",
                ))
            return findings

        # Parse the policy
        policy = self._parse_csp(csp or csp_ro)
        is_report_only = bool(csp_ro and not csp)

        severity_modifier = Severity.INFO if is_report_only else Severity.MEDIUM

        # Check each directive
        # 1. unsafe-inline in script-src
        script_src = policy.get("script-src", policy.get("default-src", []))
        if "'unsafe-inline'" in script_src:
            findings.append(self._make_finding(
                title="CSP Allows unsafe-inline Scripts",
                description=(
                    f"The CSP on {url} includes 'unsafe-inline' in script-src, "
                    "which effectively disables XSS protection from CSP."
                ),
                severity=severity_modifier,
                confidence=0.95,
                url=url,
                evidence=f"script-src: {' '.join(script_src)}",
                tags=["csp", "unsafe-inline"],
                remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
            ))

        # 2. unsafe-eval
        if "'unsafe-eval'" in script_src:
            findings.append(self._make_finding(
                title="CSP Allows unsafe-eval",
                description=f"The CSP on {url} permits eval() and similar dynamic code execution.",
                severity=severity_modifier,
                confidence=0.95,
                url=url,
                evidence=f"script-src: {' '.join(script_src)}",
                tags=["csp", "unsafe-eval"],
                remediation="Remove 'unsafe-eval' and refactor code to avoid eval().",
            ))

        # 3. Wildcard sources
        for directive, sources in policy.items():
            for src in sources:
                if src in WILDCARD_PATTERNS:
                    findings.append(self._make_finding(
                        title=f"CSP Wildcard in {directive}",
                        description=f"The directive '{directive}' on {url} includes wildcard source '{src}'.",
                        severity=Severity.LOW,
                        confidence=0.9,
                        url=url,
                        evidence=f"{directive}: {' '.join(sources)}",
                        tags=["csp", "wildcard"],
                    ))
                    break

        # 4. Missing frame-ancestors (clickjacking)
        if "frame-ancestors" not in policy and not resp.headers.get("x-frame-options"):
            findings.append(self._make_finding(
                title="CSP Missing frame-ancestors Directive",
                description=f"No frame-ancestors directive in CSP on {url}, and no X-Frame-Options header.",
                severity=Severity.LOW,
                confidence=0.85,
                url=url,
                tags=["csp", "clickjacking"],
                remediation="Add frame-ancestors 'self' to the CSP.",
            ))

        # 5. data: URI in script-src or object-src
        for directive in ("script-src", "object-src"):
            sources = policy.get(directive, [])
            if "data:" in sources:
                findings.append(self._make_finding(
                    title=f"CSP data: URI Allowed in {directive}",
                    description=f"The directive '{directive}' on {url} allows data: URIs, which can be used for XSS.",
                    severity=severity_modifier,
                    confidence=0.9,
                    url=url,
                    evidence=f"{directive}: {' '.join(sources)}",
                    tags=["csp", "data-uri"],
                ))

        # 6. Report-only mode
        if is_report_only:
            findings.append(self._make_finding(
                title="CSP in Report-Only Mode",
                description=f"CSP on {url} is in report-only mode and does not enforce restrictions.",
                severity=Severity.INFO,
                confidence=0.95,
                url=url,
                tags=["csp", "report-only"],
                remediation="Switch from Content-Security-Policy-Report-Only to Content-Security-Policy.",
            ))

        return findings

    @staticmethod
    def _parse_csp(csp_string: str) -> dict[str, list[str]]:
        """Parse a CSP header string into directive → sources mapping."""
        policy: dict[str, list[str]] = {}
        for directive_str in csp_string.split(";"):
            parts = directive_str.strip().split()
            if len(parts) >= 1:
                directive = parts[0].lower()
                sources = parts[1:] if len(parts) > 1 else []
                policy[directive] = sources
        return policy
