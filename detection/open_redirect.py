"""
Open redirect detection.

Tests URL parameters that control redirects for open redirect
vulnerabilities that can be used in phishing chains.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.redirect")

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnTo", "next", "next_url", "dest",
    "destination", "rurl", "redir", "out", "view", "login_url",
    "continue", "goto", "target", "link", "forward", "callback",
    "cb", "checkout_url", "image_url", "return_path", "success_url",
    "error_url", "cancel_url",
]


class OpenRedirectDetector(BaseDetector):
    """Detect open redirect vulnerabilities."""

    @property
    def name(self) -> str:
        return "open_redirect"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Find redirect-prone parameters
        targets = self._find_redirect_targets(scan_state)

        if not targets:
            logger.info("No redirect-prone parameters found")
            return findings

        logger.info(f"Testing {len(targets)} redirect vectors")

        tasks = [self._test_redirect(t) for t in targets[:200]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                findings.append(result)

        logger.info(f"Open redirect detector: {len(findings)} findings")
        return findings

    def _find_redirect_targets(self, scan_state: Any) -> list[dict]:
        """Find endpoints with redirect-like parameters."""
        targets = []
        seen = set()

        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for key in params:
                if key.lower() in REDIRECT_PARAMS:
                    target_key = f"{parsed.netloc}{parsed.path}:{key}"
                    if target_key not in seen:
                        seen.add(target_key)
                        targets.append({
                            "base_url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            "param": key,
                            "original_value": params[key][0],
                        })

        # Also test discovered params
        for url, params in scan_state.params.items():
            for p in params:
                if p.lower() in REDIRECT_PARAMS:
                    target_key = f"{urlparse(url).netloc}{urlparse(url).path}:{p}"
                    if target_key not in seen:
                        seen.add(target_key)
                        targets.append({
                            "base_url": url,
                            "param": p,
                            "original_value": "",
                        })

        return targets

    async def _test_redirect(self, target: dict) -> Optional[dict]:
        """Test a parameter for open redirect."""
        url = target["base_url"]
        param = target["param"]

        # Test payloads — progressively more evasive
        payloads = [
            ("https://evil.com", "direct_external"),
            ("//evil.com", "protocol_relative"),
            ("/\\evil.com", "backslash_bypass"),
            ("https://evil.com%00.target.com", "null_byte"),
            ("https://target.com@evil.com", "at_sign_bypass"),
        ]

        for payload, technique in payloads:
            resp = await self._request(
                "GET",
                url,
                params={param: payload},
                follow_redirects=False,
            )

            if not resp:
                continue

            # Check for redirect
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if self._redirects_externally(location, url):
                    return self._make_finding(
                        title=f"Open Redirect via '{param}' Parameter",
                        description=(
                            f"The parameter '{param}' on {url} redirects to an external URL "
                            f"when set to '{payload}'. Technique: {technique.replace('_', ' ')}."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.9,
                        url=url,
                        parameter=param,
                        evidence=(
                            f"Payload: {param}={payload}\n"
                            f"Response: {resp.status_code}\n"
                            f"Location: {location}"
                        ),
                        tags=["open-redirect", technique],
                        impact=(
                            "Open redirects can be chained with phishing attacks, "
                            "OAuth token theft, or SSO bypass."
                        ),
                        remediation=(
                            "Validate redirect URLs against an allowlist of trusted domains. "
                            "Use relative paths instead of full URLs for internal redirects."
                        ),
                    )

            # Check for meta refresh or JS redirect in body
            if resp.status_code == 200:
                body = resp.text[:5000].lower()
                if ("evil.com" in body and
                        ("meta http-equiv" in body or "window.location" in body or "document.location" in body)):
                    return self._make_finding(
                        title=f"Client-Side Open Redirect via '{param}'",
                        description=(
                            f"The parameter '{param}' on {url} is reflected in a client-side redirect."
                        ),
                        severity=Severity.LOW,
                        confidence=0.75,
                        url=url,
                        parameter=param,
                        tags=["open-redirect", "client-side"],
                    )

        return None

    @staticmethod
    def _redirects_externally(location: str, original_url: str) -> bool:
        """Check if a Location header points to a different domain."""
        if not location:
            return False

        original_host = urlparse(original_url).netloc
        if location.startswith("//"):
            location = "https:" + location

        try:
            redirect_host = urlparse(location).netloc
            return bool(redirect_host) and redirect_host != original_host
        except Exception:
            return False
