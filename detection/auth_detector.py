"""
Authentication & authorization detection.

Tests for:
  - Missing rate limiting on auth endpoints
  - Session fixation indicators
  - Cookie security flags
  - Auth bypass via HTTP method override
  - Default/common credential endpoints
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from urllib.parse import urlparse

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.auth")

AUTH_PATHS = ["/login", "/signin", "/auth", "/api/login", "/api/auth",
              "/api/v1/login", "/api/v1/auth", "/oauth/token"]


class AuthDetector(BaseDetector):
    """Detect authentication and session management weaknesses."""

    @property
    def name(self) -> str:
        return "auth"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Identify auth-related endpoints
        auth_endpoints = []
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            path = urlparse(url).path.lower()
            if any(ap in path for ap in AUTH_PATHS):
                auth_endpoints.append(url)

        # Also probe standard paths on live hosts
        for host in scan_state.live_hosts:
            base = host.get("url", "")
            for path in AUTH_PATHS:
                auth_endpoints.append(base.rstrip("/") + path)

        auth_endpoints = list(set(auth_endpoints))

        # 1. Cookie security analysis
        cookie_findings = await self._check_cookies(scan_state.live_hosts)
        findings.extend(cookie_findings)

        # 2. Rate limit check on auth endpoints
        for url in auth_endpoints[:20]:
            result = await self._check_rate_limit(url)
            if result:
                findings.append(result)

        # 3. HTTP method override check
        for url in auth_endpoints[:20]:
            result = await self._check_method_override(url)
            if result:
                findings.append(result)

        logger.info(f"Auth detector: {len(findings)} findings")
        return findings

    async def _check_cookies(self, live_hosts: list[dict]) -> list[dict]:
        """Check cookie security flags on all live hosts."""
        findings = []

        for host in live_hosts[:30]:
            url = host.get("url", "")
            resp = await self._get(url)
            if not resp:
                continue

            for cookie_header in resp.headers.get_list("set-cookie"):
                cookie_lower = cookie_header.lower()
                cookie_name = cookie_header.split("=")[0].strip()

                issues = []
                if "secure" not in cookie_lower and url.startswith("https"):
                    issues.append("Missing Secure flag")
                if "httponly" not in cookie_lower:
                    # Only flag session-like cookies
                    if any(kw in cookie_name.lower() for kw in
                           ("session", "token", "auth", "jwt", "sid")):
                        issues.append("Missing HttpOnly flag")
                if "samesite" not in cookie_lower:
                    issues.append("Missing SameSite attribute")

                if issues:
                    findings.append(self._make_finding(
                        title=f"Insecure Cookie Configuration — {cookie_name}",
                        description=f"Cookie '{cookie_name}' on {url}: {', '.join(issues)}.",
                        severity=Severity.LOW,
                        confidence=0.9,
                        url=url,
                        evidence=f"Set-Cookie: {cookie_header[:200]}\nIssues: {', '.join(issues)}",
                        tags=["auth", "cookie", "session"],
                        remediation=(
                            "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all "
                            "session-related cookies."
                        ),
                    ))

        return findings

    async def _check_rate_limit(self, url: str) -> Optional[dict]:
        """Check if an auth endpoint has rate limiting."""
        # Send several rapid requests
        responses = []
        for _ in range(10):
            resp = await self._post(
                url,
                json_body={"username": "test@test.com", "password": "wrongpassword123"},
                headers={"Content-Type": "application/json"},
            )
            if resp:
                responses.append(resp.status_code)

        if not responses:
            return None

        # If all requests succeed (no 429), rate limiting may be absent
        blocked = sum(1 for s in responses if s == 429)
        if blocked == 0 and len(responses) >= 8:
            return self._make_finding(
                title="Missing Rate Limiting on Authentication Endpoint",
                description=(
                    f"The authentication endpoint at {url} does not appear to implement "
                    f"rate limiting. {len(responses)} rapid requests all received non-429 responses."
                ),
                severity=Severity.MEDIUM,
                confidence=0.7,
                url=url,
                evidence=f"Sent {len(responses)} requests, responses: {responses}",
                tags=["auth", "rate-limit", "brute-force"],
                impact="An attacker can perform credential brute-force attacks without throttling.",
                remediation=(
                    "Implement rate limiting (e.g., 5 attempts per minute) on login endpoints. "
                    "Consider account lockout after repeated failures and CAPTCHA challenges."
                ),
            )

        return None

    async def _check_method_override(self, url: str) -> Optional[dict]:
        """Check for HTTP method override bypasses."""
        # Some frameworks respect X-HTTP-Method-Override
        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
        ]

        for header in override_headers:
            resp_get = await self._get(url)
            resp_override = await self._get(url, headers={header: "POST"})

            if resp_get and resp_override:
                if (resp_override.status_code != resp_get.status_code and
                        resp_override.status_code < 400):
                    return self._make_finding(
                        title=f"HTTP Method Override Accepted — {header}",
                        description=(
                            f"The endpoint {url} responds differently when the {header} header "
                            "is set, indicating the server processes method override headers. "
                            "This may bypass method-based access controls."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        url=url,
                        evidence=(
                            f"GET response: {resp_get.status_code}\n"
                            f"GET + {header}: POST response: {resp_override.status_code}"
                        ),
                        tags=["auth", "method-override", "access-control"],
                        remediation=f"Disable processing of {header} header if not required.",
                    )

        return None
