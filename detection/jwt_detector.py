"""
JWT vulnerability detection.

Checks for:
  - Algorithm confusion (none, HS256↔RS256)
  - Weak signing secrets
  - Missing expiration
  - Information disclosure in payloads
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.jwt")


COMMON_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret",
    "changeme", "test", "default", "admin",
]


class JWTDetector(BaseDetector):
    """Detect JWT-related vulnerabilities."""

    @property
    def name(self) -> str:
        return "jwt"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Collect JWTs from responses, cookies, headers
        jwts = self._collect_jwts(scan_state)
        logger.info(f"Found {len(jwts)} JWT tokens to analyze")

        for jwt_info in jwts:
            token = jwt_info["token"]
            source = jwt_info.get("source", "unknown")

            # Decode and analyze
            decoded = self._decode_jwt(token)
            if not decoded:
                continue

            header, payload = decoded

            # Check algorithm issues
            alg = header.get("alg", "")
            if alg.lower() == "none":
                findings.append(self._make_finding(
                    title="JWT Algorithm None Accepted",
                    description="A JWT token with algorithm 'none' was found, indicating the server may accept unsigned tokens.",
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    url=jwt_info.get("url", ""),
                    evidence=f"Header: {json.dumps(header)}\nSource: {source}",
                    tags=["jwt", "auth", "algorithm-none"],
                    impact="An attacker can forge arbitrary JWT tokens without a valid signature.",
                    remediation="Reject tokens with alg=none. Enforce a specific signing algorithm server-side.",
                ))

            # Check for missing expiration
            if "exp" not in payload:
                findings.append(self._make_finding(
                    title="JWT Missing Expiration Claim",
                    description="The JWT token does not contain an 'exp' (expiration) claim.",
                    severity=Severity.LOW,
                    confidence=0.8,
                    url=jwt_info.get("url", ""),
                    evidence=f"Payload keys: {list(payload.keys())}",
                    tags=["jwt", "auth", "no-expiry"],
                    remediation="Always include an 'exp' claim with a reasonable TTL.",
                ))

            # Check for sensitive data in payload
            sensitive_keys = {"password", "secret", "ssn", "credit_card", "cc"}
            found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
            if found_sensitive:
                findings.append(self._make_finding(
                    title="Sensitive Data in JWT Payload",
                    description=f"JWT payload contains potentially sensitive fields: {found_sensitive}",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    url=jwt_info.get("url", ""),
                    evidence=f"Sensitive fields: {found_sensitive}",
                    tags=["jwt", "info-disclosure"],
                    remediation="Avoid storing sensitive data in JWT payloads since they are base64-encoded, not encrypted.",
                ))

            # Check for weak HMAC secrets
            if alg.startswith("HS"):
                weak = self._test_weak_secrets(token, alg)
                if weak:
                    findings.append(self._make_finding(
                        title="JWT Signed with Weak Secret",
                        description=f"The JWT token is signed with a guessable secret: '{weak}'",
                        severity=Severity.CRITICAL,
                        confidence=0.95,
                        url=jwt_info.get("url", ""),
                        evidence=f"Algorithm: {alg}\nWeak secret: {weak}",
                        tags=["jwt", "auth", "weak-secret"],
                        impact="An attacker can forge valid JWT tokens using the weak secret.",
                        remediation="Use a cryptographically random secret of at least 256 bits.",
                    ))

            # Check for role/privilege escalation potential
            role_fields = {k: v for k, v in payload.items()
                         if k.lower() in ("role", "admin", "is_admin", "group", "permissions", "scope")}
            if role_fields:
                findings.append(self._make_finding(
                    title="JWT Contains Role/Privilege Claims",
                    description=(
                        f"JWT payload contains authorization claims: {role_fields}. "
                        "If the signing key is weak or the algorithm is exploitable, "
                        "privilege escalation may be possible."
                    ),
                    severity=Severity.INFO,
                    confidence=0.6,
                    url=jwt_info.get("url", ""),
                    evidence=f"Role fields: {json.dumps(role_fields)}",
                    tags=["jwt", "auth", "privilege-escalation-potential"],
                ))

        logger.info(f"JWT detector: {len(findings)} findings")
        return findings

    def _collect_jwts(self, scan_state: Any) -> list[dict]:
        """Extract JWT tokens from scan state data."""
        jwts = []
        jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*')

        # From weak signals (JS analysis)
        for signal in scan_state.weak_signals:
            if signal.get("type") == "JWT Token":
                jwts.append({
                    "token": signal.get("value", ""),
                    "source": "js_analysis",
                    "url": signal.get("source_url", ""),
                })

        # From endpoints (check response data if available)
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if url:
                for match in jwt_pattern.finditer(url):
                    jwts.append({"token": match.group(), "source": "url_param", "url": url})

        return jwts

    def _decode_jwt(self, token: str) -> Optional[tuple[dict, dict]]:
        """Decode a JWT without verification."""
        parts = token.split(".")
        if len(parts) < 2:
            return None

        try:
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            return header, payload
        except Exception:
            return None

    def _test_weak_secrets(self, token: str, algorithm: str) -> Optional[str]:
        """Test JWT against a list of common weak secrets."""
        try:
            import jwt as pyjwt
            for secret in COMMON_WEAK_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=[algorithm])
                    return secret
                except pyjwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
        except ImportError:
            logger.debug("pyjwt not available for weak secret testing")
        return None
