"""
Passive response analyzer.

Scans every response passing through the proxy for
security-relevant patterns without making additional requests.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from core.proxy_engine import ProxyRequest, ProxyResponse

logger = logging.getLogger("hunterengine.proxy.analyzer")


@dataclass
class PassiveFinding:
    """A finding from passive response analysis."""
    title: str
    description: str
    severity: str
    url: str
    evidence: str
    category: str
    request_id: int


# Patterns to scan for in response bodies
BODY_PATTERNS: list[tuple[str, str, str, str]] = [
    # (regex, title, severity, category)
    (r'(?:sql|mysql|postgres|oracle|sqlite).*?(?:error|syntax|exception)', "SQL Error Disclosure", "medium", "info-disclosure"),
    (r'(?:stack\s*trace|traceback|at\s+\w+\.\w+\()', "Stack Trace Disclosure", "low", "info-disclosure"),
    (r'(?:php\s+(?:fatal|warning|notice|parse\s+error))', "PHP Error Disclosure", "low", "info-disclosure"),
    (r'(?:exception\s+in\s+thread|java\.lang\.\w+exception)', "Java Exception Disclosure", "low", "info-disclosure"),
    (r'server:\s*(?:apache|nginx|iis)[\s/][\d.]+', "Server Version Disclosure", "info", "info-disclosure"),
    (r'x-powered-by:\s*.+', "Technology Disclosure via X-Powered-By", "info", "info-disclosure"),
    (r'(?:debug|verbose|trace)\s*(?:mode|=\s*true|:\s*true)', "Debug Mode Enabled", "medium", "misconfiguration"),
    (r'(?:internal\s+server\s+error|500\s+error)', "Internal Server Error", "info", "error"),
    (r'(?:access[_-]?denied|permission[_-]?denied|forbidden|unauthorized)', "Access Control Response", "info", "access-control"),
]

# Security headers to check
SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("strict-transport-security", "Missing HSTS Header", "low"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "info"),
    ("x-frame-options", "Missing X-Frame-Options", "info"),
    ("referrer-policy", "Missing Referrer-Policy", "info"),
    ("permissions-policy", "Missing Permissions-Policy", "info"),
]


class ResponseAnalyzer:
    """Passively analyze all proxied responses for security issues."""

    def __init__(self) -> None:
        self._findings: list[PassiveFinding] = []
        self._seen_patterns: set[str] = set()  # Dedup key

    def analyze(self, request: ProxyRequest, response: ProxyResponse) -> list[PassiveFinding]:
        """
        Analyze a response for security-relevant patterns.

        Called by the proxy's response hook on every response.
        """
        new_findings: list[PassiveFinding] = []

        # Only analyze text responses
        content_type = response.content_type.lower()
        if not any(ct in content_type for ct in ("text/", "json", "xml", "javascript")):
            return new_findings

        body_text = response.body.decode("utf-8", errors="ignore")

        # 1. Body pattern scanning
        for pattern, title, severity, category in BODY_PATTERNS:
            dedup_key = f"{title}:{request.host}"
            if dedup_key in self._seen_patterns:
                continue

            if re.search(pattern, body_text, re.IGNORECASE):
                self._seen_patterns.add(dedup_key)
                match = re.search(pattern, body_text, re.IGNORECASE)
                evidence = match.group(0)[:200] if match else ""

                finding = PassiveFinding(
                    title=title,
                    description=f"Passive scan detected {title.lower()} in response from {request.url}",
                    severity=severity,
                    url=request.url,
                    evidence=evidence,
                    category=category,
                    request_id=request.id,
                )
                new_findings.append(finding)

        # 2. Security header checks (only on HTML responses)
        if "text/html" in content_type:
            for header_name, title, severity in SECURITY_HEADERS:
                dedup_key = f"{title}:{request.host}"
                if dedup_key in self._seen_patterns:
                    continue

                if header_name not in {k.lower() for k in response.headers}:
                    self._seen_patterns.add(dedup_key)
                    new_findings.append(PassiveFinding(
                        title=title,
                        description=f"{title} on {request.host}",
                        severity=severity,
                        url=request.url,
                        evidence=f"Header '{header_name}' not present in response",
                        category="missing-header",
                        request_id=request.id,
                    ))

        # 3. Sensitive data in response
        self._check_sensitive_data(body_text, request, new_findings)

        self._findings.extend(new_findings)
        return new_findings

    def _check_sensitive_data(
        self,
        body: str,
        request: ProxyRequest,
        findings: list[PassiveFinding],
    ) -> None:
        """Check for sensitive data patterns in response body."""
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address", 5),
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token", 1),
        ]

        for pattern, data_type, min_matches in sensitive_patterns:
            dedup_key = f"sensitive:{data_type}:{request.host}"
            if dedup_key in self._seen_patterns:
                continue

            matches = re.findall(pattern, body)
            if len(matches) >= min_matches:
                self._seen_patterns.add(dedup_key)
                findings.append(PassiveFinding(
                    title=f"{data_type} Exposure in Response",
                    description=f"Found {len(matches)} {data_type.lower()}(s) in response from {request.url}",
                    severity="low",
                    url=request.url,
                    evidence=f"Found {len(matches)} instances (sample: {matches[0][:50]}...)",
                    category="data-exposure",
                    request_id=request.id,
                ))

    def get_findings(self) -> list[PassiveFinding]:
        """Get all passive findings."""
        return list(self._findings)

    def get_findings_by_severity(self, severity: str) -> list[PassiveFinding]:
        """Filter findings by severity."""
        return [f for f in self._findings if f.severity == severity]

    def get_stats(self) -> dict:
        """Return passive analysis statistics."""
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        for f in self._findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            "total_findings": len(self._findings),
            "by_severity": by_severity,
            "by_category": by_category,
        }
