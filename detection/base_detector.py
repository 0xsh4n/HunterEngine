"""
Abstract base detector.

All detection modules inherit from BaseDetector, which provides:
  - Consistent finding format
  - Confidence scoring interface
  - Scope enforcement
  - Rate-limited HTTP helpers
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from core.rate_limiter import RateLimiter
from core.waf_bypass import WAFBypass
from core.scope_loader import ScopeLoader
from core.browser_engine import BrowserEngine

logger = logging.getLogger("hunterengine.detection")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Standardized vulnerability finding."""
    title: str
    description: str
    severity: Severity
    confidence: float                    # 0.0 – 1.0
    detector: str                        # Module name
    url: str
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    reproduction: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "detector": self.detector,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "reproduction": self.reproduction,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


class BaseDetector(ABC):
    """
    Abstract base for all detection modules.

    Subclasses must implement:
      - name: str property
      - run(scan_state) → list[dict]
    """

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        waf_bypass: Optional[WAFBypass] = None,
        scope_loader: Optional[ScopeLoader] = None,
        browser: Optional[BrowserEngine] = None,
        concurrency: int = 10,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.waf_bypass = waf_bypass
        self.scope = scope_loader
        self.browser = browser
        self.concurrency = concurrency
        self._sem = asyncio.Semaphore(concurrency)

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector identifier."""
        ...

    @abstractmethod
    async def run(self, scan_state: Any) -> list[dict]:
        """
        Run detection against the current scan state.

        Args:
            scan_state: ScanState object with endpoints, params, etc.

        Returns:
            List of finding dicts (via Finding.to_dict()).
        """
        ...

    # ── HTTP Helpers ──────────────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[Any] = None,
        json_body: Optional[dict] = None,
        follow_redirects: bool = True,
        timeout: int = 15,
    ) -> Optional[httpx.Response]:
        """Make a rate-limited, WAF-aware HTTP request."""
        # Scope check
        if self.scope and not self.scope.is_in_scope(url):
            return None

        host = urlparse(url).hostname or ""

        # Rate limit
        if self.rate_limiter:
            await self.rate_limiter.acquire(host)

        # Build headers
        merged_headers = {}
        if self.waf_bypass:
            merged_headers.update(self.waf_bypass.get_headers(host))
        if headers:
            merged_headers.update(headers)

        async with self._sem:
            try:
                async with httpx.AsyncClient(
                    verify=False,
                    follow_redirects=follow_redirects,
                    timeout=timeout,
                ) as client:
                    resp = await client.request(
                        method=method,
                        url=url,
                        headers=merged_headers,
                        params=params,
                        data=data,
                        json=json_body,
                    )

                    if self.rate_limiter:
                        self.rate_limiter.report_response(host, resp.status_code)

                    return resp

            except Exception as e:
                logger.debug(f"Request failed {method} {url}: {e}")
                return None

    async def _get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("GET", url, **kwargs)

    async def _post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self._request("POST", url, **kwargs)

    # ── Finding helpers ───────────────────────────────────────────────────

    def _make_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        confidence: float,
        url: str,
        **kwargs,
    ) -> dict:
        """Create a standardized finding dict."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity,
            confidence=min(max(confidence, 0.0), 1.0),
            detector=self.name,
            url=url,
            **kwargs,
        )
        return finding.to_dict()

    def _truncate_evidence(self, text: str, max_len: int = 2000) -> str:
        """Truncate evidence for report readability."""
        if len(text) <= max_len:
            return text
        return text[:max_len] + f"\n... [truncated, {len(text)} bytes total]"
