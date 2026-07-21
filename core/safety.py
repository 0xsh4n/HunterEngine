"""Execution safeguards for authorized active security testing.

The AI may suggest hypotheses, but it must never be the authority that decides
whether a request is safe to issue.  This module provides a small, dependency
free policy boundary shared by active test runners.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque
from urllib.parse import urlparse


@dataclass
class SafetyConfig:
    """Limits intended to avoid accidental state changes and target instability."""

    allowed_methods: set[str] = field(default_factory=lambda: {"GET", "HEAD", "OPTIONS"})
    allow_authenticated_requests: bool = False
    max_response_bytes: int = 1_000_000
    max_failures_per_host: int = 4
    max_server_errors_per_host: int = 3
    cooldown_seconds: float = 90.0
    max_request_seconds: float = 15.0
    profile: str = "blackbox"
    max_total_requests: int = 500
    max_requests_per_host: int = 100
    max_consecutive_timeouts: int = 3

    @classmethod
    def from_settings(cls, settings: dict) -> "SafetyConfig":
        raw = (settings.get("safety", {}) or {}).get("active_testing", {}) or {}
        methods = raw.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
        profile = str(raw.get("profile", (settings.get("testing", {}) or {}).get("profile", "blackbox"))).lower()
        # Grey-box testing is opt-in and still remains read-only by default.
        # It enables authenticated headers only when explicitly authorized.
        allow_auth = bool(raw.get("allow_authenticated_requests", False))
        if profile == "greybox":
            allow_auth = allow_auth or bool(raw.get("greybox_authorized", False))
        return cls(
            allowed_methods={str(m).upper() for m in methods},
            allow_authenticated_requests=allow_auth,
            max_response_bytes=max(1024, int(raw.get("max_response_bytes", 1_000_000))),
            max_failures_per_host=max(1, int(raw.get("max_failures_per_host", 4))),
            max_server_errors_per_host=max(1, int(raw.get("max_server_errors_per_host", 3))),
            cooldown_seconds=max(1.0, float(raw.get("cooldown_seconds", 90))),
            max_request_seconds=max(1.0, float(raw.get("max_request_seconds", 15))),
            profile=profile if profile in {"blackbox", "greybox"} else "blackbox",
            max_total_requests=max(1, int(raw.get("max_total_requests", 500))),
            max_requests_per_host=max(1, int(raw.get("max_requests_per_host", 100))),
            max_consecutive_timeouts=max(1, int(raw.get("max_consecutive_timeouts", 3))),
        )


class ExecutionGuard:
    """Host circuit breaker and deterministic request policy."""

    def __init__(self, config: SafetyConfig) -> None:
        self.config = config
        self._failures: dict[str, int] = defaultdict(int)
        self._server_errors: dict[str, int] = defaultdict(int)
        self._open_until: dict[str, float] = {}
        self._requests = 0
        self._host_requests: dict[str, int] = defaultdict(int)
        self._timeouts: dict[str, int] = defaultdict(int)
        self.events: Deque[str] = deque(maxlen=100)

    def allow(self, method: str, url: str) -> tuple[bool, str]:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False, "invalid target URL"
        if self._requests >= self.config.max_total_requests:
            return False, "scan request budget exhausted"
        if self._host_requests[host] >= self.config.max_requests_per_host:
            return False, "host request budget exhausted"
        if method.upper() not in self.config.allowed_methods:
            return False, f"method {method.upper()} is not permitted by active-testing policy"
        until = self._open_until.get(host, 0.0)
        if until > time.monotonic():
            return False, f"host circuit is open for {until - time.monotonic():.0f}s"
        return True, ""

    def record_request(self, url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if host:
            self._requests += 1
            self._host_requests[host] += 1

    def record_response(self, url: str, status_code: int) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return
        if status_code >= 500:
            self._server_errors[host] += 1
            if self._server_errors[host] >= self.config.max_server_errors_per_host:
                self._trip(host, "repeated server errors")
        else:
            self._server_errors[host] = 0
            self._failures[host] = 0
            self._timeouts[host] = 0

    def record_failure(self, url: str, reason: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return
        self._failures[host] += 1
        if "timeout" in reason.lower() or "timed out" in reason.lower():
            self._timeouts[host] += 1
            if self._timeouts[host] >= self.config.max_consecutive_timeouts:
                self._trip(host, "consecutive timeouts")
        if self._failures[host] >= self.config.max_failures_per_host:
            self._trip(host, f"repeated request failures: {reason[:80]}")

    def _trip(self, host: str, reason: str) -> None:
        self._open_until[host] = time.monotonic() + self.config.cooldown_seconds
        self.events.append(f"{host}: circuit opened ({reason})")

    def status(self) -> dict:
        """Serializable health/budget telemetry for reports and checkpoints."""
        return {
            "profile": self.config.profile,
            "requests": self._requests,
            "request_budget": self.config.max_total_requests,
            "hosts": dict(self._host_requests),
            "open_circuits": sorted(self._open_until),
            "events": list(self.events),
        }
