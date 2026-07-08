"""
Request interceptor.

Provides configurable request modification rules for the proxy,
including header injection, auth insertion, and payload transformation.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from core.proxy_engine import ProxyRequest
from core.session_manager import SessionManager
from core.waf_bypass import WAFBypass

logger = logging.getLogger("hunterengine.proxy.interceptor")


@dataclass
class InterceptRule:
    """A rule defining request modifications."""
    name: str
    url_pattern: str                         # Regex pattern for URL matching
    modifications: dict[str, Any]            # {"headers": {}, "body": b"", ...}
    enabled: bool = True
    match_count: int = 0

    def matches(self, url: str) -> bool:
        return bool(re.search(self.url_pattern, url, re.IGNORECASE))


class RequestInterceptor:
    """
    Configurable request modification layer.

    Applies rules to modify requests passing through the proxy:
      - Inject auth headers per-domain
      - Add WAF bypass headers
      - Transform payloads
      - Add custom headers for testing
    """

    def __init__(
        self,
        session_mgr: Optional[SessionManager] = None,
        waf_bypass: Optional[WAFBypass] = None,
    ) -> None:
        self.session_mgr = session_mgr
        self.waf_bypass = waf_bypass
        self._rules: list[InterceptRule] = []
        self._custom_hooks: list[Callable] = []

    def add_rule(self, rule: InterceptRule) -> None:
        """Add an intercept rule."""
        self._rules.append(rule)
        logger.info(f"Added intercept rule: {rule.name}")

    def remove_rule(self, name: str) -> None:
        """Remove a rule by name."""
        self._rules = [r for r in self._rules if r.name != name]

    def add_hook(self, hook: Callable[[ProxyRequest], Optional[dict]]) -> None:
        """Add a custom request modification hook."""
        self._custom_hooks.append(hook)

    def intercept(self, request: ProxyRequest) -> Optional[dict]:
        """
        Process a request through all rules and hooks.
        Returns modification dict or None.
        """
        modifications: dict[str, Any] = {"headers": {}}

        # 1. Apply matching rules
        for rule in self._rules:
            if rule.enabled and rule.matches(request.url):
                rule.match_count += 1
                if "headers" in rule.modifications:
                    modifications["headers"].update(rule.modifications["headers"])
                if "body" in rule.modifications:
                    modifications["body"] = rule.modifications["body"]
                if "url" in rule.modifications:
                    modifications["url"] = rule.modifications["url"]

        # 2. Auto-inject auth
        if self.session_mgr:
            auth_headers = self.session_mgr.apply_to_request({}, request.host)
            modifications["headers"].update(auth_headers)

        # 3. WAF bypass headers
        if self.waf_bypass:
            bypass_headers = self.waf_bypass.get_headers(request.host)
            # Don't override explicitly set headers
            for k, v in bypass_headers.items():
                if k not in modifications["headers"]:
                    modifications["headers"][k] = v

        # 4. Custom hooks
        for hook in self._custom_hooks:
            try:
                result = hook(request)
                if result and "headers" in result:
                    modifications["headers"].update(result["headers"])
            except Exception as e:
                logger.error(f"Custom intercept hook failed: {e}")

        return modifications if modifications.get("headers") or "body" in modifications else None

    def get_rules(self) -> list[dict]:
        """List all intercept rules with stats."""
        return [
            {
                "name": r.name,
                "url_pattern": r.url_pattern,
                "enabled": r.enabled,
                "match_count": r.match_count,
            }
            for r in self._rules
        ]

    # ── Convenience rule builders ─────────────────────────────────────────

    def add_auth_header_rule(self, name: str, url_pattern: str, header: str, value: str) -> None:
        """Add a rule that injects an auth header for matching URLs."""
        self.add_rule(InterceptRule(
            name=name,
            url_pattern=url_pattern,
            modifications={"headers": {header: value}},
        ))

    def add_custom_header_rule(self, name: str, url_pattern: str, headers: dict[str, str]) -> None:
        """Add a rule that injects custom headers for matching URLs."""
        self.add_rule(InterceptRule(
            name=name,
            url_pattern=url_pattern,
            modifications={"headers": headers},
        ))
