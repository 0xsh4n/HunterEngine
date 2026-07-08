"""
Core mitmproxy management.

High-level wrapper around ProxyEngine that manages lifecycle,
adds default hooks for logging and scope enforcement, and
provides a clean interface for other modules.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.proxy_engine import ProxyEngine, ProxyConfig, ProxyRequest, ProxyResponse
from core.scope_loader import ScopeLoader

logger = logging.getLogger("hunterengine.proxy.core")


class MitmCore:
    """
    High-level proxy manager.

    Wraps ProxyEngine with scope enforcement, default logging,
    and a clean API for request/response interception.
    """

    def __init__(
        self,
        proxy: ProxyEngine,
        scope: Optional[ScopeLoader] = None,
    ) -> None:
        self.proxy = proxy
        self.scope = scope
        self._setup_default_hooks()

    def _setup_default_hooks(self) -> None:
        """Register default request/response hooks."""

        def scope_enforcer(req: ProxyRequest) -> Optional[dict]:
            """Block requests outside scope."""
            if self.scope and not self.scope.is_in_scope(req.url):
                logger.warning(f"Blocked out-of-scope request: {req.url}")
                return None  # Could modify to return a block response
            return None

        def request_logger(req: ProxyRequest) -> Optional[dict]:
            """Log all proxied requests."""
            logger.debug(f"PROXY → {req.method} {req.url}")
            return None

        def response_logger(req: ProxyRequest, resp: ProxyResponse) -> None:
            """Log all proxied responses."""
            logger.debug(f"PROXY ← {resp.status_code} {req.url} ({len(resp.body)} bytes)")

        self.proxy.on_request(scope_enforcer)
        self.proxy.on_request(request_logger)
        self.proxy.on_response(response_logger)

    async def start(self) -> None:
        """Start the proxy."""
        await self.proxy.start()

    async def stop(self) -> None:
        """Stop the proxy."""
        await self.proxy.stop()

    def get_history(self, **kwargs) -> list[tuple[ProxyRequest, Optional[ProxyResponse]]]:
        """Query proxy history."""
        return self.proxy.get_history(**kwargs)

    async def replay(self, request: ProxyRequest, modifications: Optional[dict] = None) -> Optional[ProxyResponse]:
        """Replay a captured request."""
        return await self.proxy.replay(request, modifications)

    def search_history(self, keyword: str) -> list[tuple[ProxyRequest, Optional[ProxyResponse]]]:
        """Search proxy history for a keyword in URL or response body."""
        results = []
        for req, resp in self.proxy.get_history(limit=1000):
            if keyword.lower() in req.url.lower():
                results.append((req, resp))
            elif resp and keyword.encode().lower() in resp.body.lower():
                results.append((req, resp))
        return results
