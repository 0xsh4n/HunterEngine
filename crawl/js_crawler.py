"""
Playwright-based SPA crawler.

Renders JavaScript-heavy pages (React, Next.js, Angular, Vue)
to discover endpoints invisible to static crawlers.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from core.browser_engine import BrowserEngine
from core.scope_loader import ScopeLoader

logger = logging.getLogger("hunterengine.crawl.js")


class JSCrawler:
    """Headless browser crawler for single-page applications."""

    SPA_MARKERS = (
        "react", "angular", "vue.js", "vue", "next.js", "nuxt.js", "svelte",
        "ember", "backbone", "remix", "gatsby",
    )

    def __init__(
        self,
        browser: BrowserEngine,
        scope_loader: Optional[ScopeLoader] = None,
        max_pages: int = 100,
        tech_stack: Optional[dict] = None,
    ) -> None:
        self.browser = browser
        self.scope = scope_loader
        self.max_pages = max_pages
        self.tech_stack = tech_stack or {}

    async def crawl_spa_targets(self, live_hosts: list[dict]) -> list[dict]:
        """
        Crawl live hosts that are detected as SPAs.

        Uses live_hosts.tech, is_spa flag, and optional tech_stack profiles.
        """
        spa_hosts = [h for h in live_hosts if self._is_spa_host(h)]

        if not spa_hosts:
            # Fallback: if tech detection missed, still crawl first few live hosts
            # when js_rendering was explicitly requested by the caller.
            logger.info("No SPA tech markers — probing top live hosts with JS crawler")
            spa_hosts = live_hosts[:5]

        if not spa_hosts:
            logger.info("No SPA targets detected — skipping JS crawl")
            return []

        logger.info(f"JS crawling {len(spa_hosts)} SPA targets")
        all_endpoints: list[dict] = []

        for host in spa_hosts[:20]:  # Cap concurrent browser sessions
            url = host.get("url", "")
            try:
                endpoints = await self._crawl_single(url)
                all_endpoints.extend(endpoints)
            except Exception as e:
                logger.error(f"JS crawl failed for {url}: {e}")

        return all_endpoints

    def _is_spa_host(self, host: dict) -> bool:
        if host.get("is_spa"):
            return True
        tech = [str(t).lower() for t in (host.get("tech") or [])]
        if any(marker in t for t in tech for marker in self.SPA_MARKERS):
            return True
        url = host.get("url", "")
        profile = self.tech_stack.get(url)
        if profile is None:
            return False
        if getattr(profile, "is_spa", False):
            return True
        frameworks = [str(f).lower() for f in (getattr(profile, "frameworks", None) or [])]
        if isinstance(profile, dict):
            frameworks = [str(f).lower() for f in (profile.get("frameworks") or [])]
            if profile.get("is_spa"):
                return True
        return any(marker in f for f in frameworks for marker in self.SPA_MARKERS)

    async def _crawl_single(self, start_url: str) -> list[dict]:
        """Crawl a single SPA by rendering pages and following links."""
        visited: set[str] = set()
        to_visit: list[str] = [start_url]
        endpoints: list[dict] = []
        base_domain = urlparse(start_url).netloc

        while to_visit and len(visited) < self.max_pages:
            url = to_visit.pop(0)
            if url in visited:
                continue

            # Scope check
            if self.scope and not self.scope.is_in_scope(url):
                continue

            visited.add(url)

            try:
                result = await self.browser.fetch_rendered(url, wait_ms=3000)

                endpoints.append({
                    "url": result["url"],
                    "method": "GET",
                    "source": "js_crawler",
                    "title": result.get("title", ""),
                    "status": result.get("status", 0),
                })

                # Extract API calls from rendered content
                api_endpoints = self._extract_api_calls(result.get("content", ""), start_url)
                endpoints.extend(api_endpoints)

                # Queue discovered links
                for link in result.get("links", []):
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain and link not in visited:
                        to_visit.append(link)

                # Queue JS file endpoints
                for script in result.get("scripts", []):
                    if script not in visited:
                        endpoints.append({
                            "url": script,
                            "method": "GET",
                            "source": "js_crawler_script",
                        })

            except Exception as e:
                logger.debug(f"Failed to render {url}: {e}")

        logger.info(f"JS crawl of {start_url}: {len(endpoints)} endpoints from {len(visited)} pages")
        return endpoints

    def _extract_api_calls(self, html: str, base_url: str) -> list[dict]:
        """Extract API endpoint references from rendered HTML/JS."""
        endpoints = []
        seen = set()

        # Common API URL patterns in JS
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.put\(["\']([^"\']+)["\']',
            r'\.delete\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*?open\(["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                groups = match.groups()
                if len(groups) == 2:
                    method, path = groups
                else:
                    method, path = "GET", groups[0]

                if path.startswith("/"):
                    full_url = urljoin(base_url, path)
                elif path.startswith("http"):
                    full_url = path
                else:
                    continue

                if full_url not in seen:
                    seen.add(full_url)
                    endpoints.append({
                        "url": full_url,
                        "method": method.upper() if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH") else "GET",
                        "source": "js_api_extraction",
                    })

        return endpoints
