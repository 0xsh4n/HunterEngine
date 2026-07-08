"""
Playwright browser controller.

Manages a headless Chromium instance routed through the internal
mitmproxy for SPA rendering, JS execution, and evidence screenshots.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
except ImportError:
    async_playwright = None  # type: ignore


@dataclass
class BrowserConfig:
    headless: bool = True
    proxy_url: str = "http://127.0.0.1:8080"
    use_proxy: bool = True
    page_timeout: int = 30_000
    screenshot_dir: str = "data/screenshots"
    chromium_args: list[str] = field(default_factory=lambda: [
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
    ])
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1920, "height": 1080})


class BrowserEngine:
    """
    Headless Chromium manager built on Playwright.

    Capabilities:
      - Render JS-heavy SPAs (React, Next.js, Angular, Vue)
      - Execute JS in page context
      - Capture screenshots for evidence
      - Fill forms, click elements
      - Route through internal mitmproxy
    """

    def __init__(self, config: Optional[BrowserConfig] = None) -> None:
        if async_playwright is None:
            raise ImportError("playwright is required — run: pip install playwright && playwright install chromium")
        self.config = config or BrowserConfig()
        self._pw: Any = None
        self._browser: Optional[Browser] = None

        Path(self.config.screenshot_dir).mkdir(parents=True, exist_ok=True)

    async def start(self) -> None:
        """Launch the browser."""
        self._pw = await async_playwright().start()
        launch_args = list(self.config.chromium_args)
        if self.config.use_proxy:
            launch_args.append(f"--ignore-certificate-errors")

        proxy_settings = None
        if self.config.use_proxy:
            proxy_settings = {"server": self.config.proxy_url}

        self._browser = await self._pw.chromium.launch(
            headless=self.config.headless,
            args=launch_args,
            proxy=proxy_settings,
        )

    async def stop(self) -> None:
        """Close the browser and Playwright."""
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def new_context(
        self,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> BrowserContext:
        """Create a new browser context with optional auth state."""
        if not self._browser:
            raise RuntimeError("Browser not started — call start() first")

        context = await self._browser.new_context(
            viewport=self.config.viewport,
            ignore_https_errors=True,
        )
        context.set_default_timeout(self.config.page_timeout)

        if cookies:
            await context.add_cookies(cookies)
        if headers:
            await context.set_extra_http_headers(headers)

        return context

    async def fetch_rendered(
        self,
        url: str,
        wait_selector: Optional[str] = None,
        wait_ms: int = 2000,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """
        Navigate to a URL, wait for JS rendering, and return page content.

        Returns:
            dict with keys: url, status, content, title, links, scripts
        """
        context = await self.new_context(cookies=cookies, headers=headers)
        page = await context.new_page()

        try:
            response = await page.goto(url, wait_until="networkidle")
            status = response.status if response else 0

            if wait_selector:
                try:
                    await page.wait_for_selector(wait_selector, timeout=self.config.page_timeout)
                except Exception:
                    pass
            else:
                await page.wait_for_timeout(wait_ms)

            content = await page.content()
            title = await page.title()

            # Extract links and scripts
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            scripts = await page.eval_on_selector_all(
                "script[src]",
                "els => els.map(e => e.src)"
            )

            return {
                "url": page.url,
                "status": status,
                "content": content,
                "title": title,
                "links": links,
                "scripts": scripts,
            }
        finally:
            await context.close()

    async def screenshot(
        self,
        url: str,
        filename: str,
        full_page: bool = True,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Path:
        """Take a screenshot of a URL. Returns the saved file path."""
        context = await self.new_context(cookies=cookies, headers=headers)
        page = await context.new_page()

        try:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(1000)

            path = Path(self.config.screenshot_dir) / filename
            await page.screenshot(path=str(path), full_page=full_page)
            return path
        finally:
            await context.close()

    async def execute_js(
        self,
        url: str,
        script: str,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> Any:
        """Navigate to a URL and execute JS in the page context."""
        context = await self.new_context(cookies=cookies, headers=headers)
        page = await context.new_page()

        try:
            await page.goto(url, wait_until="networkidle")
            result = await page.evaluate(script)
            return result
        finally:
            await context.close()

    async def get_page_resources(
        self,
        url: str,
        cookies: Optional[list[dict]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> list[dict[str, str]]:
        """Capture all network requests made during page load."""
        context = await self.new_context(cookies=cookies, headers=headers)
        page = await context.new_page()

        resources: list[dict[str, str]] = []

        def on_response(response):
            resources.append({
                "url": response.url,
                "status": str(response.status),
                "content_type": response.headers.get("content-type", ""),
            })

        page.on("response", on_response)

        try:
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(2000)
            return resources
        finally:
            await context.close()
