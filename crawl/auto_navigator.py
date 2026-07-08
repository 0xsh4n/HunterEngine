"""
Integrated browser auto-crawler (OWASP ZAP–style).

Opens a **visible** Chromium window and autonomously navigates the target:
  - Clicks every discoverable link, button, menu, tab, accordion
  - Auto-fills forms with intelligent test data
  - Intercepts all network traffic (XHR / fetch / WebSocket / resource loads)
  - Tracks pushState / replaceState for SPA client-side routes
  - Watches DOM mutations for dynamically injected content
  - Stays strictly within the defined scope
  - Feeds every discovered URL back into the scan pipeline
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import random
import re
import string
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Route,
        Request as PWRequest,
        Response as PWResponse,
    )
except ImportError:
    async_playwright = None  # type: ignore

from core.scope_loader import ScopeLoader

logger = logging.getLogger("hunterengine.crawl.auto_navigator")
console = Console()


# ── Configuration ─────────────────────────────────────────────────────────


@dataclass
class NavigatorConfig:
    """Auto-navigator tuning knobs."""

    headless: bool = False                # False = visible browser (ZAP-style)
    max_pages: int = 500                  # Stop after visiting this many pages
    max_depth: int = 10                   # Max click-depth from the seed URL
    page_timeout: int = 30_000            # Per-page navigation timeout (ms)
    action_delay: tuple[float, float] = (0.3, 1.2)  # Human-like pause between actions
    form_submit: bool = True              # Auto-fill and submit forms
    click_buttons: bool = True            # Click buttons and interactive elements
    click_navigation: bool = True         # Click nav menus, dropdowns, tabs
    intercept_network: bool = True        # Capture XHR / fetch / WS traffic
    screenshot_on_new_page: bool = True   # Screenshot each unique page
    screenshot_dir: str = "data/screenshots"
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1366, "height": 768})
    chromium_args: list[str] = field(default_factory=lambda: [
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
    ])
    proxy_url: str = ""                   # Optional proxy (e.g. mitmproxy)
    user_agent: str = ""                  # Custom UA; empty = default Chromium


# ── Intelligent form-fill data ────────────────────────────────────────────


FORM_FILL_MAP: dict[str, str] = {
    "email":    "testuser@hunterengine.local",
    "username": "hunterengine_test",
    "password": "T3st!Pass#2025",
    "name":     "Hunter Tester",
    "first":    "Hunter",
    "last":     "Tester",
    "phone":    "+1-555-0100",
    "search":   "test",
    "query":    "hunterengine",
    "url":      "https://hunterengine.local/callback",
    "company":  "HunterEngine Security",
    "address":  "123 Security Blvd",
    "city":     "San Francisco",
    "state":    "CA",
    "zip":      "94105",
    "country":  "US",
    "comment":  "Automated security scan — authorized testing.",
    "message":  "Automated security scan — authorized testing.",
}


def _form_value_for(field_name: str, field_type: str) -> str:
    """Pick a plausible value based on input name / type."""
    name_lower = field_name.lower()
    for key, value in FORM_FILL_MAP.items():
        if key in name_lower:
            return value
    # Fall back by HTML input type
    type_map = {
        "email":    FORM_FILL_MAP["email"],
        "password": FORM_FILL_MAP["password"],
        "tel":      FORM_FILL_MAP["phone"],
        "url":      FORM_FILL_MAP["url"],
        "number":   "42",
        "date":     "2025-01-15",
        "color":    "#4a90d9",
    }
    if field_type in type_map:
        return type_map[field_type]
    return "huntertest"


# ── Navigator ─────────────────────────────────────────────────────────────


class AutoNavigator:
    """
    OWASP ZAP–style integrated browser auto-crawler.

    Opens a headed Chromium window and autonomously explores the target,
    feeding every discovered URL and network request back as endpoints.
    """

    def __init__(
        self,
        config: Optional[NavigatorConfig] = None,
        scope_loader: Optional[ScopeLoader] = None,
    ) -> None:
        if async_playwright is None:
            raise ImportError(
                "playwright is required — run: pip install playwright && playwright install chromium"
            )
        self.config = config or NavigatorConfig()
        self.scope = scope_loader

        # Discovery state
        self._visited_urls: set[str] = set()
        self._queued_urls: list[tuple[str, int]] = []      # (url, depth)
        self._captured_endpoints: list[dict] = []
        self._captured_js_files: list[str] = []
        self._network_requests: list[dict] = []
        self._forms_submitted: set[str] = set()
        self._screenshots_taken: int = 0
        self._page_count: int = 0
        self._start_time: float = 0.0

        # Playwright handles
        self._pw: Any = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

    # ── Public API ────────────────────────────────────────────────────────

    async def crawl(self, seed_urls: list[str]) -> dict:
        """
        Auto-crawl from seed URLs.  Opens a visible browser and navigates
        autonomously.

        Returns:
            {
                "endpoints":        [{"url": str, "method": str, "source": str, ...}],
                "js_files":         [str],
                "network_requests": [{"url": str, "method": str, "status": int, ...}],
                "pages_visited":    int,
                "forms_submitted":  int,
                "screenshots":      int,
            }
        """
        self._start_time = time.time()

        # Seed the queue
        for url in seed_urls:
            if self._is_in_scope(url):
                self._queued_urls.append((url, 0))

        if not self._queued_urls:
            logger.warning("No in-scope seed URLs provided")
            return self._results()

        await self._launch_browser()

        try:
            # Live Rich dashboard in the terminal alongside the visible browser
            with Live(self._build_dashboard(), console=console, refresh_per_second=2) as live:
                while self._queued_urls and self._page_count < self.config.max_pages:
                    url, depth = self._queued_urls.pop(0)

                    if url in self._visited_urls:
                        continue
                    if depth > self.config.max_depth:
                        continue
                    if not self._is_in_scope(url):
                        continue

                    self._visited_urls.add(url)
                    self._page_count += 1

                    try:
                        await self._navigate_and_explore(url, depth)
                    except Exception as exc:
                        logger.debug("Failed to explore %s: %s", url, exc)

                    live.update(self._build_dashboard())

        finally:
            await self._close_browser()

        logger.info(
            "Auto-crawl complete: %d pages, %d endpoints, %d network requests",
            self._page_count,
            len(self._captured_endpoints),
            len(self._network_requests),
        )
        return self._results()

    # ── Browser lifecycle ─────────────────────────────────────────────────

    async def _launch_browser(self) -> None:
        """Launch headed Chromium with optional proxy routing."""
        self._pw = await async_playwright().start()

        launch_args = list(self.config.chromium_args)
        proxy = None
        if self.config.proxy_url:
            proxy = {"server": self.config.proxy_url}
            launch_args.append("--ignore-certificate-errors")

        self._browser = await self._pw.chromium.launch(
            headless=self.config.headless,
            args=launch_args,
            proxy=proxy,
        )

        self._context = await self._browser.new_context(
            viewport=self.config.viewport,
            ignore_https_errors=True,
            user_agent=self.config.user_agent or None,
        )
        self._context.set_default_timeout(self.config.page_timeout)

        self._page = await self._context.new_page()

        # ── Network interception ──────────────────────────────────────────
        if self.config.intercept_network:
            self._page.on("request", self._on_request)
            self._page.on("response", self._on_response)

    async def _close_browser(self) -> None:
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    # ── Core navigation loop ──────────────────────────────────────────────

    async def _navigate_and_explore(self, url: str, depth: int) -> None:
        """Navigate to a page, then explore all interactive elements."""
        page = self._page
        if not page:
            return

        logger.info("[depth=%d] Navigating → %s", depth, url)

        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.config.page_timeout)
        except Exception as exc:
            logger.debug("Navigation failed for %s: %s", url, exc)
            return

        # Wait for dynamic content to settle
        await self._wait_for_idle(page)

        status = response.status if response else 0
        current_url = page.url

        # Record as endpoint
        self._add_endpoint(current_url, "GET", "auto_navigator", status=status)

        # Screenshot
        if self.config.screenshot_on_new_page:
            await self._take_screenshot(page, current_url)

        # ── Extract links from the page ───────────────────────────────────
        await self._extract_links(page, depth)

        # ── Extract and submit forms ──────────────────────────────────────
        if self.config.form_submit:
            await self._process_forms(page, current_url, depth)

        # ── Click interactive elements (buttons, tabs, accordions) ────────
        if self.config.click_buttons:
            await self._click_interactive_elements(page, depth)

        # ── Click navigation elements (nav links, dropdowns) ─────────────
        if self.config.click_navigation:
            await self._click_navigation_elements(page, depth)

        # ── Extract JS files ──────────────────────────────────────────────
        await self._extract_scripts(page)

        # ── Detect SPA routes via inline JS ───────────────────────────────
        await self._detect_spa_routes(page, current_url, depth)

    async def _wait_for_idle(self, page: Page, timeout: int = 5000) -> None:
        """Wait for the page to become relatively idle (network + DOM)."""
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass
        # Small extra delay for JS rendering
        delay = random.uniform(*self.config.action_delay)
        await asyncio.sleep(delay)

    # ── Link extraction ───────────────────────────────────────────────────

    async def _extract_links(self, page: Page, depth: int) -> None:
        """Extract all <a href> links and queue them."""
        try:
            links = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({ href: e.href, text: e.textContent.trim().substring(0, 80) }))"
            )
        except Exception:
            return

        for link_info in links:
            href = link_info.get("href", "")
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            normalized = self._normalize_url(href)
            if normalized and normalized not in self._visited_urls:
                self._enqueue(normalized, depth + 1)

    # ── Form processing ───────────────────────────────────────────────────

    async def _process_forms(self, page: Page, page_url: str, depth: int) -> None:
        """Find all forms, fill them intelligently, and submit."""
        try:
            forms = await page.query_selector_all("form")
        except Exception:
            return

        for form in forms:
            try:
                form_id = await self._form_fingerprint(form, page_url)
                if form_id in self._forms_submitted:
                    continue
                self._forms_submitted.add(form_id)

                # Get action URL
                action = await form.get_attribute("action") or page_url
                method = (await form.get_attribute("method") or "GET").upper()
                action_url = urljoin(page_url, action)

                if not self._is_in_scope(action_url):
                    continue

                # Fill all input fields
                inputs = await form.query_selector_all(
                    "input:not([type='hidden']):not([type='submit']):not([type='button']):not([type='image']):not([type='reset']), "
                    "textarea, select"
                )

                for inp in inputs:
                    await self._fill_input(inp)

                # Submit the form
                logger.info("  ↳ Submitting form → %s [%s]", action_url, method)

                submit_btn = await form.query_selector(
                    "button[type='submit'], input[type='submit'], button:not([type])"
                )

                if submit_btn:
                    try:
                        async with page.expect_navigation(timeout=10_000, wait_until="domcontentloaded"):
                            await submit_btn.click()
                    except Exception:
                        # Navigation may not happen (AJAX form)
                        await asyncio.sleep(1.0)
                else:
                    # No submit button — try pressing Enter on the last input
                    if inputs:
                        try:
                            async with page.expect_navigation(timeout=10_000, wait_until="domcontentloaded"):
                                await inputs[-1].press("Enter")
                        except Exception:
                            await asyncio.sleep(1.0)

                self._add_endpoint(action_url, method, "auto_navigator_form")

                # Capture the resulting page
                await self._wait_for_idle(page)
                new_url = page.url
                if new_url not in self._visited_urls:
                    self._enqueue(new_url, depth + 1)

                # Go back to continue exploring other forms
                try:
                    await page.go_back(wait_until="domcontentloaded", timeout=8_000)
                    await self._wait_for_idle(page)
                except Exception:
                    pass

            except Exception as exc:
                logger.debug("Form processing error: %s", exc)

    async def _fill_input(self, element) -> None:
        """Fill a single input/textarea/select with intelligent test data."""
        try:
            tag = await element.evaluate("el => el.tagName.toLowerCase()")
            inp_type = (await element.get_attribute("type") or "text").lower()
            inp_name = (await element.get_attribute("name") or
                        await element.get_attribute("id") or
                        await element.get_attribute("placeholder") or "")

            if tag == "select":
                # Pick the second option if available (first is often a placeholder)
                options = await element.query_selector_all("option")
                if len(options) > 1:
                    value = await options[1].get_attribute("value")
                    if value:
                        await element.select_option(value=value)
                return

            if tag == "textarea":
                await element.fill(FORM_FILL_MAP.get("comment", "test"))
                return

            if inp_type == "checkbox":
                checked = await element.is_checked()
                if not checked:
                    await element.check()
                return

            if inp_type == "radio":
                await element.check()
                return

            if inp_type == "file":
                return  # Skip file uploads

            # Text-like inputs
            value = _form_value_for(inp_name, inp_type)
            await element.fill(value)

        except Exception:
            pass  # Element may have become stale

    async def _form_fingerprint(self, form, page_url: str) -> str:
        """Create a stable fingerprint for form deduplication."""
        try:
            action = await form.get_attribute("action") or ""
            method = await form.get_attribute("method") or "GET"
            inputs = await form.eval_on_selector_all(
                "input, textarea, select",
                "els => els.map(e => e.name || e.id || '').join(',')"
            )
            raw = f"{page_url}|{action}|{method}|{inputs}"
            return hashlib.md5(raw.encode()).hexdigest()[:12]
        except Exception:
            return hashlib.md5(page_url.encode()).hexdigest()[:12]

    # ── Interactive element clicking ──────────────────────────────────────

    async def _click_interactive_elements(self, page: Page, depth: int) -> None:
        """Click buttons, tabs, accordions, and other interactive elements."""
        selectors = [
            "button:not([type='submit']):not([type='reset'])",
            "[role='button']",
            "[role='tab']",
            ".accordion-header, .accordion-toggle, [data-toggle='collapse']",
            ".tab, .tab-link, [data-tab]",
            "[data-toggle='modal'], [data-bs-toggle='modal']",
            ".dropdown-toggle, [data-toggle='dropdown'], [data-bs-toggle='dropdown']",
            "[onclick]",
            "details > summary",
        ]

        for selector in selectors:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:10]:  # Cap per-selector to avoid explosion
                    try:
                        if not await el.is_visible():
                            continue
                        bbox = await el.bounding_box()
                        if not bbox:
                            continue

                        await el.scroll_into_view_if_needed()
                        await el.click(timeout=3_000)

                        # Brief pause to let content render
                        await asyncio.sleep(random.uniform(0.2, 0.6))

                        # Check if navigation happened (new URL)
                        new_url = page.url
                        if new_url not in self._visited_urls:
                            self._add_endpoint(new_url, "GET", "auto_navigator_click")
                            self._enqueue(new_url, depth + 1)

                    except Exception:
                        pass  # Element may be intercepted, stale, or not clickable
            except Exception:
                pass

    async def _click_navigation_elements(self, page: Page, depth: int) -> None:
        """Click navigation menus, sidebar links, and breadcrumbs."""
        nav_selectors = [
            "nav a[href]",
            ".nav a[href], .nav-link",
            ".sidebar a[href]",
            ".menu a[href], .menu-item a[href]",
            ".breadcrumb a[href]",
            "header a[href]",
            "footer a[href]",
        ]

        for selector in nav_selectors:
            try:
                elements = await page.query_selector_all(selector)
                for el in elements[:15]:
                    try:
                        href = await el.get_attribute("href")
                        if not href or href.startswith(("javascript:", "mailto:", "#")):
                            continue
                        full_url = urljoin(page.url, href)
                        if full_url not in self._visited_urls and self._is_in_scope(full_url):
                            self._enqueue(full_url, depth + 1)
                    except Exception:
                        pass
            except Exception:
                pass

    # ── Script / SPA extraction ───────────────────────────────────────────

    async def _extract_scripts(self, page: Page) -> None:
        """Extract JS file URLs from script tags."""
        try:
            scripts = await page.eval_on_selector_all(
                "script[src]",
                "els => els.map(e => e.src)"
            )
            for src in scripts:
                if src and src.endswith(".js") and src not in self._captured_js_files:
                    self._captured_js_files.append(src)
                    self._add_endpoint(src, "GET", "auto_navigator_script")
        except Exception:
            pass

    async def _detect_spa_routes(self, page: Page, base_url: str, depth: int) -> None:
        """Extract client-side routes from inline JS (React Router, Vue Router, etc.)."""
        try:
            content = await page.content()
        except Exception:
            return

        # Common SPA route patterns
        route_patterns = [
            r"""path\s*:\s*['"](/[^'"]+)['"]""",
            r"""to\s*=\s*['"](/[^'"]+)['"]""",
            r"""href\s*:\s*['"](/[^'"]+)['"]""",
            r"""navigate\s*\(\s*['"](/[^'"]+)['"]""",
            r"""pushState\s*\([^,]*,\s*[^,]*,\s*['"](/[^'"]+)['"]""",
            r"""router\.push\s*\(\s*['"](/[^'"]+)['"]""",
        ]

        for pattern in route_patterns:
            for match in re.finditer(pattern, content):
                path = match.group(1)
                if path and not path.startswith(("{{", "${")):
                    full_url = urljoin(base_url, path)
                    if full_url not in self._visited_urls and self._is_in_scope(full_url):
                        self._enqueue(full_url, depth + 1)
                        self._add_endpoint(full_url, "GET", "auto_navigator_spa_route")

    # ── Network interception callbacks ────────────────────────────────────

    def _on_request(self, request: PWRequest) -> None:
        """Capture every outgoing request."""
        url = request.url
        method = request.method
        resource_type = request.resource_type

        # Record all XHR / fetch / websocket requests as discovered endpoints
        if resource_type in ("xhr", "fetch", "websocket"):
            self._add_endpoint(url, method, f"auto_navigator_{resource_type}")

        # Also capture script and document loads
        if resource_type in ("script",) and url.endswith(".js"):
            if url not in self._captured_js_files:
                self._captured_js_files.append(url)

    def _on_response(self, response: PWResponse) -> None:
        """Record network response metadata."""
        try:
            self._network_requests.append({
                "url": response.url,
                "method": response.request.method,
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "resource_type": response.request.resource_type,
                "source": "auto_navigator_network",
            })
        except Exception:
            pass

    # ── Screenshot ────────────────────────────────────────────────────────

    async def _take_screenshot(self, page: Page, url: str) -> None:
        """Take a screenshot of the current page."""
        try:
            from pathlib import Path
            ss_dir = Path(self.config.screenshot_dir)
            ss_dir.mkdir(parents=True, exist_ok=True)

            slug = re.sub(r"[^a-zA-Z0-9]", "_", urlparse(url).path or "index")[:60]
            filename = f"autocrawl_{self._page_count:04d}_{slug}.png"
            filepath = ss_dir / filename

            await page.screenshot(path=str(filepath), full_page=False)
            self._screenshots_taken += 1
        except Exception:
            pass

    # ── Rich dashboard ────────────────────────────────────────────────────

    def _build_dashboard(self) -> Panel:
        """Build a Rich panel showing live crawl statistics."""
        elapsed = time.time() - self._start_time if self._start_time else 0
        rate = self._page_count / elapsed if elapsed > 0 else 0

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="dim")
        table.add_column("Value", style="bold cyan")

        table.add_row("⏱  Elapsed",           f"{elapsed:.0f}s")
        table.add_row("📄 Pages visited",      str(self._page_count))
        table.add_row("📋 Queue remaining",    str(len(self._queued_urls)))
        table.add_row("🔗 Endpoints found",    str(len(self._captured_endpoints)))
        table.add_row("🌐 Network requests",   str(len(self._network_requests)))
        table.add_row("📜 JS files",           str(len(self._captured_js_files)))
        table.add_row("📝 Forms submitted",    str(len(self._forms_submitted)))
        table.add_row("📸 Screenshots",        str(self._screenshots_taken))
        table.add_row("⚡ Rate",               f"{rate:.1f} pages/s")

        current_url = ""
        if self._visited_urls:
            current_url = list(self._visited_urls)[-1]
        if len(current_url) > 80:
            current_url = current_url[:77] + "..."
        table.add_row("🎯 Current",            current_url)

        return Panel(
            table,
            title="[bold green]🕷️  HunterEngine Auto-Crawler[/bold green]",
            subtitle=f"[dim]max {self.config.max_pages} pages · depth {self.config.max_depth}[/dim]",
            border_style="green",
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _is_in_scope(self, url: str) -> bool:
        """Check URL against scope boundaries."""
        if self.scope:
            return self.scope.is_in_scope(url)
        return True  # No scope loader → allow all (standalone crawl mode)

    def _normalize_url(self, url: str) -> Optional[str]:
        """Normalize a URL, stripping fragments."""
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return None
            # Strip fragment
            clean = parsed._replace(fragment="").geturl()
            return clean
        except Exception:
            return None

    def _enqueue(self, url: str, depth: int) -> None:
        """Add a URL to the crawl queue if not already visited/queued."""
        normalized = self._normalize_url(url)
        if not normalized:
            return
        if normalized in self._visited_urls:
            return
        if not self._is_in_scope(normalized):
            return
        # Avoid duplicate queue entries
        queued_urls = {u for u, _ in self._queued_urls}
        if normalized not in queued_urls:
            self._queued_urls.append((normalized, depth))

    def _add_endpoint(
        self,
        url: str,
        method: str,
        source: str,
        status: int = 0,
    ) -> None:
        """Record a discovered endpoint (deduplicated)."""
        key = f"{method}:{url}"
        if any(ep.get("_key") == key for ep in self._captured_endpoints):
            return
        self._captured_endpoints.append({
            "url": url,
            "method": method,
            "source": source,
            "status": status,
            "_key": key,
        })

    def _results(self) -> dict:
        """Return the final crawl results."""
        # Strip internal dedup keys from endpoints
        clean_endpoints = [
            {k: v for k, v in ep.items() if k != "_key"}
            for ep in self._captured_endpoints
        ]
        return {
            "endpoints": clean_endpoints,
            "js_files": list(set(self._captured_js_files)),
            "network_requests": self._network_requests,
            "pages_visited": self._page_count,
            "forms_submitted": len(self._forms_submitted),
            "screenshots": self._screenshots_taken,
        }
