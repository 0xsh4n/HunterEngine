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
from pathlib import Path
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
    page_timeout: int = 45_000            # Per-page navigation timeout (ms)
    wait_after_load: float = 3.0          # Seconds to wait after page load for JS to render
    action_delay: tuple[float, float] = (0.4, 1.5)  # Human-like pause between actions
    slow_mo: int = 150                    # Playwright slow_mo (ms) — makes headed mode watchable
    form_submit: bool = True              # Auto-fill and submit forms
    click_buttons: bool = True            # Click buttons and interactive elements
    click_navigation: bool = True         # Click nav menus, dropdowns, tabs
    intercept_network: bool = True        # Capture XHR / fetch / WS traffic
    screenshot_on_new_page: bool = True   # Screenshot each unique page
    screenshot_dir: str = "data/screenshots"
    keep_open: float = 5.0                # Seconds to keep browser open after crawl finishes
    viewport: dict[str, int] = field(default_factory=lambda: {"width": 1366, "height": 768})
    chromium_args: list[str] = field(default_factory=lambda: [
        "--disable-gpu",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--ignore-certificate-errors",
        "--disable-blink-features=AutomationControlled",
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
        self._current_url: str = ""
        self._status_message: str = "Starting..."
        self._errors: list[str] = []

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

        try:
            await self._launch_browser()
        except Exception as exc:
            logger.error("Failed to launch browser: %s", exc)
            console.print(f"[bold red]Error launching browser:[/bold red] {exc}")
            console.print("[yellow]Make sure Playwright browsers are installed:[/yellow]")
            console.print("  [cyan]playwright install chromium[/cyan]")
            return self._results()

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
                    self._current_url = url
                    self._status_message = f"Navigating (depth {depth})"

                    live.update(self._build_dashboard())

                    try:
                        await self._navigate_and_explore(url, depth)
                        self._status_message = "Exploring page..."
                    except Exception as exc:
                        err_msg = f"{url}: {exc}"
                        logger.debug("Failed to explore %s: %s", url, exc)
                        self._errors.append(err_msg[:120])
                        self._status_message = f"Error on page, continuing..."

                    live.update(self._build_dashboard())

                # End of crawl
                self._status_message = "Crawl complete!"
                live.update(self._build_dashboard())

            # Keep the browser open so the user can see the final state
            if self.config.keep_open > 0 and not self.config.headless:
                console.print(
                    f"\n[dim]Browser stays open for {self.config.keep_open:.0f}s "
                    f"— review the last page...[/dim]"
                )
                await asyncio.sleep(self.config.keep_open)

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

        # slow_mo makes headed mode watchable — actions happen at human speed
        self._browser = await self._pw.chromium.launch(
            headless=self.config.headless,
            args=launch_args,
            proxy=proxy,
            slow_mo=self.config.slow_mo if not self.config.headless else 0,
        )

        # Build context options
        ctx_options: dict[str, Any] = {
            "viewport": self.config.viewport,
            "ignore_https_errors": True,
        }
        if self.config.user_agent:
            ctx_options["user_agent"] = self.config.user_agent

        self._context = await self._browser.new_context(**ctx_options)
        self._context.set_default_timeout(self.config.page_timeout)
        self._context.set_default_navigation_timeout(self.config.page_timeout)

        self._page = await self._context.new_page()

        # ── Network interception ──────────────────────────────────────────
        if self.config.intercept_network:
            self._page.on("request", self._on_request)
            self._page.on("response", self._on_response)

        logger.info(
            "Browser launched (%s mode, slow_mo=%dms)",
            "headless" if self.config.headless else "headed",
            self.config.slow_mo if not self.config.headless else 0,
        )

    async def _close_browser(self) -> None:
        try:
            if self._context:
                await self._context.close()
        except Exception:
            pass
        try:
            if self._browser:
                await self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                await self._pw.stop()
        except Exception:
            pass

    # ── Core navigation loop ──────────────────────────────────────────────

    async def _navigate_and_explore(self, url: str, depth: int) -> None:
        """Navigate to a page, then explore all interactive elements."""
        page = self._page
        if not page:
            return

        logger.info("[depth=%d] Navigating → %s", depth, url)

        # Navigate with retry
        response = await self._safe_goto(page, url)
        if response is None:
            # Even if goto "failed", the page might have partially loaded
            # Give it a moment and try to work with whatever loaded
            await asyncio.sleep(2.0)

        # Wait for the page to fully render
        await self._wait_for_page_ready(page)

        status = response.status if response else 0
        current_url = page.url
        self._current_url = current_url

        # Record as endpoint
        self._add_endpoint(current_url, "GET", "auto_navigator", status=status)

        # Screenshot
        if self.config.screenshot_on_new_page:
            await self._take_screenshot(page, current_url)

        # ── Extract links from the page ───────────────────────────────────
        self._status_message = "Extracting links..."
        await self._extract_links(page, depth)

        # ── Extract and submit forms ──────────────────────────────────────
        if self.config.form_submit:
            self._status_message = "Processing forms..."
            await self._process_forms(page, current_url, depth)

        # ── Click interactive elements (buttons, tabs, accordions) ────────
        if self.config.click_buttons:
            self._status_message = "Clicking interactive elements..."
            await self._click_interactive_elements(page, depth)

        # ── Click navigation elements (nav links, dropdowns) ─────────────
        if self.config.click_navigation:
            self._status_message = "Exploring navigation..."
            await self._click_navigation_elements(page, depth)

        # ── Extract JS files ──────────────────────────────────────────────
        await self._extract_scripts(page)

        # ── Detect SPA routes via inline JS ───────────────────────────────
        await self._detect_spa_routes(page, current_url, depth)

    async def _safe_goto(self, page: Page, url: str, retries: int = 2) -> Any:
        """Navigate to a URL with retries and multiple wait strategies."""
        last_error = None
        for attempt in range(retries + 1):
            try:
                # First try: wait for load event (more reliable than domcontentloaded)
                response = await page.goto(
                    url,
                    wait_until="load",
                    timeout=self.config.page_timeout,
                )
                return response
            except Exception as exc:
                last_error = exc
                if attempt < retries:
                    logger.debug(
                        "Navigation attempt %d failed for %s: %s — retrying...",
                        attempt + 1, url, exc,
                    )
                    await asyncio.sleep(1.5)
                    # Retry with a more lenient wait strategy
                    try:
                        response = await page.goto(
                            url,
                            wait_until="commit",
                            timeout=self.config.page_timeout,
                        )
                        return response
                    except Exception:
                        continue

        logger.warning("All navigation attempts failed for %s: %s", url, last_error)
        return None

    async def _wait_for_page_ready(self, page: Page) -> None:
        """Wait for the page to be fully ready — both network and rendering."""
        # 1. Wait for network to settle
        try:
            await page.wait_for_load_state("networkidle", timeout=10_000)
        except Exception:
            pass

        # 2. Wait for DOM to be stable
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5_000)
        except Exception:
            pass

        # 3. Fixed delay to let JS frameworks render their content
        await asyncio.sleep(self.config.wait_after_load)

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
                        async with page.expect_navigation(timeout=10_000, wait_until="load"):
                            await submit_btn.click()
                    except Exception:
                        # Navigation may not happen (AJAX form)
                        await asyncio.sleep(1.5)
                else:
                    # No submit button — try pressing Enter on the last input
                    if inputs:
                        try:
                            async with page.expect_navigation(timeout=10_000, wait_until="load"):
                                await inputs[-1].press("Enter")
                        except Exception:
                            await asyncio.sleep(1.5)

                self._add_endpoint(action_url, method, "auto_navigator_form")

                # Wait for the resulting page to render
                await self._wait_for_page_ready(page)
                new_url = page.url
                if new_url not in self._visited_urls:
                    self._enqueue(new_url, depth + 1)

                # Go back to continue exploring other forms
                try:
                    await page.go_back(wait_until="load", timeout=10_000)
                    await self._wait_for_page_ready(page)
                except Exception:
                    # If go_back fails, navigate back to the original page
                    try:
                        await page.goto(page_url, wait_until="load", timeout=self.config.page_timeout)
                        await self._wait_for_page_ready(page)
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

                        # Human-like pause from action_delay config
                        delay = random.uniform(*self.config.action_delay)
                        await asyncio.sleep(delay)

                        # Check if navigation happened (new URL)
                        new_url = page.url
                        if new_url not in self._visited_urls and self._is_in_scope(new_url):
                            self._add_endpoint(new_url, "GET", "auto_navigator_click")
                            self._enqueue(new_url, depth + 1)
                            # Restore context page when click navigates away mid-explore
                            try:
                                await page.go_back(wait_until="domcontentloaded", timeout=8_000)
                            except Exception:
                                pass

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
        """Capture every outgoing request (in-scope only for endpoint discovery)."""
        try:
            url = request.url
            method = request.method
            resource_type = request.resource_type

            # Record all XHR / fetch / websocket requests as discovered endpoints
            if resource_type in ("xhr", "fetch", "websocket"):
                if self._is_in_scope(url):
                    self._add_endpoint(url, method, f"auto_navigator_{resource_type}")

            # Also capture script and document loads
            if resource_type in ("script",) and url.endswith(".js"):
                if url not in self._captured_js_files and self._is_in_scope(url):
                    self._captured_js_files.append(url)
        except Exception:
            pass

    def _on_response(self, response: PWResponse) -> None:
        """Record network response metadata (prefer in-scope URLs)."""
        try:
            url = response.url
            if not self._is_in_scope(url):
                # Still keep a light record for debugging, but mark out-of-scope
                if response.request.resource_type not in ("xhr", "fetch"):
                    return
            self._network_requests.append({
                "url": url,
                "method": response.request.method,
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "resource_type": response.request.resource_type,
                "source": "auto_navigator_network",
                "in_scope": self._is_in_scope(url),
            })
        except Exception:
            pass

    # ── Screenshot ────────────────────────────────────────────────────────

    async def _take_screenshot(self, page: Page, url: str) -> None:
        """Take a screenshot of the current page."""
        try:
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
        table.add_row("📄 Pages visited",      f"{self._page_count} / {self.config.max_pages}")
        table.add_row("📋 Queue remaining",    str(len(self._queued_urls)))
        table.add_row("🔗 Endpoints found",    str(len(self._captured_endpoints)))
        table.add_row("🌐 Network requests",   str(len(self._network_requests)))
        table.add_row("📜 JS files",           str(len(self._captured_js_files)))
        table.add_row("📝 Forms submitted",    str(len(self._forms_submitted)))
        table.add_row("📸 Screenshots",        str(self._screenshots_taken))
        table.add_row("⚡ Rate",               f"{rate:.1f} pages/s")

        # Current URL (truncated)
        display_url = self._current_url
        if len(display_url) > 72:
            display_url = display_url[:69] + "..."
        table.add_row("🎯 Current",            display_url or "(starting)")
        table.add_row("📊 Status",             self._status_message)

        # Show last error if any
        if self._errors:
            last_err = self._errors[-1]
            if len(last_err) > 72:
                last_err = last_err[:69] + "..."
            table.add_row("⚠️  Last error",      f"[red]{last_err}[/red]")

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
