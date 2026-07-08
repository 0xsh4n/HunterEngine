"""
Active web crawling.

Wraps katana + gospider + hakrawler for comprehensive endpoint
discovery, link extraction, and JS file collection.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from core.rate_limiter import RateLimiter
from core.waf_bypass import WAFBypass

logger = logging.getLogger("hunterengine.crawl.active")


class ActiveCrawler:
    """Multi-tool active web crawler."""

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        waf_bypass: Optional[WAFBypass] = None,
        max_depth: int = 5,
        timeout: int = 600,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.waf_bypass = waf_bypass
        self.max_depth = max_depth
        self.timeout = timeout
        self._tools = {
            "katana": shutil.which("katana") is not None,
            "gospider": shutil.which("gospider") is not None,
            "hakrawler": shutil.which("hakrawler") is not None,
        }

    async def crawl(self, urls: list[str]) -> dict:
        """
        Crawl a list of URLs using all available tools.

        Returns:
            {"endpoints": [{"url": str, "method": str, "source": str}],
             "js_files": [str],
             "forms": [dict]}
        """
        if not urls:
            return {"endpoints": [], "js_files": [], "forms": []}

        tasks = []
        if self._tools.get("katana"):
            tasks.append(self._run_katana(urls))
        if self._tools.get("gospider"):
            tasks.append(self._run_gospider(urls))
        if self._tools.get("hakrawler"):
            tasks.append(self._run_hakrawler(urls))

        if not tasks:
            logger.warning("No crawling tools available")
            return {"endpoints": [], "js_files": [], "forms": []}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_endpoints: list[dict] = []
        all_js: set[str] = set()

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Crawler failed: {result}")
                continue
            all_endpoints.extend(result.get("endpoints", []))
            all_js.update(result.get("js_files", []))

        # Deduplicate endpoints
        seen_urls = set()
        unique_endpoints = []
        for ep in all_endpoints:
            url = ep.get("url", "")
            if url not in seen_urls:
                seen_urls.add(url)
                unique_endpoints.append(ep)

        logger.info(f"Active crawl: {len(unique_endpoints)} endpoints, {len(all_js)} JS files")
        return {
            "endpoints": unique_endpoints,
            "js_files": sorted(all_js),
            "forms": [],
        }

    async def _run_katana(self, urls: list[str]) -> dict:
        """Run katana — JS-aware crawler."""
        logger.info("Running katana")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        try:
            cmd = [
                "katana", "-list", urls_file, "-silent",
                "-json", "-depth", str(self.max_depth),
                "-js-crawl", "-known-files", "all",
                "-concurrency", "10",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            endpoints = []
            js_files = set()

            for line in stdout.decode().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("request", {}).get("endpoint", "") or data.get("endpoint", "")
                    if not url:
                        continue

                    ep = {
                        "url": url,
                        "method": data.get("request", {}).get("method", "GET"),
                        "source": "katana",
                        "status": data.get("response", {}).get("status_code"),
                    }
                    endpoints.append(ep)

                    if url.endswith(".js"):
                        js_files.add(url)
                except json.JSONDecodeError:
                    # Plain URL output
                    url = line.strip()
                    endpoints.append({"url": url, "method": "GET", "source": "katana"})
                    if url.endswith(".js"):
                        js_files.add(url)

            return {"endpoints": endpoints, "js_files": list(js_files)}
        finally:
            Path(urls_file).unlink(missing_ok=True)

    async def _run_gospider(self, urls: list[str]) -> dict:
        """Run gospider — spider with link extraction."""
        logger.info("Running gospider")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        try:
            cmd = [
                "gospider", "-S", urls_file, "--quiet",
                "-d", str(self.max_depth),
                "-c", "5", "-t", "5",
                "--js",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            endpoints = []
            js_files = set()

            for line in stdout.decode().strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                # gospider output: [source] [type] - URL
                parts = line.split(" - ", 1)
                url = parts[-1].strip() if parts else line
                if url.startswith("http"):
                    endpoints.append({"url": url, "method": "GET", "source": "gospider"})
                    if url.endswith(".js"):
                        js_files.add(url)

            return {"endpoints": endpoints, "js_files": list(js_files)}
        finally:
            Path(urls_file).unlink(missing_ok=True)

    async def _run_hakrawler(self, urls: list[str]) -> dict:
        """Run hakrawler — fast endpoint harvesting."""
        logger.info("Running hakrawler")

        endpoints = []
        js_files = set()

        for url in urls[:20]:  # hakrawler takes single URLs
            try:
                proc = await asyncio.create_subprocess_exec(
                    "hakrawler", "-url", url, "-depth", str(min(self.max_depth, 3)),
                    "-plain",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)

                for line in stdout.decode().strip().splitlines():
                    u = line.strip()
                    if u.startswith("http"):
                        endpoints.append({"url": u, "method": "GET", "source": "hakrawler"})
                        if u.endswith(".js"):
                            js_files.add(u)
            except Exception as e:
                logger.debug(f"hakrawler failed for {url}: {e}")

        return {"endpoints": endpoints, "js_files": list(js_files)}
