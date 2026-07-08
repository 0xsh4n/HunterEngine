"""
Historical URL collection.

Wraps gau + waymore + waybackurls for gathering historical
endpoints from the Wayback Machine and other sources.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("hunterengine.recon.historical")


# Extensions to filter out (binary/static files)
EXCLUDED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov",
    ".pdf", ".zip", ".gz", ".tar",
}


class HistoricalURLCollector:
    """Collect historical URLs for a domain from web archives."""

    def __init__(self, timeout: int = 300) -> None:
        self.timeout = timeout
        self._tools = {
            "gau": shutil.which("gau") is not None,
            "waybackurls": shutil.which("waybackurls") is not None,
        }

    async def collect(
        self,
        domain: str,
        filter_extensions: bool = True,
    ) -> list[str]:
        """
        Collect historical URLs from all available sources.
        Returns a deduplicated, filtered list of URLs.
        """
        tasks = []

        if self._tools.get("gau"):
            tasks.append(self._run_gau(domain))
        if self._tools.get("waybackurls"):
            tasks.append(self._run_waybackurls(domain))

        if not tasks:
            logger.warning("No historical URL tools available")
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_urls: set[str] = set()
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Historical URL tool failed: {result}")
                continue
            all_urls.update(result)

        # Filter
        if filter_extensions:
            all_urls = {u for u in all_urls if not self._has_excluded_ext(u)}

        # Deduplicate by normalized form
        normalized = set()
        unique = []
        for url in sorted(all_urls):
            norm = self._normalize(url)
            if norm not in normalized:
                normalized.add(norm)
                unique.append(url)

        logger.info(f"Collected {len(unique)} unique historical URLs for {domain}")
        return unique

    async def _run_gau(self, domain: str) -> list[str]:
        """Run gau (GetAllUrls)."""
        logger.info(f"Running gau on {domain}")
        cmd = ["gau", "--threads", "5", "--subs", domain]
        return await self._run_tool(cmd, "gau")

    async def _run_waybackurls(self, domain: str) -> list[str]:
        """Run waybackurls."""
        logger.info(f"Running waybackurls on {domain}")
        cmd_proc = await asyncio.create_subprocess_exec(
            "waybackurls",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            cmd_proc.communicate(input=f"{domain}\n".encode()), 
            timeout=self.timeout
        )
        lines = stdout.decode().strip().splitlines()
        logger.info(f"waybackurls found {len(lines)} URLs")
        return [line.strip() for line in lines if line.strip()]

    async def _run_tool(self, cmd: list[str], name: str) -> list[str]:
        """Execute a tool and return stdout lines."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            lines = stdout.decode().strip().splitlines()
            logger.info(f"{name} found {len(lines)} URLs")
            return [line.strip() for line in lines if line.strip()]
        except asyncio.TimeoutError:
            logger.warning(f"{name} timed out")
            return []
        except Exception as e:
            logger.error(f"{name} failed: {e}")
            return []

    @staticmethod
    def _has_excluded_ext(url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(path.endswith(ext) for ext in EXCLUDED_EXTENSIONS)

    @staticmethod
    def _normalize(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()

    def categorize_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Categorize URLs by type for targeted analysis."""
        categories: dict[str, list[str]] = {
            "api": [],
            "js": [],
            "json": [],
            "xml": [],
            "params": [],
            "other": [],
        }

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()

            if "/api/" in path or "/v1/" in path or "/v2/" in path or "/graphql" in path:
                categories["api"].append(url)
            elif path.endswith(".js"):
                categories["js"].append(url)
            elif path.endswith(".json"):
                categories["json"].append(url)
            elif path.endswith(".xml"):
                categories["xml"].append(url)
            elif parsed.query:
                categories["params"].append(url)
            else:
                categories["other"].append(url)

        return categories
