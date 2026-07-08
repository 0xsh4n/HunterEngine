"""
Subdomain enumeration.

Wraps subfinder + amass + assetfinder for comprehensive passive
and active subdomain discovery, then deduplicates results.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from typing import Optional

logger = logging.getLogger("hunterengine.recon.subdomain")


class SubdomainEnumerator:
    """
    Multi-tool subdomain enumerator.

    Runs available tools in parallel and merges results.
    Gracefully skips tools that aren't installed.
    """

    def __init__(self, wordlist: Optional[str] = None, timeout: int = 300) -> None:
        self.wordlist = wordlist or "config/wordlists/subdomains.txt"
        self.timeout = timeout
        self._available_tools: dict[str, bool] = {}
        self._check_tools()

    def _check_tools(self) -> None:
        """Detect which tools are installed."""
        for tool in ("subfinder", "amass", "assetfinder"):
            self._available_tools[tool] = shutil.which(tool) is not None
            if self._available_tools[tool]:
                logger.info(f"  ✓ {tool} found")
            else:
                logger.debug(f"  ✗ {tool} not found")

    async def enumerate(self, domain: str) -> list[str]:
        """
        Run all available subdomain tools against a domain.
        Returns a deduplicated list of discovered subdomains.
        """
        tasks = []

        if self._available_tools.get("subfinder"):
            tasks.append(self._run_subfinder(domain))
        if self._available_tools.get("amass"):
            tasks.append(self._run_amass(domain))
        if self._available_tools.get("assetfinder"):
            tasks.append(self._run_assetfinder(domain))

        if not tasks:
            logger.warning("No subdomain tools available — returning base domain only")
            return [domain]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_subs: set[str] = set()
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Subdomain tool failed: {result}")
                continue
            all_subs.update(result)

        # Normalize
        normalized = set()
        for sub in all_subs:
            sub = sub.strip().lower().rstrip(".")
            if sub and domain in sub:
                normalized.add(sub)

        logger.info(f"Total unique subdomains for {domain}: {len(normalized)}")
        return sorted(normalized)

    async def _run_subfinder(self, domain: str) -> list[str]:
        """Run subfinder for passive subdomain enumeration."""
        logger.info(f"Running subfinder on {domain}")
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        return await self._run_tool(cmd, "subfinder")

    async def _run_amass(self, domain: str) -> list[str]:
        """Run amass for active + passive enumeration."""
        logger.info(f"Running amass on {domain}")
        cmd = ["amass", "enum", "-passive", "-d", domain]
        return await self._run_tool(cmd, "amass")

    async def _run_assetfinder(self, domain: str) -> list[str]:
        """Run assetfinder for fast subdomain scraping."""
        logger.info(f"Running assetfinder on {domain}")
        cmd = ["assetfinder", "--subs-only", domain]
        return await self._run_tool(cmd, "assetfinder")

    async def _run_tool(self, cmd: list[str], name: str) -> list[str]:
        """Execute a tool and return its stdout lines as a list."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )

            if proc.returncode != 0:
                logger.warning(f"{name} exited with code {proc.returncode}: {stderr.decode()[:200]}")

            lines = stdout.decode().strip().splitlines()
            logger.info(f"{name} found {len(lines)} subdomains")
            return [line.strip() for line in lines if line.strip()]

        except asyncio.TimeoutError:
            logger.warning(f"{name} timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"{name} failed: {e}")
            return []
