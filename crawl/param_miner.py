"""
HTTP parameter discovery.

Wraps arjun for discovering hidden GET/POST parameters on endpoints.
Falls back to wordlist-based probing if arjun is unavailable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from core.rate_limiter import RateLimiter

logger = logging.getLogger("hunterengine.crawl.params")


class ParamMiner:
    """Discover hidden HTTP parameters on target endpoints."""

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        wordlist: str = "config/wordlists/params.txt",
        timeout: int = 120,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.wordlist = wordlist
        self.timeout = timeout
        self._has_arjun = shutil.which("arjun") is not None

    async def discover(self, urls: list[str]) -> dict[str, list[str]]:
        """
        Discover parameters on a list of URLs.

        Returns:
            Dict mapping URL → list of discovered parameter names.
        """
        if not urls:
            return {}

        if self._has_arjun:
            return await self._run_arjun(urls)
        return await self._probe_wordlist(urls)

    async def _run_arjun(self, urls: list[str]) -> dict[str, list[str]]:
        """Use arjun for parameter discovery."""
        logger.info(f"Running arjun on {len(urls)} URLs")
        results: dict[str, list[str]] = {}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        try:
            output_file = tempfile.mktemp(suffix=".json")
            cmd = [
                "arjun", "-i", urls_file,
                "-oJ", output_file,
                "-w", self.wordlist,
                "-t", "10",
                "--stable",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            # Parse output
            output_path = Path(output_file)
            if output_path.exists():
                data = json.loads(output_path.read_text())
                for entry in data if isinstance(data, list) else [data]:
                    url = entry.get("url", "")
                    params = entry.get("params", [])
                    if url and params:
                        results[url] = params

            logger.info(f"arjun discovered params on {len(results)} URLs")
            return results

        finally:
            Path(urls_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

    async def _probe_wordlist(self, urls: list[str]) -> dict[str, list[str]]:
        """Fallback: probe parameters using wordlist and response diffing."""
        import httpx

        logger.info(f"Probing parameters with wordlist on {len(urls)} URLs")
        wordlist_path = Path(self.wordlist)
        if not wordlist_path.exists():
            logger.warning(f"Param wordlist not found: {self.wordlist}")
            return {}

        params = wordlist_path.read_text().strip().splitlines()
        results: dict[str, list[str]] = {}
        sem = asyncio.Semaphore(10)

        async def probe_url(url: str):
            found_params = []
            async with sem:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=10) as client:
                        # Baseline request
                        if self.rate_limiter:
                            from urllib.parse import urlparse
                            host = urlparse(url).hostname or ""
                            await self.rate_limiter.acquire(host)
                        baseline = await client.get(url)
                        baseline_len = len(baseline.content)

                        # Test each parameter
                        for param in params[:30]:  # Cap per URL
                            if self.rate_limiter:
                                await self.rate_limiter.acquire(host)
                            try:
                                test_resp = await client.get(
                                    url, params={param: "huntertest123"}
                                )
                                # Significant difference indicates the param is reflected
                                if abs(len(test_resp.content) - baseline_len) > 50:
                                    found_params.append(param)
                            except Exception:
                                continue

                except Exception as e:
                    logger.debug(f"Param probing failed for {url}: {e}")

            if found_params:
                results[url] = found_params

        await asyncio.gather(*[probe_url(u) for u in urls[:50]])
        return results
