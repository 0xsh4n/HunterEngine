"""
Live host probing.

Wraps httpx (ProjectDiscovery) for HTTP probing with tech detection,
and naabu for port scanning.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
import re
from pathlib import Path
from typing import Optional

from core.rate_limiter import RateLimiter
from core.tool_resolver import find_projectdiscovery_httpx
from core.waf_bypass import WAFBypass

logger = logging.getLogger("hunterengine.recon.prober")

# Regex to strip ANSI escape codes
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


class LiveProber:
    """Probe hosts for HTTP services and open ports."""

    def __init__(
        self,
        rate_limiter: Optional[RateLimiter] = None,
        waf_bypass: Optional[WAFBypass] = None,
        timeout: int = 300,
    ) -> None:
        self.rate_limiter = rate_limiter
        self.waf_bypass = waf_bypass
        self.timeout = timeout
        self._httpx_bin = find_projectdiscovery_httpx()
        self._has_httpx = self._httpx_bin is not None
        self._has_naabu = shutil.which("naabu") is not None

    async def probe_hosts(self, hostnames: list[str]) -> list[dict]:
        """
        Probe a list of hostnames for live HTTP services.

        Returns list of dicts:
            {"url": str, "status": int, "title": str, "tech": [str],
             "content_length": int, "webserver": str}
        """
        if not hostnames:
            return []

        if self._has_httpx:
            return await self._probe_httpx(hostnames)
        return await self._probe_python(hostnames)

    async def _probe_httpx(self, hostnames: list[str]) -> list[dict]:
        """Use ProjectDiscovery httpx for probing."""
        logger.info(f"Probing {len(hostnames)} hosts with httpx")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hostnames))
            hosts_file = f.name

        try:
            cmd = [
                self._httpx_bin or "httpx", "-l", hosts_file, "-silent",
                "-json",
                "-title", "-tech-detect", "-status-code",
                "-content-length", "-web-server",
                "-follow-redirects",
                "-threads", "20",
                "-timeout", "10",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            if proc.returncode != 0:
                logger.error(f"httpx failed with code {proc.returncode}: {stderr.decode().strip()[:200]}")

            results = []
            for line in stdout.decode().strip().splitlines():
                clean_line = ANSI_ESCAPE.sub('', line).strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                    results.append({
                        "url": data.get("url", ""),
                        "status": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "content_length": data.get("content_length", 0),
                        "webserver": data.get("webserver", ""),
                        "host": data.get("host", ""),
                        "scheme": data.get("scheme", "https"),
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"httpx found {len(results)} live hosts")
            return results

        finally:
            Path(hosts_file).unlink(missing_ok=True)

    async def _probe_python(self, hostnames: list[str]) -> list[dict]:
        """Fallback: probe using Python httpx."""
        import httpx

        logger.info(f"Probing {len(hostnames)} hosts with Python httpx")
        results = []
        sem = asyncio.Semaphore(20)

        async def probe_one(hostname: str) -> Optional[dict]:
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{hostname}"
                    if self.rate_limiter:
                        await self.rate_limiter.acquire(hostname)
                    try:
                        async with httpx.AsyncClient(
                            verify=False,
                            follow_redirects=True,
                            timeout=10,
                        ) as client:
                            resp = await client.get(url)
                            if self.rate_limiter:
                                self.rate_limiter.report_response(hostname, resp.status_code)
                            return {
                                "url": str(resp.url),
                                "status": resp.status_code,
                                "title": "",
                                "tech": [],
                                "content_length": len(resp.content),
                                "webserver": resp.headers.get("server", ""),
                                "host": hostname,
                                "scheme": scheme,
                            }
                    except Exception:
                        continue
            return None

        tasks = [probe_one(h) for h in hostnames]
        for result in await asyncio.gather(*tasks):
            if result:
                results.append(result)

        logger.info(f"Python probe found {len(results)} live hosts")
        return results

    async def port_scan(self, hostnames: list[str], top_ports: int = 1000) -> dict[str, list[int]]:
        """
        Scan for open ports using naabu.
        Returns dict mapping hostname → list of open ports.
        """
        if not self._has_naabu:
            logger.warning("naabu not installed — skipping port scan")
            return {}

        logger.info(f"Port scanning {len(hostnames)} hosts")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hostnames))
            hosts_file = f.name

        try:
            cmd = [
                "naabu", "-l", hosts_file, "-silent",
                "-json", "-top-ports", str(top_ports),
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            port_map: dict[str, list[int]] = {}
            for line in stdout.decode().strip().splitlines():
                clean_line = ANSI_ESCAPE.sub('', line).strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                    host = data.get("host", "")
                    port = data.get("port", 0)
                    port_map.setdefault(host, []).append(port)
                except json.JSONDecodeError:
                    continue

            return port_map

        finally:
            Path(hosts_file).unlink(missing_ok=True)
