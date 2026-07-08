"""
DNS resolution module.

Wraps dnsx for bulk DNS resolution and record enumeration.
Falls back to Python's asyncio DNS if dnsx is not installed.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger("hunterengine.recon.dns")


class DNSResolver:
    """Resolve subdomains to IPs and collect DNS records."""

    def __init__(self, timeout: int = 120) -> None:
        self.timeout = timeout
        self._has_dnsx = shutil.which("dnsx") is not None

    async def resolve_bulk(self, hostnames: list[str]) -> list[dict]:
        """
        Resolve a list of hostnames.

        Returns list of dicts:
            {"hostname": str, "ips": [str], "cname": str|None, "resolved": bool}
        """
        if not hostnames:
            return []

        if self._has_dnsx:
            return await self._resolve_dnsx(hostnames)
        return await self._resolve_python(hostnames)

    async def _resolve_dnsx(self, hostnames: list[str]) -> list[dict]:
        """Use dnsx for fast bulk resolution."""
        logger.info(f"Resolving {len(hostnames)} hosts with dnsx")

        # Write hosts to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hostnames))
            hosts_file = f.name

        try:
            cmd = [
                "dnsx", "-l", hosts_file, "-silent",
                "-a", "-cname", "-resp",
                "-json",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            results = []
            import json
            for line in stdout.decode().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    results.append({
                        "hostname": data.get("host", ""),
                        "ips": data.get("a", []),
                        "cname": data.get("cname", [None])[0] if data.get("cname") else None,
                        "resolved": bool(data.get("a")),
                    })
                except json.JSONDecodeError:
                    continue

            logger.info(f"dnsx resolved {len(results)} hosts")
            return results

        finally:
            Path(hosts_file).unlink(missing_ok=True)

    async def _resolve_python(self, hostnames: list[str]) -> list[dict]:
        """Fallback: resolve using Python's socket module."""
        logger.info(f"Resolving {len(hostnames)} hosts with Python DNS")

        async def resolve_one(hostname: str) -> dict:
            loop = asyncio.get_event_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(hostname, None, family=socket.AF_INET),
                    timeout=5,
                )
                ips = list({info[4][0] for info in infos})
                return {
                    "hostname": hostname,
                    "ips": ips,
                    "cname": None,
                    "resolved": True,
                }
            except Exception:
                return {
                    "hostname": hostname,
                    "ips": [],
                    "cname": None,
                    "resolved": False,
                }

        sem = asyncio.Semaphore(50)

        async def throttled(h):
            async with sem:
                return await resolve_one(h)

        results = await asyncio.gather(*[throttled(h) for h in hostnames])
        resolved = [r for r in results if r["resolved"]]
        logger.info(f"Resolved {len(resolved)}/{len(hostnames)} hosts")
        return list(results)

    async def get_cname_chain(self, hostname: str) -> list[str]:
        """Get the full CNAME chain for a hostname (useful for subdomain takeover checks)."""
        if not self._has_dnsx:
            return []

        cmd = ["dnsx", "-d", hostname, "-cname", "-resp", "-silent"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return [line.strip() for line in stdout.decode().strip().splitlines() if line.strip()]
