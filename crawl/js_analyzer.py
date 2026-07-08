"""
JavaScript analysis module.

Wraps jsluice + LinkFinder for endpoint and secret discovery in JS files.
Includes inline regex-based analysis as a fallback.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("hunterengine.crawl.jsanalyzer")


# Patterns for sensitive data in JS
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
    (r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Secret Key"),
    (r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Access Token"),
    (r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', "Auth Token"),
    (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Hardcoded Password"),
    (r'["\']?aws_access_key_id["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', "AWS Access Key"),
    (r'["\']?aws_secret_access_key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', "AWS Secret Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Key ID"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub PAT"),
    (r'sk-[a-zA-Z0-9]{48}', "OpenAI API Key"),
    (r'xox[bpas]-[0-9a-zA-Z\-]{10,}', "Slack Token"),
    (r'ya29\.[0-9A-Za-z_-]+', "Google OAuth Token"),
    (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),
]

ENDPOINT_PATTERNS: list[str] = [
    r'["\'](/api/[a-zA-Z0-9_/\-\.]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-\.]+)["\']',
    r'["\'](https?://[a-zA-Z0-9\-\.]+/api/[^"\']+)["\']',
    r'["\'](/graphql[^"\']*)["\']',
    r'["\'](/ws[s]?/[^"\']*)["\']',
    r'["\'](/webhook[s]?/[^"\']*)["\']',
    r'["\'](/internal/[^"\']*)["\']',
    r'["\'](/admin/[^"\']*)["\']',
    r'["\'](/debug/[^"\']*)["\']',
]


class JSAnalyzer:
    """Analyze JavaScript files for endpoints, secrets, and source maps."""

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout
        self._has_jsluice = shutil.which("jsluice") is not None

    async def analyze(self, js_url: str) -> dict:
        """
        Analyze a single JS file.

        Returns:
            {"secrets": [dict], "endpoints": [dict], "source_map": str|None}
        """
        result = {
            "secrets": [],
            "endpoints": [],
            "source_map": None,
        }

        try:
            js_content = await self._fetch_js(js_url)
            if not js_content:
                return result

            # Check for source map
            source_map = self._find_source_map(js_content, js_url)
            result["source_map"] = source_map

            # Run jsluice if available
            if self._has_jsluice:
                jsluice_results = await self._run_jsluice(js_content)
                result["endpoints"].extend(jsluice_results.get("endpoints", []))
                result["secrets"].extend(jsluice_results.get("secrets", []))

            # Run regex analysis (complements jsluice)
            regex_secrets = self._scan_secrets(js_content, js_url)
            regex_endpoints = self._scan_endpoints(js_content, js_url)

            result["secrets"].extend(regex_secrets)
            result["endpoints"].extend(regex_endpoints)

            # Deduplicate
            seen_secrets = set()
            unique_secrets = []
            for s in result["secrets"]:
                key = (s.get("type", ""), s.get("value", "")[:20])
                if key not in seen_secrets:
                    seen_secrets.add(key)
                    unique_secrets.append(s)
            result["secrets"] = unique_secrets

        except Exception as e:
            logger.debug(f"JS analysis failed for {js_url}: {e}")

        return result

    async def _fetch_js(self, url: str) -> Optional[str]:
        """Download a JS file."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
        except Exception as e:
            logger.debug(f"Failed to fetch JS {url}: {e}")
        return None

    async def _run_jsluice(self, js_content: str) -> dict:
        """Run jsluice for endpoint/secret extraction."""
        result = {"endpoints": [], "secrets": []}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(js_content)
            js_file = f.name

        try:
            # Extract URLs
            proc = await asyncio.create_subprocess_exec(
                "jsluice", "urls", js_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            for line in stdout.decode().strip().splitlines():
                try:
                    data = json.loads(line)
                    result["endpoints"].append({
                        "url": data.get("url", ""),
                        "method": "GET",
                        "source": "jsluice",
                    })
                except json.JSONDecodeError:
                    pass

            # Extract secrets
            proc = await asyncio.create_subprocess_exec(
                "jsluice", "secrets", js_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            for line in stdout.decode().strip().splitlines():
                try:
                    data = json.loads(line)
                    result["secrets"].append({
                        "type": data.get("kind", "Unknown"),
                        "value": data.get("data", {}).get("value", "")[:50],
                        "source": "jsluice",
                        "severity": "medium",
                    })
                except json.JSONDecodeError:
                    pass

        finally:
            Path(js_file).unlink(missing_ok=True)

        return result

    def _scan_secrets(self, content: str, source_url: str) -> list[dict]:
        """Regex-based secret scanning."""
        secrets = []
        for pattern, secret_type in SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)
                secrets.append({
                    "type": secret_type,
                    "value": value[:50] + "..." if len(value) > 50 else value,
                    "source_url": source_url,
                    "source": "regex",
                    "confidence": 0.7,
                    "severity": "high" if "aws" in secret_type.lower() or "password" in secret_type.lower() else "medium",
                })
        return secrets

    def _scan_endpoints(self, content: str, source_url: str) -> list[dict]:
        """Regex-based endpoint extraction."""
        endpoints = []
        seen = set()

        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content):
                path = match.group(1)
                if path not in seen:
                    seen.add(path)
                    endpoints.append({
                        "url": path,
                        "method": "GET",
                        "source": "js_regex",
                        "source_url": source_url,
                    })

        return endpoints

    @staticmethod
    def _find_source_map(content: str, js_url: str) -> Optional[str]:
        """Check for source map reference."""
        match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', content)
        if match:
            map_url = match.group(1)
            if not map_url.startswith("http"):
                from urllib.parse import urljoin
                map_url = urljoin(js_url, map_url)
            return map_url
        return None

    async def analyze_bulk(self, js_urls: list[str], concurrency: int = 10) -> dict:
        """Analyze multiple JS files concurrently."""
        sem = asyncio.Semaphore(concurrency)
        all_secrets: list[dict] = []
        all_endpoints: list[dict] = []
        source_maps: list[str] = []

        async def analyze_one(url: str):
            async with sem:
                result = await self.analyze(url)
                all_secrets.extend(result["secrets"])
                all_endpoints.extend(result["endpoints"])
                if result["source_map"]:
                    source_maps.append(result["source_map"])

        await asyncio.gather(*[analyze_one(u) for u in js_urls], return_exceptions=True)

        return {
            "secrets": all_secrets,
            "endpoints": all_endpoints,
            "source_maps": source_maps,
        }
