"""
Technology fingerprinting.

Detects frameworks, languages, and tech stack from HTTP responses.
Focused on Node/React/Next.js/Angular/Vue detection for targeted scanning.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger("hunterengine.recon.tech")


@dataclass
class TechProfile:
    """Detected technology profile for a host."""
    url: str = ""
    frameworks: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    servers: list[str] = field(default_factory=list)
    cms: list[str] = field(default_factory=list)
    cdn: list[str] = field(default_factory=list)
    js_libraries: list[str] = field(default_factory=list)
    is_spa: bool = False
    has_graphql: bool = False
    has_api: bool = False
    raw_headers: dict[str, str] = field(default_factory=dict)


# ── Signature database ────────────────────────────────────────────────────

HEADER_SIGNATURES: dict[str, dict[str, list[str]]] = {
    "x-powered-by": {
        "Express": ["express", "frameworks"],
        "Next.js": ["next.js", "frameworks"],
        "PHP": ["php", "languages"],
        "ASP.NET": ["asp.net", "frameworks"],
        "Django": ["django", "frameworks"],
        "Flask": ["flask", "frameworks"],
    },
    "server": {
        "nginx": ["nginx", "servers"],
        "Apache": ["apache", "servers"],
        "cloudflare": ["cloudflare", "cdn"],
        "Vercel": ["vercel", "cdn"],
        "Netlify": ["netlify", "cdn"],
        "AmazonS3": ["aws-s3", "cdn"],
        "gunicorn": ["gunicorn", "servers"],
        "uvicorn": ["uvicorn", "servers"],
    },
}

BODY_SIGNATURES: list[tuple[str, str, str]] = [
    # (regex_pattern, tech_name, category)
    (r"__NEXT_DATA__", "Next.js", "frameworks"),
    (r"__NUXT__", "Nuxt.js", "frameworks"),
    (r"ng-version", "Angular", "frameworks"),
    (r"data-reactroot", "React", "frameworks"),
    (r"__vue__", "Vue.js", "frameworks"),
    (r"__svelte", "Svelte", "frameworks"),
    (r"wp-content", "WordPress", "cms"),
    (r"drupal", "Drupal", "cms"),
    (r"joomla", "Joomla", "cms"),
    (r"shopify", "Shopify", "cms"),
    (r"window\.Webflow", "Webflow", "cms"),
    (r"cdn\.jsdelivr\.net", "jsDelivr", "cdn"),
    (r"cdnjs\.cloudflare\.com", "Cloudflare CDN", "cdn"),
    (r"unpkg\.com", "unpkg", "cdn"),
    (r"/graphql", "GraphQL", "api"),
    (r"apollo-client", "Apollo GraphQL", "js_libraries"),
    (r"socket\.io", "Socket.IO", "js_libraries"),
    (r"jquery", "jQuery", "js_libraries"),
    (r"bootstrap", "Bootstrap", "js_libraries"),
    (r"tailwindcss", "Tailwind CSS", "js_libraries"),
]


class TechFingerprinter:
    """Detect technologies from HTTP response headers and body content."""

    def __init__(self, timeout: int = 10) -> None:
        self.timeout = timeout

    async def detect(self, url: str) -> TechProfile:
        """Fingerprint a URL's technology stack."""
        profile = TechProfile(url=url)

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=self.timeout) as client:
                resp = await client.get(url)
                profile.raw_headers = dict(resp.headers)
                self._scan_headers(resp.headers, profile)
                self._scan_body(resp.text, profile)
        except Exception as e:
            logger.debug(f"Tech fingerprint failed for {url}: {e}")

        # Infer SPA
        profile.is_spa = bool(
            set(profile.frameworks) & {"React", "Angular", "Vue.js", "Next.js", "Nuxt.js", "Svelte"}
        )
        profile.has_graphql = "GraphQL" in profile.frameworks or any("graphql" in f.lower() for f in profile.js_libraries)
        profile.has_api = profile.has_graphql or any("/api" in profile.url.lower() for _ in [1])

        # Deduplicate
        for attr in ("frameworks", "languages", "servers", "cms", "cdn", "js_libraries"):
            setattr(profile, attr, sorted(set(getattr(profile, attr))))

        return profile

    def _scan_headers(self, headers: httpx.Headers, profile: TechProfile) -> None:
        """Check response headers against known signatures."""
        for header_name, sigs in HEADER_SIGNATURES.items():
            value = headers.get(header_name, "").lower()
            if not value:
                continue
            for keyword, (tech, category) in sigs.items():
                if keyword.lower() in value:
                    getattr(profile, category).append(tech)

    def _scan_body(self, body: str, profile: TechProfile) -> None:
        """Check response body against known signatures."""
        for pattern, tech, category in BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                if category == "api":
                    profile.has_api = True
                    if tech == "GraphQL":
                        profile.has_graphql = True
                else:
                    getattr(profile, category).append(tech)

    async def detect_bulk(self, urls: list[str], concurrency: int = 10) -> dict[str, TechProfile]:
        """Fingerprint multiple URLs concurrently."""
        import asyncio
        sem = asyncio.Semaphore(concurrency)
        results: dict[str, TechProfile] = {}

        async def detect_one(url: str):
            async with sem:
                results[url] = await self.detect(url)

        await asyncio.gather(*[detect_one(u) for u in urls], return_exceptions=True)
        return results
