"""
Subdomain takeover detection.

Checks for dangling CNAME records pointing to unclaimed services
(S3, GitHub Pages, Heroku, Azure, etc.) that can be taken over.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.takeover")

# Service fingerprints: (cname_pattern, response_fingerprint, service_name)
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    (r"\.s3\.amazonaws\.com", "NoSuchBucket", "AWS S3"),
    (r"\.s3-website[.-]", "NoSuchBucket", "AWS S3 Website"),
    (r"\.herokuapp\.com", "No such app", "Heroku"),
    (r"\.herokuapp\.com", "no-such-app", "Heroku"),
    (r"\.github\.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    (r"\.ghost\.io", "The thing you were looking for is no longer here", "Ghost"),
    (r"\.myshopify\.com", "Sorry, this shop is currently unavailable", "Shopify"),
    (r"\.tumblr\.com", "There's nothing here", "Tumblr"),
    (r"\.wordpress\.com", "Do you want to register", "WordPress.com"),
    (r"\.pantheonsite\.io", "The gods are wise", "Pantheon"),
    (r"\.zendesk\.com", "Help Center Closed", "Zendesk"),
    (r"\.surge\.sh", "project not found", "Surge.sh"),
    (r"\.bitbucket\.io", "Repository not found", "Bitbucket"),
    (r"\.azurewebsites\.net", "404 Web Site not found", "Azure"),
    (r"\.cloudfront\.net", "Bad Request", "CloudFront"),
    (r"\.elasticbeanstalk\.com", "404 Not Found", "Elastic Beanstalk"),
    (r"\.firebaseapp\.com", "Firebase Hosting Setup Complete", "Firebase"),
    (r"\.netlify\.app", "Not Found", "Netlify"),
    (r"\.ngrok\.io", "Tunnel .* not found", "ngrok"),
    (r"\.fly\.dev", "not found", "Fly.io"),
    (r"\.vercel\.app", "DEPLOYMENT_NOT_FOUND", "Vercel"),
    (r"\.render\.com", "not found", "Render"),
    (r"\.cargocollective\.com", "404 Not Found", "Cargo"),
    (r"\.helpjuice\.com", "We could not find what you're looking for", "Helpjuice"),
    (r"\.helpscoutdocs\.com", "No settings were found", "HelpScout"),
    (r"\.feedpress\.me", "The feed has not been found", "FeedPress"),
    (r"\.freshdesk\.com", "may not exist or is no longer available", "Freshdesk"),
    (r"\.uptimerobot\.com", "page not found", "UptimeRobot"),
    (r"\.tilda\.ws", "Please renew your subscription", "Tilda"),
]

# Patterns that indicate NXDOMAIN or similar resolution failure
NXDOMAIN_INDICATORS = [
    "NXDOMAIN",
    "SERVFAIL",
    "server can't find",
    "Name or service not known",
]


class SubdomainTakeoverDetector(BaseDetector):
    """Detect subdomain takeover via dangling CNAME records."""

    @property
    def name(self) -> str:
        return "subdomain_takeover"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # We need DNS CNAME data — check if we have it, otherwise probe
        subdomains = scan_state.subdomains
        if not subdomains:
            return findings

        logger.info(f"Checking {len(subdomains)} subdomains for takeover")

        tasks = [self._check_subdomain(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                findings.append(result)

        logger.info(f"Subdomain takeover detector: {len(findings)} findings")
        return findings

    async def _check_subdomain(self, subdomain: str) -> Optional[dict]:
        """Check a single subdomain for takeover potential."""
        # First, get CNAME if possible
        cname = await self._get_cname(subdomain)

        if not cname:
            return None

        # Check CNAME against known vulnerable services
        for cname_pattern, response_fingerprint, service in TAKEOVER_FINGERPRINTS:
            if not re.search(cname_pattern, cname, re.IGNORECASE):
                continue

            # Probe the subdomain for the fingerprint response
            for scheme in ("https", "http"):
                url = f"{scheme}://{subdomain}"
                resp = await self._get(url)

                if not resp:
                    # Connection failed — might be dangling
                    return self._make_finding(
                        title=f"Potential Subdomain Takeover — {service}",
                        description=(
                            f"The subdomain {subdomain} has a CNAME record pointing to "
                            f"{cname} ({service}), but the target is not responding. "
                            "This may indicate the service has been deprovisioned and "
                            "the subdomain can be claimed."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.6,
                        url=url,
                        evidence=f"CNAME: {subdomain} → {cname}\nService: {service}\nHTTP: Connection failed",
                        tags=["subdomain-takeover", service.lower().replace(" ", "-")],
                        impact=(
                            "An attacker can claim the deprovisioned service and serve "
                            "arbitrary content under the target's subdomain, enabling "
                            "phishing, cookie stealing, and trust abuse."
                        ),
                        remediation=(
                            f"Either reprovision the {service} resource or remove the "
                            f"dangling CNAME record for {subdomain}."
                        ),
                    )

                if resp.status_code in (404, 0) or re.search(
                    response_fingerprint, resp.text, re.IGNORECASE
                ):
                    return self._make_finding(
                        title=f"Subdomain Takeover — {service}",
                        description=(
                            f"The subdomain {subdomain} points to {cname} ({service}) "
                            f"which returns a '{response_fingerprint}' fingerprint, "
                            "indicating the service is unclaimed and can be taken over."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.85,
                        url=url,
                        evidence=(
                            f"CNAME: {subdomain} → {cname}\n"
                            f"Service: {service}\n"
                            f"HTTP {resp.status_code}\n"
                            f"Fingerprint matched: {response_fingerprint}"
                        ),
                        tags=["subdomain-takeover", service.lower().replace(" ", "-"), "verified"],
                        impact=(
                            "An attacker can claim the deprovisioned service and serve "
                            "arbitrary content under the target's subdomain."
                        ),
                        remediation=(
                            f"Remove the dangling CNAME record for {subdomain}, or "
                            f"reprovision the {service} resource."
                        ),
                    )

        return None

    async def _get_cname(self, hostname: str) -> Optional[str]:
        """Resolve CNAME for a hostname."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode().strip().rstrip(".")
            return cname if cname else None
        except Exception:
            return None
