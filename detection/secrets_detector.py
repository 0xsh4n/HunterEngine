"""
Secrets detection module.

Scans for exposed API keys, tokens, credentials in:
  - JS files (from crawl phase)
  - .env files
  - Git exposure (.git/config)
  - Response bodies
  - package.json / package-lock.json
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.secrets")


SENSITIVE_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/.aws/credentials",
    "/.npmrc",
    "/wp-config.php.bak",
    "/.htpasswd",
    "/server-status",
    "/phpinfo.php",
    "/.DS_Store",
]


class SecretsDetector(BaseDetector):
    """Detect exposed secrets, credentials, and sensitive files."""

    @property
    def name(self) -> str:
        return "secrets"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # 1. Check JS secrets from crawl phase
        for signal in scan_state.weak_signals:
            if signal.get("source") in ("jsluice", "regex", "js_regex"):
                findings.append(self._make_finding(
                    title=f"Exposed {signal.get('type', 'Secret')} in JavaScript",
                    description=(
                        f"A {signal.get('type', 'secret')} was found in a JavaScript file. "
                        f"Source: {signal.get('source_url', 'unknown')}"
                    ),
                    severity=Severity.HIGH if signal.get("severity") == "high" else Severity.MEDIUM,
                    confidence=signal.get("confidence", 0.7),
                    url=signal.get("source_url", ""),
                    evidence=f"Type: {signal.get('type')}\nValue: {signal.get('value', '')}",
                    tags=["secret", "js"],
                ))

        # 2. Probe for sensitive files
        live_urls = [h.get("url", "") for h in scan_state.live_hosts]
        for base_url in live_urls[:30]:
            results = await self._probe_sensitive_paths(base_url)
            findings.extend(results)

        # 3. Check package files for info disclosure
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if any(url.endswith(p) for p in ("package.json", "package-lock.json", "composer.json")):
                result = await self._check_package_file(url)
                if result:
                    findings.append(result)

        logger.info(f"Secrets detector: {len(findings)} findings")
        return findings

    async def _probe_sensitive_paths(self, base_url: str) -> list[dict]:
        """Probe a host for common sensitive file paths."""
        findings = []

        async def check_path(path: str):
            url = base_url.rstrip("/") + path
            resp = await self._get(url)
            if not resp or resp.status_code != 200:
                return

            body = resp.text[:5000]
            content_type = resp.headers.get("content-type", "")

            # Validate it's actual sensitive content, not a generic 200 page
            if len(body) < 10:
                return
            if "text/html" in content_type and "<html" in body.lower() and ".env" in path:
                return  # Likely a custom 404 page

            if ".env" in path and "=" in body:
                findings.append(self._make_finding(
                    title=f"Exposed Environment File ({path})",
                    description=f"Environment variables file accessible at {url}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    url=url,
                    evidence=self._truncate_evidence(body),
                    tags=["secret", "env", "config"],
                    impact="Environment files often contain database credentials, API keys, and secrets.",
                    remediation="Block access to .env files in your web server configuration.",
                ))
            elif ".git" in path:
                findings.append(self._make_finding(
                    title=f"Exposed Git Repository ({path})",
                    description=f"Git repository metadata accessible at {url}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    url=url,
                    evidence=self._truncate_evidence(body),
                    tags=["secret", "git", "source-code"],
                    impact="Git exposure can reveal source code, credentials, and internal project structure.",
                    remediation="Block access to .git directories in your web server configuration.",
                ))
            elif path in ("/.DS_Store", "/.htpasswd", "/server-status"):
                findings.append(self._make_finding(
                    title=f"Sensitive File Exposed ({path})",
                    description=f"Sensitive file accessible at {url}",
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    url=url,
                    evidence=self._truncate_evidence(body),
                    tags=["secret", "info-disclosure"],
                ))

        await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS], return_exceptions=True)
        return findings

    async def _check_package_file(self, url: str) -> Optional[dict]:
        """Check if a package.json/lock file reveals sensitive info."""
        resp = await self._get(url)
        if not resp or resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        # Look for private registry URLs, internal package names, scripts with secrets
        sensitive_keys = []
        if "scripts" in data:
            for script_name, script_val in data.get("scripts", {}).items():
                if any(kw in script_val.lower() for kw in ("password", "secret", "token", "key=")):
                    sensitive_keys.append(f"scripts.{script_name}")

        if "repository" in data:
            repo = data.get("repository", {})
            repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
            if "internal" in repo_url or "private" in repo_url:
                sensitive_keys.append("repository (internal)")

        if sensitive_keys:
            return self._make_finding(
                title="Information Disclosure via Package File",
                description=f"Package file at {url} exposes internal details: {', '.join(sensitive_keys)}",
                severity=Severity.LOW,
                confidence=0.7,
                url=url,
                evidence=self._truncate_evidence(json.dumps(data, indent=2)),
                tags=["info-disclosure", "package"],
            )

        return None
