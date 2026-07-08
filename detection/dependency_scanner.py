"""
Dependency vulnerability scanning.

Cross-references exposed package.json / package-lock.json
against known vulnerability databases.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

import httpx

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.deps")


class DependencyScanner(BaseDetector):
    """Scan exposed dependency files for known vulnerabilities."""

    @property
    def name(self) -> str:
        return "dependency"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Find exposed package files from endpoints
        dep_urls = []
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if any(url.endswith(f) for f in (
                "package.json", "package-lock.json", "yarn.lock",
                "composer.json", "composer.lock",
                "Gemfile.lock", "requirements.txt",
                "go.sum", "Cargo.lock",
            )):
                dep_urls.append(url)

        # Also probe live hosts for package files
        for host in scan_state.live_hosts[:30]:
            base = host.get("url", "")
            for path in ("/package.json", "/package-lock.json"):
                resp = await self._get(base.rstrip("/") + path)
                if resp and resp.status_code == 200:
                    try:
                        resp.json()
                        dep_urls.append(base.rstrip("/") + path)
                    except Exception:
                        pass

        dep_urls = list(set(dep_urls))

        for url in dep_urls:
            result = await self._analyze_dependency_file(url)
            findings.extend(result)

        logger.info(f"Dependency scanner: {len(findings)} findings")
        return findings

    async def _analyze_dependency_file(self, url: str) -> list[dict]:
        """Download and analyze a dependency file."""
        findings = []

        resp = await self._get(url)
        if not resp or resp.status_code != 200:
            return findings

        try:
            data = resp.json()
        except Exception:
            return findings

        # Extract dependencies
        deps: dict[str, str] = {}

        if "dependencies" in data:
            deps.update(data["dependencies"])
        if "devDependencies" in data:
            deps.update(data["devDependencies"])

        # For package-lock.json, extract from packages
        if "packages" in data:
            for pkg_path, pkg_info in data.get("packages", {}).items():
                if pkg_path and "node_modules/" in pkg_path:
                    name = pkg_path.split("node_modules/")[-1]
                    version = pkg_info.get("version", "")
                    if name and version:
                        deps[name] = version

        if not deps:
            return findings

        # First finding: the file itself is exposed
        findings.append(self._make_finding(
            title="Exposed Dependency Manifest",
            description=(
                f"The dependency file at {url} is publicly accessible, "
                f"revealing {len(deps)} packages and their versions."
            ),
            severity=Severity.LOW,
            confidence=0.95,
            url=url,
            evidence=f"Total packages: {len(deps)}\nSample: {dict(list(deps.items())[:10])}",
            tags=["info-disclosure", "dependencies"],
            impact="Attackers can identify vulnerable package versions to target.",
            remediation="Block public access to dependency manifest files.",
        ))

        # Check known vulnerable packages via npm audit API
        vulnerable = await self._check_npm_audit(deps)
        for vuln in vulnerable:
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            findings.append(self._make_finding(
                title=f"Vulnerable Dependency: {vuln['package']}@{vuln['version']}",
                description=(
                    f"The package {vuln['package']}@{vuln['version']} has a known "
                    f"vulnerability: {vuln.get('title', 'Unknown')}."
                ),
                severity=sev_map.get(vuln.get("severity", ""), Severity.MEDIUM),
                confidence=0.85,
                url=url,
                evidence=(
                    f"Package: {vuln['package']}@{vuln['version']}\n"
                    f"Advisory: {vuln.get('title', 'N/A')}\n"
                    f"Severity: {vuln.get('severity', 'unknown')}\n"
                    f"Patched in: {vuln.get('patched_version', 'N/A')}"
                ),
                tags=["dependency", "cve", vuln["package"]],
                references=vuln.get("references", []),
                remediation=f"Update {vuln['package']} to version {vuln.get('patched_version', 'latest')}.",
            ))

        return findings

    async def _check_npm_audit(self, deps: dict[str, str]) -> list[dict]:
        """Check npm packages against the registry for known vulnerabilities."""
        vulnerable = []

        # Use npm registry advisories API (bulk)
        try:
            # Format for npm audit: {"package_name": ["version"]}
            audit_payload = {}
            for name, version in deps.items():
                clean_version = re.sub(r'[^\d.]', '', version)
                if clean_version:
                    audit_payload[name] = [clean_version]

            if not audit_payload:
                return vulnerable

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    "https://registry.npmjs.org/-/npm/v1/security/audits",
                    json={
                        "name": "audit-check",
                        "version": "1.0.0",
                        "requires": {k: v[0] for k, v in audit_payload.items()},
                        "dependencies": {
                            k: {"version": v[0]} for k, v in audit_payload.items()
                        },
                    },
                    headers={"Content-Type": "application/json"},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    advisories = data.get("advisories", {})
                    for adv_id, adv in advisories.items():
                        vulnerable.append({
                            "package": adv.get("module_name", ""),
                            "version": deps.get(adv.get("module_name", ""), ""),
                            "title": adv.get("title", ""),
                            "severity": adv.get("severity", ""),
                            "patched_version": adv.get("patched_versions", ""),
                            "references": [adv.get("url", "")],
                        })

        except Exception as e:
            logger.debug(f"npm audit check failed: {e}")

        return vulnerable
