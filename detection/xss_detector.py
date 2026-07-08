"""
XSS detection module.

Wraps dalfox for reflected/DOM XSS scanning, with optional
Playwright-based headless verification to reduce false positives.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.xss")


class XSSDetector(BaseDetector):
    """Detect reflected and DOM-based XSS using dalfox + headless verification."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._has_dalfox = shutil.which("dalfox") is not None
        self.timeout = 300

    @property
    def name(self) -> str:
        return "xss"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Collect URLs with query parameters (primary XSS targets)
        param_urls = []
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if "?" in url or ep.get("method", "GET") == "POST":
                param_urls.append(url)

        # Also include URLs with discovered params
        for url, params in scan_state.params.items():
            for p in params:
                param_urls.append(f"{url}?{p}=testvalue")

        param_urls = list(set(param_urls))[:500]  # Cap

        if not param_urls:
            logger.info("No parameterized URLs found — skipping XSS scan")
            return findings

        if self._has_dalfox:
            findings = await self._run_dalfox(param_urls)
        else:
            findings = await self._run_reflection_check(param_urls)

        # Headless verification for high-value findings
        if self.browser and findings:
            findings = await self._verify_with_browser(findings)

        logger.info(f"XSS detector: {len(findings)} findings")
        return findings

    async def _run_dalfox(self, urls: list[str]) -> list[dict]:
        """Run dalfox scanner against parameterized URLs."""
        logger.info(f"Running dalfox on {len(urls)} URLs")
        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            urls_file = f.name

        try:
            cmd = [
                "dalfox", "file", urls_file,
                "--silence", "--format", "json",
                "--timeout", "10",
                "--delay", "100",
                "--only-poc", "g",
                "--skip-bav",
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)

            for line in stdout.decode().strip().splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    vuln_type = data.get("type", "reflected")
                    poc_url = data.get("data", "")
                    param = data.get("param", "")
                    inject_type = data.get("inject_type", "")

                    severity = Severity.HIGH
                    if "dom" in vuln_type.lower():
                        severity = Severity.HIGH
                    elif "reflected" in vuln_type.lower():
                        severity = Severity.MEDIUM

                    findings.append(self._make_finding(
                        title=f"Cross-Site Scripting ({vuln_type.upper()}) via '{param}'",
                        description=(
                            f"Dalfox detected {vuln_type} XSS on parameter '{param}'. "
                            f"Injection type: {inject_type}."
                        ),
                        severity=severity,
                        confidence=0.85,
                        url=poc_url or data.get("url", ""),
                        parameter=param,
                        evidence=f"PoC URL: {poc_url}\nType: {vuln_type}\nInjection: {inject_type}",
                        tags=["xss", vuln_type.lower()],
                        impact=(
                            "An attacker can execute arbitrary JavaScript in the context of "
                            "an authenticated user's session, potentially stealing cookies, "
                            "session tokens, or performing actions on their behalf."
                        ),
                        remediation=(
                            "Encode all user input before rendering in HTML context. "
                            "Use Content-Security-Policy headers. "
                            "Implement output encoding specific to the context (HTML, JS, URL, CSS)."
                        ),
                    ))
                except json.JSONDecodeError:
                    continue

        finally:
            Path(urls_file).unlink(missing_ok=True)

        return findings

    async def _run_reflection_check(self, urls: list[str]) -> list[dict]:
        """Fallback: check for input reflection (indicator, not confirmed XSS)."""
        logger.info("dalfox not available — running reflection checks")
        findings = []
        canary = "hunter8xss7probe"

        for url in urls[:100]:
            # Inject canary into first param
            if "?" in url:
                base, query = url.split("?", 1)
                parts = query.split("&")
                for i, part in enumerate(parts):
                    if "=" in part:
                        key, _ = part.split("=", 1)
                        test_url = f"{base}?{'&'.join(parts[:i])}&{key}={canary}&{'&'.join(parts[i+1:])}"
                        test_url = test_url.replace("&&", "&").rstrip("&")

                        resp = await self._get(test_url)
                        if resp and canary in resp.text:
                            findings.append(self._make_finding(
                                title=f"Reflected Input on Parameter '{key}'",
                                description=(
                                    f"User input on parameter '{key}' is reflected in the response. "
                                    "This may indicate a potential XSS vulnerability. "
                                    "Manual verification recommended."
                                ),
                                severity=Severity.LOW,
                                confidence=0.5,
                                url=url,
                                parameter=key,
                                evidence=f"Canary '{canary}' reflected in response body",
                                tags=["xss", "reflection", "needs-verification"],
                            ))
                            break  # One per URL

        return findings

    async def _verify_with_browser(self, findings: list[dict]) -> list[dict]:
        """Use Playwright to verify XSS findings by checking for JS execution."""
        verified = []
        for finding in findings:
            url = finding.get("url", "")
            if not url or finding.get("confidence", 0) >= 0.95:
                verified.append(finding)
                continue

            try:
                context = await self.browser.new_context()
                page = await context.new_page()

                dialog_fired = False

                async def handle_dialog(dialog):
                    nonlocal dialog_fired
                    dialog_fired = True
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)

                await page.goto(url, wait_until="networkidle", timeout=10000)
                await page.wait_for_timeout(2000)

                if dialog_fired:
                    finding["confidence"] = 0.98
                    finding["evidence"] += "\n[VERIFIED] Browser dialog triggered — confirmed XSS"
                    finding["severity"] = Severity.HIGH.value
                    finding["tags"].append("verified")

                verified.append(finding)
                await context.close()

            except Exception as e:
                logger.debug(f"Browser verification failed for {url}: {e}")
                verified.append(finding)

        return verified
