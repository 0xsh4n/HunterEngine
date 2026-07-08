"""
SSRF detection module.

Uses interactsh-client for out-of-band callback detection
to identify server-side request forgery vulnerabilities.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlencode

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.ssrf")

# Parameters commonly vulnerable to SSRF
SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "target", "rurl",
    "domain", "host", "site", "page", "feed", "src", "source",
    "file", "reference", "ref", "img", "image", "link", "load",
    "callback", "return", "next", "data", "proxy", "webhook",
    "fetch", "request", "endpoint", "resource",
]


class SSRFDetector(BaseDetector):
    """Detect server-side request forgery via OOB callback detection."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._has_interactsh = shutil.which("interactsh-client") is not None
        self._callback_domain: Optional[str] = None

    @property
    def name(self) -> str:
        return "ssrf"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Identify SSRF-prone parameters
        targets = self._find_ssrf_targets(scan_state)

        if not targets:
            logger.info("No SSRF-prone parameters found")
            return findings

        logger.info(f"Testing {len(targets)} potential SSRF vectors")

        if self._has_interactsh:
            findings = await self._test_with_interactsh(targets)
        else:
            findings = await self._test_blind(targets)

        logger.info(f"SSRF detector: {len(findings)} findings")
        return findings

    def _find_ssrf_targets(self, scan_state: Any) -> list[dict]:
        """Find endpoints with URL/path-like parameters."""
        targets = []

        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            parsed = urlparse(url)
            if not parsed.query:
                continue

            for param in parsed.query.split("&"):
                if "=" in param:
                    key, value = param.split("=", 1)
                    key_lower = key.lower()
                    if key_lower in SSRF_PARAMS or self._looks_like_url_param(value):
                        targets.append({
                            "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            "param": key,
                            "original_value": value,
                            "method": ep.get("method", "GET"),
                        })

        # From discovered params
        for url, params in scan_state.params.items():
            for p in params:
                if p.lower() in SSRF_PARAMS:
                    targets.append({
                        "url": url,
                        "param": p,
                        "original_value": "",
                        "method": "GET",
                    })

        return targets[:200]

    @staticmethod
    def _looks_like_url_param(value: str) -> bool:
        """Check if a param value looks like it takes a URL."""
        return (
            value.startswith("http") or
            value.startswith("//") or
            value.startswith("/") or
            "." in value and "/" in value
        )

    async def _test_with_interactsh(self, targets: list[dict]) -> list[dict]:
        """Test SSRF using interactsh for OOB callback detection."""
        findings = []

        # Start interactsh-client and get a callback domain
        logger.info("Starting interactsh-client for OOB detection")

        output_file = tempfile.mktemp(suffix=".json")
        proc = await asyncio.create_subprocess_exec(
            "interactsh-client", "-json", "-o", output_file,
            "-n", "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # Read the generated callback domain from output
            await asyncio.sleep(3)
            stdout_partial = await proc.stdout.read(4096) if proc.stdout else b""
            lines = stdout_partial.decode().strip().splitlines()

            callback_domain = None
            for line in lines:
                line = line.strip()
                if "." in line and not line.startswith("{") and not line.startswith("["):
                    callback_domain = line
                    break

            if not callback_domain:
                logger.warning("Could not get interactsh callback domain")
                proc.terminate()
                return findings

            self._callback_domain = callback_domain
            logger.info(f"Interactsh callback domain: {callback_domain}")

            # Test each target
            for i, target in enumerate(targets):
                url = target["url"]
                param = target["param"]
                identifier = f"ssrf{i:04d}"
                payload_url = f"http://{identifier}.{callback_domain}"

                resp = await self._request(
                    target.get("method", "GET"),
                    url,
                    params={param: payload_url},
                )

            # Wait for callbacks
            await asyncio.sleep(10)
            proc.terminate()

            # Parse results
            output_path = Path(output_file)
            if output_path.exists():
                for line in output_path.read_text().strip().splitlines():
                    try:
                        data = json.loads(line)
                        # Extract identifier to map back to target
                        full_id = data.get("full-id", "")
                        for i, target in enumerate(targets):
                            identifier = f"ssrf{i:04d}"
                            if identifier in full_id:
                                findings.append(self._make_finding(
                                    title=f"Server-Side Request Forgery via '{target['param']}'",
                                    description=(
                                        f"The parameter '{target['param']}' on {target['url']} "
                                        "triggered an out-of-band DNS/HTTP callback, confirming "
                                        "the server makes requests to attacker-controlled URLs."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence=0.95,
                                    url=target["url"],
                                    parameter=target["param"],
                                    evidence=(
                                        f"Callback received:\n"
                                        f"Protocol: {data.get('protocol', 'unknown')}\n"
                                        f"Remote Address: {data.get('remote-address', 'unknown')}\n"
                                        f"Timestamp: {data.get('timestamp', 'unknown')}"
                                    ),
                                    tags=["ssrf", "oob", "verified"],
                                    impact=(
                                        "SSRF can be used to access internal services, "
                                        "read cloud metadata (e.g. AWS IMDSv1), scan internal networks, "
                                        "or exfiltrate data."
                                    ),
                                    remediation=(
                                        "Validate and sanitize URL parameters on the server side. "
                                        "Use an allowlist of permitted domains/IPs. "
                                        "Block requests to internal/private IP ranges. "
                                        "Use IMDSv2 on cloud instances."
                                    ),
                                ))
                                break
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.error(f"Interactsh testing failed: {e}")
            proc.terminate()
        finally:
            Path(output_file).unlink(missing_ok=True)

        return findings

    async def _test_blind(self, targets: list[dict]) -> list[dict]:
        """Fallback: test for SSRF indicators without OOB."""
        findings = []

        for target in targets[:50]:
            url = target["url"]
            param = target["param"]

            # Test with localhost — compare timing/response differences
            normal_resp = await self._get(url, params={param: "https://example.com"})
            if not normal_resp:
                continue
            normal_time = normal_resp.elapsed.total_seconds() if hasattr(normal_resp, 'elapsed') else 0

            test_resp = await self._get(url, params={param: "http://127.0.0.1:1"})
            if not test_resp:
                continue
            test_time = test_resp.elapsed.total_seconds() if hasattr(test_resp, 'elapsed') else 0

            # Significant response difference may indicate SSRF
            if (abs(len(test_resp.content) - len(normal_resp.content)) > 200 or
                    test_resp.status_code != normal_resp.status_code):
                findings.append(self._make_finding(
                    title=f"Potential SSRF via '{param}' (Response Differential)",
                    description=(
                        f"The parameter '{param}' on {url} shows different responses "
                        "when given internal vs. external URLs, which may indicate SSRF."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.5,
                    url=url,
                    parameter=param,
                    evidence=(
                        f"External URL response: {normal_resp.status_code} ({len(normal_resp.content)} bytes)\n"
                        f"Internal URL response: {test_resp.status_code} ({len(test_resp.content)} bytes)"
                    ),
                    tags=["ssrf", "differential", "needs-verification"],
                ))

        return findings
