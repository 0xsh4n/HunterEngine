"""
Prototype pollution detection.

Tests for client-side and server-side prototype pollution
by injecting __proto__ and constructor.prototype payloads
into JSON bodies and query parameters.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.proto")


class PrototypePollutionDetector(BaseDetector):
    """Detect prototype pollution vulnerabilities in Node.js/JS backends."""

    @property
    def name(self) -> str:
        return "prototype_pollution"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Target endpoints that accept JSON (APIs, Node.js backends)
        json_endpoints = []
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            method = ep.get("method", "GET").upper()
            if method in ("POST", "PUT", "PATCH") or "/api/" in url:
                json_endpoints.append(ep)

        # Also check based on tech stack
        node_hosts = set()
        for url, tech in scan_state.tech_stack.items():
            if hasattr(tech, "frameworks"):
                frameworks = tech.frameworks if hasattr(tech, "frameworks") else []
            elif isinstance(tech, dict):
                frameworks = tech.get("frameworks", [])
            else:
                frameworks = []

            if any(f.lower() in ("express", "next.js", "node.js", "koa", "fastify")
                   for f in frameworks):
                node_hosts.add(url)

        # Prioritize Node.js endpoints
        targets = []
        for ep in json_endpoints:
            url = ep.get("url", "")
            priority = 2 if any(url.startswith(h) for h in node_hosts) else 1
            targets.append((ep, priority))

        targets.sort(key=lambda x: x[1], reverse=True)

        for ep, _ in targets[:100]:
            result = await self._test_endpoint(ep)
            findings.extend(result)

        # Client-side PP check via Playwright
        if self.browser:
            client_findings = await self._test_client_side(scan_state)
            findings.extend(client_findings)

        logger.info(f"Prototype pollution detector: {len(findings)} findings")
        return findings

    async def _test_endpoint(self, endpoint: dict) -> list[dict]:
        """Test a single endpoint for server-side prototype pollution."""
        findings = []
        url = endpoint.get("url", "")
        method = endpoint.get("method", "POST").upper()

        # Server-side PP: inject __proto__ in JSON body and observe behavior changes
        test_payloads = [
            {"__proto__": {"huntertest": "polluted"}},
            {"constructor": {"prototype": {"huntertest": "polluted"}}},
        ]

        for payload in test_payloads:
            try:
                # Send with pollution payload
                resp = await self._request(
                    method if method in ("POST", "PUT", "PATCH") else "POST",
                    url,
                    json_body=payload,
                    headers={"Content-Type": "application/json"},
                )
                if not resp:
                    continue

                body = resp.text.lower()

                # Check for indicators of pollution
                # 1. Error messages that reveal __proto__ processing
                if "__proto__" in body and resp.status_code < 500:
                    findings.append(self._make_finding(
                        title="Potential Server-Side Prototype Pollution",
                        description=(
                            f"The endpoint {url} processes __proto__ properties in JSON input. "
                            "The server reflected or processed prototype properties, which may "
                            "indicate vulnerability to prototype pollution."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.65,
                        url=url,
                        method=method,
                        evidence=(
                            f"Payload: {json.dumps(payload)}\n"
                            f"Status: {resp.status_code}\n"
                            f"Response contains __proto__ reference"
                        ),
                        tags=["prototype-pollution", "server-side", "needs-verification"],
                        impact=(
                            "Server-side prototype pollution can lead to denial of service, "
                            "privilege escalation, or remote code execution depending on the application."
                        ),
                        remediation=(
                            "Sanitize JSON input to strip __proto__ and constructor properties. "
                            "Use Object.create(null) for untrusted objects. "
                            "Consider using --frozen-intrinsics in Node.js."
                        ),
                    ))

                # 2. 500 error on __proto__ (may crash the app)
                if resp.status_code == 500:
                    # Check if normal request works fine
                    normal_resp = await self._request(
                        method if method in ("POST", "PUT", "PATCH") else "POST",
                        url,
                        json_body={"normal": "data"},
                        headers={"Content-Type": "application/json"},
                    )
                    if normal_resp and normal_resp.status_code < 500:
                        findings.append(self._make_finding(
                            title="Server Error on __proto__ Injection",
                            description=(
                                f"The endpoint {url} returns a 500 error when __proto__ is included "
                                "in the JSON body, while normal requests succeed. This strongly "
                                "suggests the server processes prototype properties unsafely."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.75,
                            url=url,
                            method=method,
                            evidence=(
                                f"Payload: {json.dumps(payload)}\n"
                                f"__proto__ request status: 500\n"
                                f"Normal request status: {normal_resp.status_code}"
                            ),
                            tags=["prototype-pollution", "server-side", "crash"],
                        ))

            except Exception as e:
                logger.debug(f"PP test failed for {url}: {e}")

        return findings

    async def _test_client_side(self, scan_state: Any) -> list[dict]:
        """Test for client-side prototype pollution via URL parameters."""
        findings = []

        targets = [h.get("url", "") for h in scan_state.live_hosts[:20]]

        for url in targets:
            try:
                # Test with __proto__ in query string
                test_url = f"{url}?__proto__[huntertest]=polluted"
                context = await self.browser.new_context()
                page = await context.new_page()

                await page.goto(test_url, wait_until="networkidle", timeout=10000)
                await page.wait_for_timeout(1000)

                # Check if pollution worked
                result = await page.evaluate(
                    "() => { return ({}).huntertest; }"
                )

                if result == "polluted":
                    findings.append(self._make_finding(
                        title="Client-Side Prototype Pollution",
                        description=(
                            f"The page at {url} is vulnerable to client-side prototype pollution "
                            "via URL query parameters. Injecting __proto__[huntertest]=polluted "
                            "successfully polluted Object.prototype."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.95,
                        url=url,
                        evidence=(
                            f"Test URL: {test_url}\n"
                            f"({{}}).huntertest === 'polluted'"
                        ),
                        tags=["prototype-pollution", "client-side", "verified"],
                    ))

                await context.close()

            except Exception as e:
                logger.debug(f"Client PP test failed for {url}: {e}")

        return findings
