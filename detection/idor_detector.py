"""
IDOR detection module.

Tests for Insecure Direct Object References by comparing
responses across different ID values and auth contexts.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.idor")


class IDORDetector(BaseDetector):
    """Detect IDOR/BOLA vulnerabilities via sequential ID diffing."""

    @property
    def name(self) -> str:
        return "idor"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Find endpoints with numeric or UUID-like IDs
        targets = self._find_idor_targets(scan_state)
        logger.info(f"Testing {len(targets)} IDOR candidates")

        for target in targets[:100]:
            result = await self._test_idor(target)
            findings.extend(result)

        logger.info(f"IDOR detector: {len(findings)} findings")
        return findings

    def _find_idor_targets(self, scan_state: Any) -> list[dict]:
        """Identify endpoints with object reference patterns."""
        targets = []
        id_pattern = re.compile(r'/(\d{1,10})(?:/|$|\?)')
        uuid_pattern = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)', re.I)

        seen = set()
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if not url or url in seen:
                continue
            seen.add(url)

            parsed = urlparse(url)
            path = parsed.path

            # Check for numeric IDs in path
            for match in id_pattern.finditer(path):
                id_val = match.group(1)
                if int(id_val) < 100000:  # Likely an object ID
                    targets.append({
                        "url": url,
                        "id_value": id_val,
                        "id_type": "numeric",
                        "id_location": "path",
                        "method": ep.get("method", "GET"),
                    })

            # Check for UUIDs in path
            for match in uuid_pattern.finditer(path):
                targets.append({
                    "url": url,
                    "id_value": match.group(1),
                    "id_type": "uuid",
                    "id_location": "path",
                    "method": ep.get("method", "GET"),
                })

            # Check for ID parameters in query string
            for key, values in parse_qs(parsed.query).items():
                key_lower = key.lower()
                if key_lower in ("id", "user_id", "uid", "account_id", "order_id", "item_id",
                                  "doc_id", "file_id", "report_id", "invoice_id"):
                    for val in values:
                        targets.append({
                            "url": url,
                            "id_value": val,
                            "id_type": "numeric" if val.isdigit() else "string",
                            "id_location": "query",
                            "id_param": key,
                            "method": ep.get("method", "GET"),
                        })

        return targets

    async def _test_idor(self, target: dict) -> list[dict]:
        """Test a single endpoint for IDOR by requesting adjacent IDs."""
        findings = []
        url = target["url"]
        id_value = target["id_value"]
        id_type = target["id_type"]
        method = target.get("method", "GET")

        # Get original response
        original = await self._request(method, url)
        if not original or original.status_code >= 400:
            return findings

        original_len = len(original.content)

        # Generate adjacent IDs
        if id_type == "numeric" and id_value.isdigit():
            original_id = int(id_value)
            test_ids = [str(original_id + d) for d in [1, -1, 2, -2] if original_id + d > 0]
        else:
            return findings  # Can't easily enumerate UUIDs

        for test_id in test_ids:
            # Build test URL
            if target["id_location"] == "path":
                test_url = url.replace(f"/{id_value}/", f"/{test_id}/")
                test_url = test_url.replace(f"/{id_value}?", f"/{test_id}?")
                if test_url == url:
                    # ID at end of path
                    test_url = url[:url.rfind(id_value)] + test_id + url[url.rfind(id_value) + len(id_value):]
            else:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                param_name = target.get("id_param", "id")
                params[param_name] = [test_id]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

            if test_url == url:
                continue

            test_resp = await self._request(method, test_url)
            if not test_resp:
                continue

            # Analyze response
            test_len = len(test_resp.content)

            if test_resp.status_code == 200 and test_len > 100:
                # Got data for a different object — potential IDOR
                size_ratio = min(original_len, test_len) / max(original_len, test_len, 1)

                if size_ratio > 0.3:  # Responses are structurally similar
                    # Check if content is actually different (not the same record)
                    if test_resp.text != original.text:
                        findings.append(self._make_finding(
                            title=f"Potential IDOR — Accessible Object with ID {test_id}",
                            description=(
                                f"Changing the object ID from '{id_value}' to '{test_id}' "
                                f"at {url} returned a valid 200 response with different content. "
                                "This may indicate an Insecure Direct Object Reference allowing "
                                "access to other users' data."
                            ),
                            severity=Severity.HIGH,
                            confidence=0.6,
                            url=test_url,
                            parameter=target.get("id_param", "path_id"),
                            evidence=(
                                f"Original ID: {id_value} → {original.status_code} ({original_len} bytes)\n"
                                f"Test ID: {test_id} → {test_resp.status_code} ({test_len} bytes)\n"
                                f"Content differs: True\n"
                                f"Size similarity: {size_ratio:.2f}"
                            ),
                            tags=["idor", "bola", "access-control"],
                            impact=(
                                "An attacker can access, modify, or delete other users' objects "
                                "by manipulating the object ID."
                            ),
                            remediation=(
                                "Implement proper authorization checks — verify the requesting user "
                                "owns or has permission to access the requested object. "
                                "Use unpredictable identifiers (UUIDs) as a defense-in-depth measure."
                            ),
                        ))
                        break  # One finding per endpoint

        return findings
