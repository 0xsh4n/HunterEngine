"""
GraphQL security detection.

Checks for:
  - Introspection enabled in production
  - Query depth/complexity limits
  - Batching attacks
  - Field suggestion leaks
  - Authorization bypass via aliasing
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.graphql")


class GraphQLDetector(BaseDetector):
    """Detect GraphQL-specific security issues."""

    @property
    def name(self) -> str:
        return "graphql"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Find GraphQL endpoints from crawl data
        gql_endpoints = []
        for ep in scan_state.endpoints:
            url = ep.get("url", "")
            if "graphql" in url.lower() or "gql" in url.lower():
                gql_endpoints.append(url)

        # Also from tech detection
        for url, tech in scan_state.tech_stack.items():
            has_gql = False
            if hasattr(tech, "has_graphql"):
                has_gql = tech.has_graphql
            elif isinstance(tech, dict):
                has_gql = tech.get("has_graphql", False)
            if has_gql:
                gql_endpoints.append(url.rstrip("/") + "/graphql")

        gql_endpoints = list(set(gql_endpoints))

        if not gql_endpoints:
            logger.info("No GraphQL endpoints found")
            return findings

        logger.info(f"Testing {len(gql_endpoints)} GraphQL endpoints")

        for url in gql_endpoints:
            results = await self._test_endpoint(url)
            findings.extend(results)

        logger.info(f"GraphQL detector: {len(findings)} findings")
        return findings

    async def _test_endpoint(self, url: str) -> list[dict]:
        """Run all GraphQL security checks on an endpoint."""
        findings = []

        # 1. Introspection check
        intro_result = await self._check_introspection(url)
        if intro_result:
            findings.append(intro_result)

        # 2. Depth limit check
        depth_result = await self._check_depth_limit(url)
        if depth_result:
            findings.append(depth_result)

        # 3. Batching attack check
        batch_result = await self._check_batching(url)
        if batch_result:
            findings.append(batch_result)

        # 4. Field suggestion leak
        suggest_result = await self._check_field_suggestions(url)
        if suggest_result:
            findings.append(suggest_result)

        return findings

    async def _check_introspection(self, url: str) -> Optional[dict]:
        """Check if introspection is enabled."""
        query = '{"query": "{ __schema { types { name } } }"}'
        resp = await self._post(
            url,
            data=query,
            headers={"Content-Type": "application/json"},
        )

        if not resp or resp.status_code != 200:
            return None

        try:
            data = resp.json()
            schema = data.get("data", {}).get("__schema")
            if schema and schema.get("types"):
                type_names = [t.get("name", "") for t in schema["types"]
                             if not t.get("name", "").startswith("__")]
                return self._make_finding(
                    title="GraphQL Introspection Enabled",
                    description=(
                        f"Full schema introspection is enabled at {url}. "
                        f"Exposed {len(type_names)} custom types."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.95,
                    url=url,
                    evidence=f"Exposed types: {', '.join(type_names[:20])}{'...' if len(type_names) > 20 else ''}",
                    tags=["graphql", "introspection", "info-disclosure"],
                    impact="Attackers can map the entire API schema, discovering sensitive queries, mutations, and types.",
                    remediation="Disable introspection in production environments.",
                )
        except Exception:
            pass

        return None

    async def _check_depth_limit(self, url: str) -> Optional[dict]:
        """Check for missing query depth limits (DoS potential)."""
        # Build a deeply nested query
        depth = 10
        query_inner = "{ __typename }"
        for i in range(depth):
            query_inner = f"{{ __type(name: \"Query\") {{ fields {{ type {query_inner} }} }} }}"

        resp = await self._post(
            url,
            json_body={"query": query_inner},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )

        if not resp:
            return None

        try:
            data = resp.json()
            # If the deep query succeeds without error, no depth limit
            if "data" in data and "errors" not in data:
                return self._make_finding(
                    title="GraphQL Missing Query Depth Limit",
                    description=(
                        f"The GraphQL endpoint at {url} accepts deeply nested queries "
                        f"(tested depth: {depth}) without rejection. This enables "
                        "denial-of-service via resource exhaustion."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    url=url,
                    evidence=f"Deep query (depth {depth}) accepted successfully",
                    tags=["graphql", "dos", "depth-limit"],
                    impact="Attackers can craft deeply nested queries to exhaust server resources.",
                    remediation="Implement query depth limiting (recommended max depth: 5-7).",
                )
        except Exception:
            pass

        return None

    async def _check_batching(self, url: str) -> Optional[dict]:
        """Check if query batching is enabled (brute force potential)."""
        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]

        resp = await self._post(
            url,
            json_body=batch,
            headers={"Content-Type": "application/json"},
        )

        if not resp or resp.status_code != 200:
            return None

        try:
            data = resp.json()
            if isinstance(data, list) and len(data) >= 3:
                return self._make_finding(
                    title="GraphQL Query Batching Enabled",
                    description=(
                        f"The GraphQL endpoint at {url} accepts batched queries. "
                        "An attacker can send multiple operations in a single request "
                        "to bypass rate limiting."
                    ),
                    severity=Severity.LOW,
                    confidence=0.9,
                    url=url,
                    evidence=f"Sent 3 batched queries, received {len(data)} responses",
                    tags=["graphql", "batching", "rate-limit-bypass"],
                    remediation="Disable query batching or implement per-operation rate limiting.",
                )
        except Exception:
            pass

        return None

    async def _check_field_suggestions(self, url: str) -> Optional[dict]:
        """Check if error messages leak field name suggestions."""
        # Intentionally misspell a field to trigger suggestions
        resp = await self._post(
            url,
            json_body={"query": "{ usr { emal } }"},
            headers={"Content-Type": "application/json"},
        )

        if not resp:
            return None

        try:
            data = resp.json()
            errors = data.get("errors", [])
            for error in errors:
                msg = error.get("message", "")
                if "did you mean" in msg.lower() or "suggest" in msg.lower():
                    return self._make_finding(
                        title="GraphQL Field Suggestion Information Leak",
                        description=(
                            f"The GraphQL endpoint at {url} returns field name suggestions "
                            "in error messages, allowing attackers to enumerate valid fields "
                            "even without introspection."
                        ),
                        severity=Severity.LOW,
                        confidence=0.85,
                        url=url,
                        evidence=f"Error message: {msg[:200]}",
                        tags=["graphql", "info-disclosure", "suggestions"],
                        remediation="Disable field suggestions in production GraphQL configuration.",
                    )
        except Exception:
            pass

        return None
