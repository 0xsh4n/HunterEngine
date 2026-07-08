"""
GraphQL schema extraction and mapping.

Discovers GraphQL endpoints, extracts schemas via introspection,
and maps queries/mutations/types for the detection phase.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger("hunterengine.crawl.graphql")

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/v1",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
    "/v2/graphql",
]


class GraphQLMapper:
    """Discover and map GraphQL endpoints and schemas."""

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    async def discover_endpoints(self, base_urls: list[str]) -> list[dict]:
        """
        Probe base URLs for GraphQL endpoints.

        Returns list of dicts: {"url": str, "introspection_enabled": bool}
        """
        found = []
        sem = asyncio.Semaphore(10)

        async def probe(base_url: str, path: str):
            url = base_url.rstrip("/") + path
            async with sem:
                try:
                    async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                        # Test with simple introspection
                        resp = await client.post(
                            url,
                            json={"query": "{ __typename }"},
                            headers={"Content-Type": "application/json"},
                        )
                        if resp.status_code == 200:
                            try:
                                data = resp.json()
                                if "data" in data or "errors" in data:
                                    found.append({
                                        "url": url,
                                        "introspection_enabled": False,
                                        "base_url": base_url,
                                    })
                            except Exception:
                                pass
                except Exception:
                    pass

        tasks = [
            probe(base, path)
            for base in base_urls
            for path in COMMON_GRAPHQL_PATHS
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(f"Discovered {len(found)} GraphQL endpoints")
        return found

    async def extract_schema(self, graphql_url: str, headers: Optional[dict] = None) -> Optional[dict]:
        """
        Attempt full introspection on a GraphQL endpoint.

        Returns the schema dict or None if introspection is disabled.
        """
        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                resp = await client.post(
                    graphql_url,
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json", **(headers or {})},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    schema = data.get("data", {}).get("__schema")
                    if schema:
                        logger.info(f"Introspection succeeded on {graphql_url}")
                        return schema

        except Exception as e:
            logger.debug(f"Introspection failed on {graphql_url}: {e}")

        return None

    def parse_schema(self, schema: dict) -> dict[str, Any]:
        """
        Parse an introspected schema into a structured map.

        Returns:
            {"queries": [str], "mutations": [str], "types": [dict],
             "sensitive_fields": [dict]}
        """
        queries = []
        mutations = []
        types_info = []
        sensitive_fields = []

        SENSITIVE_NAMES = {
            "password", "secret", "token", "key", "apiKey",
            "accessToken", "refreshToken", "ssn", "creditCard",
            "email", "phone", "address", "admin", "role",
        }

        for type_def in schema.get("types", []):
            name = type_def.get("name", "")
            if name.startswith("__"):
                continue

            kind = type_def.get("kind", "")
            fields = type_def.get("fields") or []

            type_info = {
                "name": name,
                "kind": kind,
                "fields": [f.get("name", "") for f in fields],
            }
            types_info.append(type_info)

            # Check query/mutation types
            query_type = schema.get("queryType", {}).get("name", "Query")
            mutation_type = schema.get("mutationType", {}).get("name", "Mutation")

            if name == query_type:
                queries = [f.get("name", "") for f in fields]
            elif name == mutation_type:
                mutations = [f.get("name", "") for f in fields]

            # Flag sensitive fields
            for field_def in fields:
                fname = field_def.get("name", "").lower()
                if any(s in fname for s in SENSITIVE_NAMES):
                    sensitive_fields.append({
                        "type": name,
                        "field": field_def.get("name", ""),
                        "description": field_def.get("description", ""),
                    })

        return {
            "queries": queries,
            "mutations": mutations,
            "types": types_info,
            "sensitive_fields": sensitive_fields,
            "type_count": len(types_info),
            "query_count": len(queries),
            "mutation_count": len(mutations),
        }

    async def map_all(
        self,
        base_urls: list[str],
        headers: Optional[dict] = None,
    ) -> list[dict]:
        """Full GraphQL mapping: discover → introspect → parse."""
        endpoints = await self.discover_endpoints(base_urls)

        results = []
        for ep in endpoints:
            schema = await self.extract_schema(ep["url"], headers)
            if schema:
                ep["introspection_enabled"] = True
                ep["schema"] = self.parse_schema(schema)
            results.append(ep)

        return results
