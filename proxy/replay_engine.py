"""
Request replay engine (Burp Repeater equivalent).

Provides an interface to replay captured proxy requests with
modifications for manual testing and verification.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

from core.proxy_engine import ProxyRequest, ProxyResponse

logger = logging.getLogger("hunterengine.proxy.replay")


@dataclass
class ReplayResult:
    """Result of a replayed request."""
    original_request: ProxyRequest
    modified_request: dict
    response: ProxyResponse
    elapsed_ms: float
    diff_from_original: dict


class ReplayEngine:
    """
    Request replay and modification tool.

    Features:
      - Replay any captured request
      - Modify headers, body, method, URL
      - Compare responses (original vs modified)
      - Batch replay with parameter fuzzing
    """

    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout
        self._history: list[ReplayResult] = []

    async def replay(
        self,
        request: ProxyRequest,
        modifications: Optional[dict] = None,
        original_response: Optional[ProxyResponse] = None,
    ) -> ReplayResult:
        """
        Replay a request with optional modifications.

        Args:
            request: Original captured request
            modifications: Optional dict with keys: headers, body, method, url, params
            original_response: Original response for diff comparison
        """
        mods = modifications or {}
        method = mods.get("method", request.method)
        url = mods.get("url", request.url)
        headers = {**request.headers, **mods.get("headers", {})}
        body = mods.get("body", request.body)

        # Remove proxy-specific headers
        for h in ("proxy-connection", "proxy-authorization"):
            headers.pop(h, None)

        start = time.monotonic()
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
        elapsed = (time.monotonic() - start) * 1000

        proxy_response = ProxyResponse(
            request_id=request.id,
            timestamp=time.time(),
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=resp.content,
            content_type=resp.headers.get("content-type", ""),
        )

        # Compute diff
        diff = {}
        if original_response:
            diff = self._compute_diff(original_response, proxy_response)

        result = ReplayResult(
            original_request=request,
            modified_request=mods,
            response=proxy_response,
            elapsed_ms=round(elapsed, 2),
            diff_from_original=diff,
        )
        self._history.append(result)
        return result

    async def replay_with_variations(
        self,
        request: ProxyRequest,
        param_name: str,
        values: list[str],
    ) -> list[ReplayResult]:
        """
        Replay a request multiple times with different parameter values.
        Useful for fuzzing a specific parameter.
        """
        results = []

        for value in values:
            # Modify the parameter in URL or body
            url = request.url
            body = request.body

            if f"{param_name}=" in url:
                import re
                url = re.sub(
                    f"{re.escape(param_name)}=[^&]*",
                    f"{param_name}={value}",
                    url,
                )
                modifications = {"url": url}
            elif body:
                body_str = body.decode("utf-8", errors="ignore")
                if f"{param_name}=" in body_str:
                    import re
                    body_str = re.sub(
                        f"{re.escape(param_name)}=[^&]*",
                        f"{param_name}={value}",
                        body_str,
                    )
                    modifications = {"body": body_str.encode()}
                elif body_str.startswith("{"):
                    try:
                        data = json.loads(body_str)
                        data[param_name] = value
                        modifications = {"body": json.dumps(data).encode()}
                    except json.JSONDecodeError:
                        modifications = {}
                else:
                    modifications = {}
            else:
                modifications = {"url": f"{url}{'&' if '?' in url else '?'}{param_name}={value}"}

            result = await self.replay(request, modifications)
            results.append(result)

        return results

    async def compare_auth(
        self,
        request: ProxyRequest,
        auth_headers: list[dict[str, str]],
    ) -> list[ReplayResult]:
        """
        Replay a request with different auth contexts.
        Useful for testing IDOR/access control.
        """
        results = []
        for headers in auth_headers:
            result = await self.replay(request, {"headers": headers})
            results.append(result)
        return results

    def _compute_diff(self, original: ProxyResponse, modified: ProxyResponse) -> dict:
        """Compute differences between original and modified responses."""
        return {
            "status_changed": original.status_code != modified.status_code,
            "status_original": original.status_code,
            "status_modified": modified.status_code,
            "size_diff": len(modified.body) - len(original.body),
            "size_original": len(original.body),
            "size_modified": len(modified.body),
            "content_type_changed": original.content_type != modified.content_type,
            "headers_diff": {
                k: v for k, v in modified.headers.items()
                if original.headers.get(k) != v
            },
        }

    def get_history(self) -> list[ReplayResult]:
        """Get replay history."""
        return list(self._history)

    def clear_history(self) -> None:
        """Clear replay history."""
        self._history.clear()
