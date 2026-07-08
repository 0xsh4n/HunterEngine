"""
Parameter correlator.

Correlates parameters across different endpoints to identify
shared backend handlers, common patterns, and systemic issues.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hunterengine.memory.params")


class ParamCorrelator:
    """Correlate parameters across endpoints for systemic vulnerability detection."""

    def correlate(self, params: dict[str, list[str]]) -> dict[str, list[str]]:
        """
        Find parameters that appear across multiple endpoints.

        Args:
            params: Dict mapping URL → list of parameter names

        Returns:
            Dict mapping parameter name → list of URLs where it appears
        """
        param_to_urls: dict[str, list[str]] = defaultdict(list)

        for url, param_list in params.items():
            for p in param_list:
                param_to_urls[p.lower()].append(url)

        # Filter to params appearing in multiple endpoints
        return {
            param: urls
            for param, urls in param_to_urls.items()
            if len(urls) >= 2
        }

    def find_shared_handlers(self, params: dict[str, list[str]]) -> list[dict]:
        """
        Identify endpoints that likely share a backend handler
        based on overlapping parameter sets.
        """
        groups: list[dict] = []
        urls = list(params.keys())

        for i, url_a in enumerate(urls):
            params_a = set(p.lower() for p in params[url_a])
            if len(params_a) < 2:
                continue

            for url_b in urls[i + 1:]:
                params_b = set(p.lower() for p in params[url_b])
                if len(params_b) < 2:
                    continue

                overlap = params_a & params_b
                if len(overlap) >= 2:
                    similarity = len(overlap) / min(len(params_a), len(params_b))
                    if similarity >= 0.5:
                        groups.append({
                            "urls": [url_a, url_b],
                            "shared_params": sorted(overlap),
                            "similarity": round(similarity, 2),
                        })

        return groups

    def find_interesting_params(self, params: dict[str, list[str]]) -> dict[str, list[str]]:
        """
        Identify parameters with interesting names that warrant
        deeper testing (auth-related, debug, file access, etc.).
        """
        INTERESTING = {
            "auth": ["token", "auth", "key", "api_key", "apikey", "secret", "jwt", "session"],
            "file_access": ["file", "path", "dir", "folder", "doc", "document", "upload", "download"],
            "injection": ["query", "search", "q", "sql", "cmd", "command", "exec"],
            "redirect": ["url", "redirect", "next", "return", "callback", "goto", "dest"],
            "debug": ["debug", "test", "verbose", "trace", "dev", "admin"],
            "id_reference": ["id", "uid", "user_id", "account_id", "order_id"],
        }

        results: dict[str, list[str]] = defaultdict(list)

        for url, param_list in params.items():
            for p in param_list:
                p_lower = p.lower()
                for category, keywords in INTERESTING.items():
                    if any(kw in p_lower for kw in keywords):
                        results[category].append(f"{url}?{p}")
                        break

        return dict(results)

    def detect_anomalies(
        self,
        current_params: dict[str, list[str]],
        historical_params: dict[str, list[str]],
    ) -> list[dict]:
        """
        Compare current vs. historical parameter sets to find anomalies.
        New params on existing endpoints may indicate new features to test.
        """
        anomalies = []

        for url in current_params:
            current = set(current_params[url])
            historical = set(historical_params.get(url, []))

            new_params = current - historical
            removed_params = historical - current

            if new_params:
                anomalies.append({
                    "url": url,
                    "type": "new_params",
                    "params": sorted(new_params),
                    "message": f"{len(new_params)} new parameters discovered",
                })

            if removed_params:
                anomalies.append({
                    "url": url,
                    "type": "removed_params",
                    "params": sorted(removed_params),
                    "message": f"{len(removed_params)} parameters no longer present",
                })

        return anomalies
