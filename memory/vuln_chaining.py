"""
Vulnerability chaining engine.

Combines individually weak findings into higher-severity
chained vulnerabilities (e.g., open redirect + XSS → P1).
"""

from __future__ import annotations

import logging
from itertools import combinations
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hunterengine.memory.chaining")


# Chain rules: (finding_A_tags, finding_B_tags, chain_title, chain_severity, chain_description)
CHAIN_RULES: list[tuple[set[str], set[str], str, str, str]] = [
    (
        {"open-redirect"},
        {"xss"},
        "Open Redirect → XSS Chain",
        "high",
        "An open redirect can be chained with reflected XSS to bypass same-origin restrictions.",
    ),
    (
        {"cors"},
        {"xss"},
        "CORS Misconfiguration + XSS Chain",
        "critical",
        "CORS misconfiguration combined with XSS enables full cross-origin data theft.",
    ),
    (
        {"ssrf"},
        {"info-disclosure"},
        "SSRF → Internal Data Access",
        "critical",
        "SSRF combined with information disclosure can expose internal services and secrets.",
    ),
    (
        {"idor"},
        {"info-disclosure"},
        "IDOR + Information Disclosure",
        "high",
        "IDOR with data exposure allows mass extraction of user data.",
    ),
    (
        {"csrf"},
        {"idor"},
        "CSRF + IDOR → Account Takeover",
        "critical",
        "CSRF on an IDOR-vulnerable endpoint enables actions on behalf of any user.",
    ),
    (
        {"open-redirect"},
        {"jwt"},
        "Open Redirect → Token Theft",
        "high",
        "An open redirect can leak authentication tokens via the Referer header or fragment.",
    ),
    (
        {"prototype-pollution"},
        {"xss"},
        "Prototype Pollution → XSS",
        "critical",
        "Prototype pollution can be leveraged to achieve cross-site scripting.",
    ),
    (
        {"rate-limit"},
        {"auth"},
        "Missing Rate Limit on Auth → Brute Force",
        "high",
        "Absent rate limiting on authentication endpoints enables credential brute-force attacks.",
    ),
    (
        {"csp", "unsafe-inline"},
        {"xss", "reflection"},
        "Weak CSP + Input Reflection → XSS",
        "high",
        "CSP with unsafe-inline combined with input reflection enables script execution.",
    ),
    (
        {"subdomain-takeover"},
        {"cookie"},
        "Subdomain Takeover → Cookie Theft",
        "critical",
        "A taken-over subdomain can steal cookies scoped to the parent domain.",
    ),
]


class VulnChaining:
    """Chain weak findings into composite high-severity vulnerabilities."""

    def find_chains(self, findings: list[dict], weak_signals: list[dict]) -> list[dict]:
        """
        Analyze findings for potential chaining opportunities.

        Returns list of chained finding dicts with elevated severity.
        """
        all_items = findings + weak_signals
        if len(all_items) < 2:
            return []

        chained: list[dict] = []
        used_pairs: set[tuple[int, int]] = set()

        for i, item_a in enumerate(all_items):
            tags_a = set(item_a.get("tags", []))
            host_a = urlparse(item_a.get("url", "")).netloc

            for j, item_b in enumerate(all_items):
                if i >= j:
                    continue

                pair = (i, j)
                if pair in used_pairs:
                    continue

                tags_b = set(item_b.get("tags", []))
                host_b = urlparse(item_b.get("url", "")).netloc

                # Only chain findings on the same host (or related hosts)
                if host_a and host_b:
                    domain_a = ".".join(host_a.split(".")[-2:])
                    domain_b = ".".join(host_b.split(".")[-2:])
                    if domain_a != domain_b:
                        continue

                # Check against chain rules
                for rule_tags_a, rule_tags_b, title, severity, description in CHAIN_RULES:
                    if (rule_tags_a & tags_a and rule_tags_b & tags_b) or \
                       (rule_tags_a & tags_b and rule_tags_b & tags_a):
                        used_pairs.add(pair)

                        chained.append({
                            "title": title,
                            "description": description,
                            "severity": severity,
                            "confidence": min(
                                item_a.get("confidence", 0.5) + 0.1,
                                item_b.get("confidence", 0.5) + 0.1,
                                0.95,
                            ),
                            "detector": "vuln_chaining",
                            "url": item_a.get("url", ""),
                            "evidence": (
                                f"Chain component A:\n"
                                f"  Title: {item_a.get('title', '')}\n"
                                f"  URL: {item_a.get('url', '')}\n"
                                f"  Tags: {list(tags_a)}\n\n"
                                f"Chain component B:\n"
                                f"  Title: {item_b.get('title', '')}\n"
                                f"  URL: {item_b.get('url', '')}\n"
                                f"  Tags: {list(tags_b)}"
                            ),
                            "tags": ["chained", "escalated"] + list(tags_a | tags_b),
                            "metadata": {
                                "chain_components": [
                                    {"title": item_a.get("title"), "url": item_a.get("url")},
                                    {"title": item_b.get("title"), "url": item_b.get("url")},
                                ],
                            },
                        })
                        break

        logger.info(f"Found {len(chained)} vulnerability chains")
        return chained
