"""HTTP request smuggling hunter subagent (safe header canaries only)."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class SmugglingHunter(HunterSubagent):
    name = "request_smuggling"
    max_probes = 6

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty HTTP request-smuggling researcher. "
            "Prefer endpoints behind likely reverse proxies / CDNs / APIs "
            "(/api/, gateways, load-balanced hosts). "
            "Suggest SAFE differential probes only: ambiguous Content-Length vs "
            "Transfer-Encoding header canaries, duplicate Content-Length, or "
            "TE: chunked with check=status_diff or check=error_leak. "
            "location=header. Do NOT propose full desync exploit chains, "
            "poisoning of other users, or DoS. Return compact JSON only."
        )
