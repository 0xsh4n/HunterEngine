"""CORS misconfiguration hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class CORSHunter(HunterSubagent):
    name = "cors"
    max_probes = 6

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty CORS hunter. "
            "Target authenticated/API endpoints that may reflect Origin. "
            "Suggest Origin header probes like https://evil.example with "
            "location=header, parameter=Origin, check=reflect or check=status_diff. "
            "Look for ACAO reflection + ACAC true patterns in rationale. "
            "Non-destructive only. Return compact JSON only."
        )
