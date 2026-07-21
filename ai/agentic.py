"""Bounded autonomous decision support for black/grey-box scans.

This layer is deliberately policy-first: it can prioritize work and explain
why, but cannot authorize a request.  The execution guard remains the final
authority for every active probe.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AgenticDecision:
    action: str
    priority: float
    rationale: str
    evidence: list[str]


class AgenticPlanner:
    """Cheap, deterministic planner used as a reliable fallback around an LLM."""

    def __init__(self, profile: str = "blackbox") -> None:
        self.profile = profile if profile in {"blackbox", "greybox"} else "blackbox"

    def decide(self, state: Any) -> list[AgenticDecision]:
        endpoints = list(getattr(state, "endpoints", []) or [])
        findings = list(getattr(state, "findings", []) or [])
        decisions: list[AgenticDecision] = []
        if not endpoints:
            decisions.append(AgenticDecision("discover_endpoints", 1.0, "No attack surface discovered yet", []))
            return decisions
        api = [e for e in endpoints if "/api" in str(e.get("url", "")).lower()]
        params = sum(bool(e.get("params") or "?") for e in endpoints)
        if api:
            decisions.append(AgenticDecision("prioritize_api_authorization", 0.95,
                "API endpoints are high-value authorization boundaries", [str(e.get("url")) for e in api[:5]]))
        if params:
            decisions.append(AgenticDecision("prioritize_input_validation", 0.85,
                "Parameterized endpoints support safe differential validation", [f"{params} parameterized endpoints"]))
        if self.profile == "greybox":
            decisions.append(AgenticDecision("compare_authenticated_surface", 0.9,
                "Grey-box authorization enables safe authenticated vs anonymous comparison",
                ["explicit authorization required", "read-only methods only"]))
        if findings:
            decisions.append(AgenticDecision("correlate_findings", 0.8,
                "Existing findings may form a higher-impact chain", [f"{len(findings)} findings"]))
        decisions.sort(key=lambda d: d.priority, reverse=True)
        return decisions

    def apply(self, state: Any) -> list[dict]:
        rows = [d.__dict__ for d in self.decide(state)]
        setattr(state, "agentic_decisions", rows)
        return rows
