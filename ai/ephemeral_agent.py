"""Optional AI-generated specialist planner.

The model may describe a temporary adapter/workflow, but generated Python is
never imported or executed. It must still return the same structured probes as
normal hunters and passes through the normal safety gate.
"""
from __future__ import annotations

import json
from typing import Any

from ai.ollama_client import OllamaClient
from ai.subagents.base import PlannedProbe, ProbePlan


class EphemeralAgentPlanner:
    name = "ephemeral"

    def __init__(self, client: OllamaClient, max_probes: int = 4) -> None:
        self.client = client
        self.max_probes = max_probes

    async def plan(self, targets: list[dict[str, Any]], context: dict[str, Any]) -> ProbePlan:
        if not targets:
            return ProbePlan(self.name)
        payload = {
            "task": "Act as a temporary application-behavior analyst and propose safe read-only validation probes.",
            "targets": targets[:12], "application_behavior": context.get("behavior_model", {}),
            "rules": ["Copy target URLs exactly", "GET/HEAD/OPTIONS only", "No signup, brute force, destructive actions, or generated code execution"],
            "schema": {"probes": [{"url": "target URL", "method": "GET", "parameter": "name", "payload": "safe canary", "check": "reflect|status_diff|error_leak", "vuln_class": "behavior"}]},
        }
        try:
            data = await self.client.chat_json(system="You are a defensive authorized testing planner. Return JSON only.", user=json.dumps(payload)[:5500])
        except Exception:
            return ProbePlan(self.name)
        probes = []
        for row in (data or {}).get("probes", []):
            if isinstance(row, dict):
                probe = PlannedProbe.from_dict(row, default_class=self.name)
                if probe: probes.append(probe)
            if len(probes) >= self.max_probes: break
        return ProbePlan(self.name, probes=probes, notes="Temporary AI-generated adapter; code execution disabled")
