"""
Base class for local bug-hunting subagents.

Each subagent uses a compact specialist prompt + Ollama (Qwen3 reasoning)
to propose scoped, non-destructive probes. Execution stays in TestingAgent.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ai.ollama_client import OllamaClient

logger = logging.getLogger("hunterengine.ai.subagents")


@dataclass
class PlannedProbe:
    """A single safe validation probe suggested by a subagent."""

    url: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    location: str = "query"  # query | body | header | path
    check: str = "reflect"  # reflect | status_diff | redirect | error_leak | auth_bypass
    rationale: str = ""
    severity_hint: str = "medium"
    vuln_class: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], default_class: str = "") -> Optional["PlannedProbe"]:
        url = str(data.get("url", "")).strip()
        if not url:
            return None
        return cls(
            url=url,
            method=str(data.get("method", "GET")).upper() or "GET",
            parameter=str(data.get("parameter", "")).strip(),
            payload=str(data.get("payload", "")).strip()[:500],
            location=str(data.get("location", "query")).lower() or "query",
            check=str(data.get("check", "reflect")).lower() or "reflect",
            rationale=str(data.get("rationale", "")).strip()[:400],
            severity_hint=str(data.get("severity_hint", "medium")).lower() or "medium",
            vuln_class=str(data.get("vuln_class", default_class) or default_class).lower(),
        )


@dataclass
class ProbePlan:
    """Batch of probes from one subagent call."""

    agent: str
    probes: list[PlannedProbe] = field(default_factory=list)
    notes: str = ""
    priority_targets: list[str] = field(default_factory=list)


class HunterSubagent(ABC):
    """Specialist bug-hunter that plans probes via local LLM."""

    name: str = "base"
    max_probes: int = 8

    def __init__(self, client: OllamaClient, max_probes: int = 8) -> None:
        self.client = client
        self.max_probes = max_probes

    @abstractmethod
    def system_prompt(self) -> str:
        """Compact specialist system prompt."""
        ...

    def focus_hint(self) -> str:
        return self.name

    async def plan(self, targets: list[dict[str, Any]], context: dict[str, Any]) -> ProbePlan:
        if not targets:
            return ProbePlan(agent=self.name)

        user_payload = {
            "task": f"Plan up to {self.max_probes} high-value, non-destructive {self.focus_hint()} probes.",
            "required_json_schema": {
                "probes": [
                    {
                        "url": "full URL",
                        "method": "GET|HEAD|OPTIONS",
                        "parameter": "param name or empty",
                        "payload": "safe canary / test value",
                        "location": "query|body|header|path",
                        "check": "reflect|status_diff|redirect|error_leak|auth_bypass",
                        "severity_hint": "info|low|medium|high|critical",
                        "rationale": "one short sentence",
                        "vuln_class": self.name,
                    }
                ],
                "priority_targets": ["urls worth deeper testing"],
                "notes": "optional short note",
            },
            "rules": [
                "Only target URLs from the provided list, copied exactly.",
                "Prefer parameterized endpoints and auth-sensitive paths.",
                "Payloads must be non-destructive canaries — no exploit chains, no DoS, no brute force.",
                "Skip static assets (.js/.css/.png/.svg/.woff).",
                "Return compact JSON only.",
            ],
            "scan_context": context,
            "targets": targets,
        }
        user = json.dumps(user_payload, ensure_ascii=True, default=str)
        # Keep prompt lean for 4B speed
        if len(user) > 5500:
            user = user[:5500]

        try:
            data = await self.client.chat_json(
                system=self.system_prompt(),
                user=user,
            )
        except Exception as exc:
            logger.warning("%s planning failed: %s", self.name, exc)
            return ProbePlan(agent=self.name)

        if not data:
            return ProbePlan(agent=self.name)

        probes: list[PlannedProbe] = []
        for item in data.get("probes", []) or []:
            if not isinstance(item, dict):
                continue
            probe = PlannedProbe.from_dict(item, default_class=self.name)
            if probe:
                probes.append(probe)
            if len(probes) >= self.max_probes:
                break

        priority = [
            str(u).strip()
            for u in (data.get("priority_targets") or [])[:10]
            if str(u).strip()
        ]
        return ProbePlan(
            agent=self.name,
            probes=probes,
            notes=str(data.get("notes", ""))[:500],
            priority_targets=priority,
        )
