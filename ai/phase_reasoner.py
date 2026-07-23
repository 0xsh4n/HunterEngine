"""
Per-phase AI reasoning hook — puts an explainable decision in *every* step.

At each phase boundary this produces a short rationale ("given what we know,
here is what this phase will focus on and why") plus a confidence. It is
deterministic and instant by default; when a local model is configured and
reachable it upgrades the rationale with an LLM, capturing the thinking trace.
Either way the output lands on scan state so the dashboard and report can show
the engine's reasoning at every step — without ever gating execution on the LLM.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

logger = logging.getLogger("hunterengine.ai.phase_reasoner")


class PhaseReasoner:
    """Attaches an AI/deterministic rationale to each pipeline phase."""

    def __init__(self, client: Optional[Any] = None, *, use_llm: bool = False) -> None:
        # ``client`` is an OllamaClient-like object; optional.
        self.client = client
        self.use_llm = use_llm and client is not None

    async def reason(self, phase: str, state: Any, *, timeout: float = 8.0) -> dict[str, Any]:
        facts = self._facts(state)
        decision = self._deterministic(phase, facts)

        if self.use_llm:
            try:
                enriched = await asyncio.wait_for(self._llm(phase, facts, decision), timeout=timeout)
                if enriched:
                    decision["rationale"] = enriched
                    decision["source"] = "llm"
            except Exception as exc:  # never let phase reasoning break a scan
                logger.debug("Phase LLM reasoning failed for %s: %s", phase, exc)

        self._record(state, phase, decision)
        return decision

    # ── deterministic core ────────────────────────────────────────────────
    @staticmethod
    def _facts(state: Any) -> dict[str, Any]:
        behavior = getattr(state, "behavior_model", {}) or {}
        return {
            "live_hosts": len(getattr(state, "live_hosts", []) or []),
            "endpoints": len(getattr(state, "endpoints", []) or []),
            "findings": len(getattr(state, "findings", []) or []),
            "weak_signals": len(getattr(state, "weak_signals", []) or []),
            "risk_score": behavior.get("risk_score", 0),
            "focus_areas": [a.get("area") for a in (behavior.get("focus_areas") or [])[:4]],
            "mechanisms": behavior.get("mechanisms", []),
            "state_changing": behavior.get("state_changing_endpoints", 0),
            "object_refs": behavior.get("object_reference_endpoints", 0),
        }

    def _deterministic(self, phase: str, f: dict[str, Any]) -> dict[str, Any]:
        focus = ", ".join(x for x in f["focus_areas"] if x) or "the discovered surface"
        rationales = {
            "recon": (
                "Enumerate the authorized attack surface passively before touching "
                "the target; breadth now reduces noise later.", 0.9),
            "active_recon": (
                f"Probe {f['live_hosts'] or 'candidate'} host(s) and fingerprint tech to "
                "separate live, testable surface from dead assets.", 0.85),
            "crawl": (
                f"Map routes/JS/params across {f['endpoints'] or 0} endpoint(s); "
                "parameterized and API routes are the raw material for every hunter.", 0.85),
            "threat_model": (
                f"Score the surface and prioritize {focus}; "
                f"risk={f['risk_score']}, object-refs={f['object_refs']}, "
                f"state-changing={f['state_changing']}.", 0.9),
            "detect": (
                f"Run detectors weighted toward {focus}; skip categories the surface "
                "does not exhibit to keep this phase fast.", 0.8),
            "ai_test": (
                f"Plan non-destructive validation probes for {focus}; "
                "specialist subagents reason per endpoint, execution stays safety-gated.", 0.85),
            "post_exploit": (
                f"Assess impact of {f['findings']} finding(s) — blast radius, chainability, "
                "and what a real attacker would gain — without any state change.", 0.8),
            "correlate": (
                f"Chain {f['weak_signals']} weak signal(s) into higher-severity composites "
                "where evidence lines up across hosts.", 0.8),
            "ai": (
                f"Triage {f['findings']} finding(s): re-weigh confidence, judge false-positive "
                "risk, and write remediation before reporting.", 0.85),
            "report": (
                "Compile evidence-backed, triage-ready reports in the configured formats.", 0.9),
        }
        rationale, confidence = rationales.get(
            phase, (f"Execute {phase} over the current state.", 0.7))
        return {
            "phase": phase,
            "rationale": rationale,
            "confidence": confidence,
            "focus_areas": [x for x in f["focus_areas"] if x],
            "source": "deterministic",
        }

    async def _llm(self, phase: str, facts: dict[str, Any], decision: dict[str, Any]) -> str:
        system = (
            "You are the planning brain of an authorized, non-destructive bug-bounty "
            "engine. In ONE or TWO sentences, explain what this phase should focus on "
            "and why, given the facts. No exploit instructions, no data exfiltration."
        )
        user = (
            f"phase={phase}\nfacts={facts}\n"
            f"deterministic_plan={decision['rationale']}\n"
            "Return only the improved plain-text rationale."
        )
        reply = await self.client.chat(system=system, user=user, json_mode=False, label=f"phase:{phase}")
        return (reply or "").strip()[:600]

    @staticmethod
    def _record(state: Any, phase: str, decision: dict[str, Any]) -> None:
        decisions = list(getattr(state, "agentic_decisions", []) or [])
        decisions.append({
            "action": f"phase:{phase}",
            "priority": decision.get("confidence", 0.7),
            "rationale": decision.get("rationale", ""),
            "evidence": decision.get("focus_areas", []),
        })
        setattr(state, "agentic_decisions", decisions[-200:])

        if decision.get("source") == "llm":
            traces = list(getattr(state, "ai_reasoning_traces", []) or [])
            traces.append({
                "phase": phase,
                "agent": "phase_planner",
                "model": getattr(getattr(state, "_reasoner_model", None), "model", "llm"),
                "text": decision.get("rationale", ""),
            })
            setattr(state, "ai_reasoning_traces", traces[-300:])
