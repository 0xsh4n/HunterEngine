"""
Classic 8-step penetration-testing methodology.

HunterEngine's internal runner phases are grouped into the eight canonical
steps a human team follows. This module is the single source of truth for the
step order, their titles, the AI role in each, and the mapping onto the
orchestrator's runner phases. Both the pipeline and the dashboard read it so
the methodology stays consistent everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class MethodologyStep:
    id: str
    title: str
    summary: str
    ai_role: str
    runners: tuple[str, ...]  # orchestrator ScanPhase values, in order


# NOTE: runner values must match core.orchestrator.ScanPhase values.
METHODOLOGY: tuple[MethodologyStep, ...] = (
    MethodologyStep(
        id="recon",
        title="1 · Reconnaissance",
        summary="Passive asset discovery: subdomains, DNS, historical URLs.",
        ai_role="AI ranks which assets are worth active follow-up.",
        runners=("recon",),
    ),
    MethodologyStep(
        id="scanning",
        title="2 · Scanning & Enumeration",
        summary="Live probing, tech fingerprinting, crawl, JS/GraphQL/param mining.",
        ai_role="AI guides crawl focus and flags high-signal endpoints.",
        runners=("active_recon", "crawl"),
    ),
    MethodologyStep(
        id="threat_model",
        title="3 · Threat Modeling",
        summary="Build a scored attack-surface + behaviour model and a plan.",
        ai_role="AI reasons over the surface to pick focus areas and hunters.",
        runners=("threat_model",),
    ),
    MethodologyStep(
        id="vuln_analysis",
        title="4 · Vulnerability Analysis",
        summary="Behaviour-driven classic detectors run over the mapped surface.",
        ai_role="AI selects and prioritizes detectors from the threat model.",
        runners=("detect",),
    ),
    MethodologyStep(
        id="exploitation",
        title="5 · Exploitation (safe validation)",
        summary="AI hunters plan and execute non-destructive validation probes.",
        ai_role="Specialist AI subagents plan scoped, safety-gated probes.",
        runners=("ai_test",),
    ),
    MethodologyStep(
        id="post_exploit",
        title="6 · Post-Exploitation (impact)",
        summary="Assess blast radius and confirm impact — non-destructive only.",
        ai_role="AI estimates impact/chainability and what a real attacker gains.",
        runners=("post_exploit",),
    ),
    MethodologyStep(
        id="correlation",
        title="7 · Correlation & Chaining",
        summary="Chain weak signals into higher-severity composite findings.",
        ai_role="AI links related signals across hosts into attack chains.",
        runners=("correlate",),
    ),
    MethodologyStep(
        id="reporting",
        title="8 · Reporting",
        summary="AI triage/enrichment, then multi-format report generation.",
        ai_role="AI writes triage verdicts, remediation, and the report.",
        runners=("ai", "report"),
    ),
)

# Ordered runner-phase pipeline derived from the methodology (single source).
PIPELINE_ORDER: tuple[str, ...] = tuple(
    runner for step in METHODOLOGY for runner in step.runners
)

# Runner phase -> methodology step id (for progress/labels).
RUNNER_TO_STEP: dict[str, str] = {
    runner: step.id for step in METHODOLOGY for runner in step.runners
}


def manifest() -> list[dict[str, Any]]:
    """JSON-serializable methodology description for the dashboard."""
    return [
        {
            "id": s.id,
            "title": s.title,
            "summary": s.summary,
            "ai_role": s.ai_role,
            "runners": list(s.runners),
        }
        for s in METHODOLOGY
    ]
