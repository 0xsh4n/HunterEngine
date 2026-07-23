"""
Post-exploitation impact assessment — strictly non-destructive.

Real post-exploitation (persistence, lateral movement, data exfiltration) is
out of scope for an authorized, safety-gated engine. Instead this step reasons
about what a confirmed finding *would* give an attacker: blast radius, whether
it chains with other findings on the same host, and the business impact. It
only reads already-collected findings and the behaviour model — it sends no
traffic and changes no state.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("hunterengine.ai.impact")

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Vuln class → (attacker gain, typical blast-radius weight 0..1)
IMPACT_MODEL: dict[str, tuple[str, float]] = {
    "idor": ("Access or modify other users' objects/data", 0.8),
    "auth": ("Bypass authentication or escalate privileges", 0.9),
    "jwt": ("Forge or replay tokens to impersonate users", 0.85),
    "ssrf": ("Reach internal services / cloud metadata", 0.85),
    "xss": ("Run script in victim sessions / steal tokens", 0.6),
    "ssti": ("Server-side template evaluation → possible RCE", 0.95),
    "open_redirect": ("Phish users or leak tokens via redirect", 0.4),
    "cors": ("Read cross-origin responses with victim creds", 0.55),
    "request_smuggling": ("Desync requests, poison caches/queues", 0.8),
    "secrets": ("Use leaked credentials/keys directly", 0.9),
    "graphql": ("Over-fetch or mutate via exposed schema", 0.6),
}


def _class_of(finding: dict) -> str:
    detector = str(finding.get("detector", "")).lower()
    for name in IMPACT_MODEL:
        if name in detector:
            return name
    return str(finding.get("vuln_class") or finding.get("type") or "").lower()


def _host(url: str) -> str:
    return (urlparse(str(url)).hostname or "").lower()


def assess_impact(state: Any, *, max_findings: int = 60) -> dict[str, Any]:
    """Annotate findings with impact and detect same-host chain potential."""
    findings = [f for f in (getattr(state, "findings", []) or []) if isinstance(f, dict)]
    if not findings:
        setattr(state, "impact_assessments", [])
        return {"assessed": 0, "chains": 0}

    behavior = getattr(state, "behavior_model", {}) or {}
    surface_boost = min(float(behavior.get("risk_score", 0)) / 20.0, 0.15)

    by_host: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_host[_host(f.get("url", ""))].append(f)

    assessments: list[dict[str, Any]] = []
    chains = 0
    for finding in findings[:max_findings]:
        cls = _class_of(finding)
        gain, weight = IMPACT_MODEL.get(cls, ("Undetermined attacker benefit", 0.4))
        sev = str(finding.get("severity", "info")).lower()
        sev_factor = (SEVERITY_ORDER.index(sev) + 1) / len(SEVERITY_ORDER) if sev in SEVERITY_ORDER else 0.4
        confidence = float(finding.get("confidence", 0.0) or 0.0)

        host = _host(finding.get("url", ""))
        neighbours = [
            _class_of(o) for o in by_host.get(host, [])
            if o is not finding and _class_of(o)
        ]
        chainable = sorted({c for c in neighbours if c and c != cls})
        # Auth/IDOR/JWT next to injection classes is the classic escalation.
        escalates = bool({"auth", "idor", "jwt"} & set(chainable + [cls])) and bool(
            {"ssrf", "ssti", "xss", "secrets"} & set(chainable + [cls])
        )
        if chainable:
            chains += 1

        blast = round(min(weight * sev_factor * (0.5 + confidence / 2) + surface_boost, 1.0), 3)
        impact = {
            "title": str(finding.get("title", ""))[:120],
            "url": str(finding.get("url", ""))[:200],
            "vuln_class": cls or "unknown",
            "attacker_gain": gain,
            "blast_radius": blast,
            "severity": sev,
            "chainable_with": chainable,
            "escalation_path": escalates,
            "host": host,
        }
        assessments.append(impact)

        # Annotate the finding in place (non-destructive metadata only).
        meta = finding.setdefault("metadata", {})
        meta["impact_assessment"] = {
            "attacker_gain": gain,
            "blast_radius": blast,
            "chainable_with": chainable,
            "escalation_path": escalates,
        }
        if escalates and "impact-chain" not in (finding.get("tags") or []):
            finding.setdefault("tags", []).append("impact-chain")

    assessments.sort(key=lambda a: a["blast_radius"], reverse=True)
    setattr(state, "impact_assessments", assessments[:max_findings])

    # A reasoning trace so the dashboard shows post-exploitation thinking.
    top = assessments[0] if assessments else None
    traces = list(getattr(state, "ai_reasoning_traces", []) or [])
    traces.append({
        "phase": "post_exploit",
        "agent": "impact_assessor",
        "model": "deterministic",
        "text": (
            f"Assessed {len(assessments)} finding(s); {chains} share a host and may chain. "
            + (f"Highest blast radius: {top['title']} ({top['blast_radius']}) — {top['attacker_gain']}."
               if top else "No exploitable impact ranked.")
        ),
    })
    setattr(state, "ai_reasoning_traces", traces[-300:])
    logger.info("Impact assessment: %d finding(s), %d chain candidate(s)", len(assessments), chains)
    return {"assessed": len(assessments), "chains": chains, "top": top}
