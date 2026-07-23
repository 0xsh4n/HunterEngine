"""Tests for the 8-step methodology, per-phase reasoning, behaviour-driven
detection ranking, impact assessment, and dashboard scan control."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from ai.impact import assess_impact
from ai.phase_reasoner import PhaseReasoner
from core.methodology import METHODOLOGY, PIPELINE_ORDER, RUNNER_TO_STEP, manifest
from core.orchestrator import Orchestrator, ScanPhase, PHASE_ALIASES


def test_methodology_has_eight_classic_steps():
    ids = [s.id for s in METHODOLOGY]
    assert ids == [
        "recon", "scanning", "threat_model", "vuln_analysis",
        "exploitation", "post_exploit", "correlation", "reporting",
    ]
    # Every runner maps back to a step, and the pipeline order is derived from it.
    assert PIPELINE_ORDER[0] == "recon"
    assert PIPELINE_ORDER[-1] == "report"
    assert RUNNER_TO_STEP["ai_test"] == "exploitation"
    assert RUNNER_TO_STEP["detect"] == "vuln_analysis"
    assert len(manifest()) == 8


def test_classic_phase_aliases_resolve():
    assert PHASE_ALIASES["exploitation"] == ScanPhase.AI_TEST.value
    assert PHASE_ALIASES["vuln_analysis"] == ScanPhase.DETECT.value
    assert PHASE_ALIASES["threat_modeling"] == ScanPhase.THREAT_MODEL.value
    assert PHASE_ALIASES["post_exploitation"] == ScanPhase.POST_EXPLOIT.value
    assert Orchestrator.normalize_phases(["scanning", "exploitation"]) == ["active_recon", "ai_test"]


@pytest.mark.asyncio
async def test_phase_reasoner_records_decision_every_phase():
    state = SimpleNamespace(behavior_model={"risk_score": 4, "focus_areas": [{"area": "api"}]})
    reasoner = PhaseReasoner(client=None, use_llm=False)
    for phase in PIPELINE_ORDER:
        decision = await reasoner.reason(phase, state)
        assert decision["rationale"]
        assert decision["source"] == "deterministic"
    recorded = [d["action"] for d in state.agentic_decisions]
    assert recorded == [f"phase:{p}" for p in PIPELINE_ORDER]


def test_detector_ranking_prioritizes_from_behaviour():
    behavior = {
        "focus_areas": [
            {"area": "idor_prone", "score": 3.0},
            {"area": "redirect", "score": 1.5},
        ],
        "mechanisms": ["token_or_jwt"],
    }
    enabled = ["xss", "idor", "open_redirect", "jwt", "secrets"]
    ranked = Orchestrator._rank_detectors(enabled, behavior)
    names = [n for n, _ in ranked]
    scores = dict(ranked)
    assert scores["idor"] > 0 and scores["jwt"] > 0 and scores["open_redirect"] > 0
    # idor (focus 3.0) and jwt (mechanism boost) should rank above unrelated xss
    assert names.index("idor") < names.index("xss")
    assert names.index("jwt") < names.index("xss")


def test_impact_assessment_is_nondestructive_and_chains():
    state = SimpleNamespace(
        findings=[
            {"title": "IDOR", "detector": "ai_test_idor", "severity": "high",
             "confidence": 0.8, "url": "https://a.test/api/orders/1"},
            {"title": "SSRF", "detector": "ssrf_detector", "severity": "high",
             "confidence": 0.7, "url": "https://a.test/api/fetch"},
        ],
        behavior_model={"risk_score": 8.0},
        ai_reasoning_traces=[],
    )
    result = assess_impact(state)
    assert result["assessed"] == 2
    assert result["chains"] >= 1  # same host → chain candidate
    assert state.impact_assessments[0]["blast_radius"] > 0
    # idor + ssrf on one host is a classic escalation path
    assert any(a["escalation_path"] for a in state.impact_assessments)
    # A post-exploitation reasoning trace was recorded
    assert any(t["phase"] == "post_exploit" for t in state.ai_reasoning_traces)


def test_scan_manager_lifecycle(tmp_path, monkeypatch):
    from dashboard.scan_manager import ScanManager

    mgr = ScanManager("config/settings.yaml", "config/scope.yaml")
    assert mgr.running is False
    assert mgr.status()["outcome"] == "idle"

    with pytest.raises(ValueError):
        mgr.start(profile="destroyeverything")

    # Stop when nothing runs is a safe no-op.
    assert mgr.stop()["running"] is False
