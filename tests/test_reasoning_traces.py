"""Tests for reasoning-trace capture, deeper triage, behaviour analysis,
and the operational dashboard run-loader."""

from __future__ import annotations

import time
from types import SimpleNamespace

from ai.behavior import analyze_behavior
from ai.local_reasoner import EXPLOITABILITY, LocalAIConfig, LocalAIReasoner
from ai.ollama_client import OllamaClient, OllamaClientConfig, extract_thinking, strip_thinking


def test_extract_thinking_splits_reasoning_from_content():
    thinking, clean = extract_thinking("<think>weigh the evidence</think>{\"ok\": true}")
    assert thinking == "weigh the evidence"
    assert clean == '{"ok": true}'
    # Backwards-compatible helper still strips.
    assert strip_thinking("<thinking>x</thinking>hello") == "hello"


def test_extract_thinking_handles_unterminated_block():
    thinking, clean = extract_thinking("answer<think>still reasoning and truncated")
    assert "still reasoning" in thinking
    assert clean == "answer"


def test_client_captures_and_drains_traces():
    client = OllamaClient(OllamaClientConfig(model="qwen3:4b"))
    client._capture_thinking("first thought", label="idor")
    client._capture_thinking("second thought", label="xss")
    assert client.usage["thinking_chars"] > 0
    drained = client.drain_traces()
    assert [t["label"] for t in drained] == ["idor", "xss"]
    assert client.reasoning_traces == []


def test_fallback_reasoning_has_reasoning_dimensions():
    reasoner = LocalAIReasoner(LocalAIConfig(enabled=True))
    analysis = reasoner._fallback_analysis(
        {"title": "IDOR", "url": "https://x.test/api/orders/1", "parameter": "id"},
        {"endpoint_count": 60, "weak_signal_count": 0},
    )
    assert analysis["exploitability"] in EXPLOITABILITY
    assert analysis["impact_area"]
    assert analysis["reasoning_steps"]
    assert analysis["attack_prerequisites"]


def test_reasoner_finalize_records_traces_and_summary():
    reasoner = LocalAIReasoner(LocalAIConfig(enabled=True))
    reasoner.reasoning_traces = [{"phase": "triage", "text": "thinking"}]
    state = SimpleNamespace()
    eligible = [{"title": "IDOR", "severity": "high", "confidence": 0.8, "tags": ["ai-needs-review"]}]
    reasoner._finalize_reasoning(state, eligible, fallback=True)
    assert state.ai_reasoning_traces
    assert state.ai_reasoning_summary["reviewed"] == 1
    assert state.ai_reasoning_summary["top_risks"][0]["severity"] == "high"
    assert "IDOR" in state.ai_reasoning_summary["needs_review"]


def test_behavior_analysis_scores_surface_and_structure():
    state = SimpleNamespace(
        endpoints=[
            {"url": "https://app.test/api/orders/42", "method": "GET", "status": 200},
            {"url": "https://app.test/admin/users?id=7", "method": "GET", "status": 403},
            {"url": "https://app.test/account/settings", "method": "POST", "status": 200},
            {"url": "https://app.test/login", "method": "POST", "status": 200},
        ],
        tech_stack={},
    )
    b = analyze_behavior(state)
    assert b["endpoint_total"] == 4
    assert b["object_reference_endpoints"] >= 1
    assert b["state_changing_endpoints"] >= 2
    assert b["risk_score"] > 0
    areas = {a["area"] for a in b["focus_areas"]}
    assert {"admin", "auth", "account"} & areas
    assert b["auth_posture"]["observed_401_403"] >= 1
    # focus areas suggest concrete hunters
    assert any(a["suggest_hunters"] for a in b["focus_areas"])


def test_dashboard_run_loader_and_analytics(tmp_path):
    from core.checkpoint import CheckpointStore
    from dashboard.app import _load_latest_run

    state = SimpleNamespace(
        phase=SimpleNamespace(value="ai"),
        findings=[{"title": "IDOR", "severity": "high", "confidence": 0.8, "url": "https://a.test/x"}],
        weak_signals=[], chained_findings=[],
        behavior_model={"risk_score": 5.0, "focus_areas": []},
        agentic_decisions=[{"action": "prioritize_api_authorization", "priority": 0.9, "rationale": "r", "evidence": []}],
        ai_reasoning_traces=[{"phase": "ai_test", "agent": "idor", "text": "reasoning"}],
        ai_reasoning_summary={"reviewed": 1, "top_risks": []},
        ai_token_usage={"total_tokens": 100, "thinking_chars": 20},
        ai_enriched_findings=1, ai_test_probes=3, ai_test_findings=1,
        phase_health={"ai_test": {"status": "ok", "elapsed": 1.0}},
        learning_events=[], errors=[], subdomains=[], live_hosts=[],
        endpoints=[{"url": "https://a.test/x"}], js_files=[], historical_urls=[],
        tech_stack={}, params={}, graphql_schemas=[], total_requests=1, start_time=time.time(),
    )
    store = CheckpointStore(str(tmp_path / "checkpoints"))
    store.save(state, reason="test", next_phase=None)

    settings = {"general": {"data_dir": str(tmp_path)}}
    run = _load_latest_run(settings)
    assert run["available"] is True
    assert run["counts"]["findings"] == 1
    assert run["severity_counts"]["high"] == 1
    assert run["reasoning_traces"][0]["agent"] == "idor"
    assert run["ai_token_usage"]["thinking_chars"] == 20
