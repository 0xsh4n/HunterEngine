"""Tests for the HunterEngine MCP tool logic (transport-independent).

These exercise HunterEngineTools directly so they run without the optional
``mcp`` package installed. The FastMCP wiring is a thin wrapper over these.
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from integrations.mcp_server import HunterEngineTools


def _write_checkpoint(tmp_path):
    from core.checkpoint import CheckpointStore

    state = SimpleNamespace(
        phase=SimpleNamespace(value="done"),
        findings=[
            {"title": "IDOR", "severity": "high", "confidence": 0.82, "detector": "ai_test_idor",
             "url": "https://a.test/api/orders/1", "parameter": "id",
             "metadata": {"ai_analysis": {"exploitability": "straightforward", "impact_area": "other users",
                                          "reasoning_steps": ["enumerable id"]},
                          "impact_assessment": {"blast_radius": 0.7, "chainable_with": ["ssrf"]}}},
            {"title": "Low info", "severity": "low", "confidence": 0.4, "detector": "csp",
             "url": "https://a.test/"},
        ],
        weak_signals=[], chained_findings=[],
        behavior_model={"risk_score": 6.0, "focus_areas": [{"area": "api"}]},
        agentic_decisions=[{"action": "phase:recon", "priority": 0.9, "rationale": "map surface", "evidence": []}],
        ai_reasoning_traces=[{"phase": "exploitation", "agent": "idor", "text": "reason"}],
        ai_reasoning_summary={"reviewed": 2, "top_risks": []},
        impact_assessments=[{"title": "IDOR", "blast_radius": 0.7, "escalation_path": True}],
        ai_token_usage={"total_tokens": 100}, ai_enriched_findings=1, ai_test_probes=4, ai_test_findings=1,
        phase_health={}, learning_events=[], errors=[], subdomains=[], live_hosts=[{"url": "https://a.test"}],
        endpoints=[{"url": "https://a.test/api/orders/1"}], js_files=[], historical_urls=[],
        tech_stack={}, params={}, graphql_schemas=[], total_requests=1, start_time=time.time(),
    )
    CheckpointStore(str(tmp_path / "checkpoints")).save(state, reason="test", next_phase=None)


def _tools(tmp_path):
    settings = tmp_path / "settings.yaml"
    scope = tmp_path / "scope.yaml"
    settings.write_text(f"general:\n  data_dir: {tmp_path}\nai:\n  enabled: true\n", encoding="utf-8")
    scope.write_text("program: test\nin_scope:\n  domains:\n    - a.test\n", encoding="utf-8")
    return HunterEngineTools(str(settings), str(scope))


def test_methodology_and_scope(tmp_path):
    tools = _tools(tmp_path)
    ids = [s["id"] for s in tools.methodology()["steps"]]
    assert ids[0] == "recon" and ids[-1] == "reporting" and len(ids) == 8
    assert tools.get_scope()["program"] == "test"


def test_run_summary_and_findings(tmp_path):
    tools = _tools(tmp_path)
    _write_checkpoint(tmp_path)
    summary = tools.run_summary()
    assert summary["available"] is True
    assert summary["counts"]["findings"] == 2
    assert summary["severity_counts"].get("high") == 1

    high = tools.list_findings(severity="high")
    assert high["count"] == 1
    f = high["findings"][0]
    assert f["exploitability"] == "straightforward"
    assert f["blast_radius"] == 0.7
    assert f["chainable_with"] == ["ssrf"]


def test_reasoning_and_behavior_and_domains(tmp_path):
    tools = _tools(tmp_path)
    _write_checkpoint(tmp_path)
    reasoning = tools.get_reasoning()
    assert reasoning["available"] is True
    assert reasoning["decisions"]
    assert tools.get_behavior()["behavior"]["risk_score"] == 6.0
    assert "analytics" in tools.list_domains()


def test_scan_lifecycle_guards(tmp_path):
    tools = _tools(tmp_path)
    st = tools.scan_status()
    assert st["running"] is False and st["outcome"] == "idle"
    # Invalid profile is reported, not raised, to the MCP client.
    res = tools.start_scan(profile="nope")
    assert res["ok"] is False and "profile" in res["error"]
    assert tools.stop_scan()["status"]["running"] is False


@pytest.mark.asyncio
async def test_build_server_registers_all_tools(tmp_path):
    pytest.importorskip("mcp")
    from integrations.mcp_server import build_server

    server = build_server(str(tmp_path / "settings.yaml"), str(tmp_path / "scope.yaml"))
    names = {t.name for t in await server.list_tools()}
    assert {"methodology", "start_scan", "scan_status", "list_findings",
            "get_reasoning", "get_behavior", "list_domains"} <= names
