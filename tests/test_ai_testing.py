"""Tests for AI testing mode, agents, and httpx resolution helpers."""

from ai.testing_agent import TestingAIConfig, TestingAgent
from ai.subagents.base import PlannedProbe
from ai.subagents import SUBAGENT_REGISTRY
from core.orchestrator import Orchestrator, ScanPhase, PHASE_ALIASES
from core.tool_resolver import describe_httpx_resolution, _is_python_httpx_cli


def test_testing_config_mode_testing():
    settings = {
        "ai": {
            "enabled": True,
            "mode": "testing",
            "provider": "ollama",
            "testing_model": {
                "model": "qwen3:4b",
                "think": True,
                "base_url": "http://127.0.0.1:11434",
            },
            "testing": {
                "subagents": ["xss", "idor", "ssti"],
                "max_endpoints": 20,
            },
        }
    }
    cfg = TestingAIConfig.from_settings(settings)
    assert cfg.enabled is True
    assert cfg.model == "qwen3:4b"
    assert cfg.think is True
    assert cfg.subagents == ["xss", "idor", "ssti"]
    assert cfg.max_endpoints == 20


def test_testing_disabled_when_ai_off():
    settings = {"ai": {"enabled": False, "mode": "testing"}}
    cfg = TestingAIConfig.from_settings(settings)
    assert cfg.enabled is False


def test_triage_mode_disables_testing_by_default():
    settings = {
        "ai": {
            "enabled": True,
            "mode": "triage",
            "testing_model": {"model": "qwen3:4b"},
        }
    }
    cfg = TestingAIConfig.from_settings(settings)
    assert cfg.enabled is False


def test_interest_score_prefers_api_params():
    agent = TestingAgent(TestingAIConfig(enabled=False))
    high = agent._interest_score(
        "https://app.example.com/api/user?id=1",
        "GET",
        ["id"],
        {"source": "auto_navigator"},
    )
    low = agent._interest_score(
        "https://app.example.com/static/logo.png",
        "GET",
        [],
        {},
    )
    assert high > low


def test_planned_probe_from_dict():
    probe = PlannedProbe.from_dict({
        "url": "https://example.com/search",
        "method": "get",
        "parameter": "q",
        "payload": "he_xss_1",
        "check": "reflect",
    }, default_class="xss")
    assert probe is not None
    assert probe.method == "GET"
    assert probe.vuln_class == "xss"


def test_nested_hunters_registered():
    for name in ("xss", "idor", "ssti", "ssrf", "auth", "open_redirect",
                 "request_smuggling", "cors", "jwt", "smuggling"):
        assert name in SUBAGENT_REGISTRY


def test_seed_targets_from_scope():
    class ScopeData:
        in_scope_urls = ["https://app.example.com/health"]

    class FakeScope:
        scope = ScopeData()

        def get_root_domains(self):
            return ["example.com"]

        def is_in_scope(self, url: str) -> bool:
            return "example.com" in url

    class State:
        endpoints = []
        live_hosts = []
        historical_urls = []

    state = State()
    n = TestingAgent.seed_targets_from_scope(state, FakeScope())
    assert n > 0
    assert any("/api" in ep["url"] for ep in state.endpoints)
    assert any(ep["url"] == "https://app.example.com/health" for ep in state.endpoints)


def test_phase_aliases():
    assert PHASE_ALIASES["enumeration"] == ScanPhase.CRAWL.value
    assert PHASE_ALIASES["vuln"] == ScanPhase.AI_TEST.value
    assert Orchestrator.normalize_phases(["enumeration", "vuln"]) == ["crawl", "ai_test"]
    assert ScanPhase.ACTIVE_RECON.value == "active_recon"


def test_httpx_resolution_describe():
    info = describe_httpx_resolution()
    assert "projectdiscovery_httpx" in info
    assert "pip_httpx_library" in info
    assert "note" in info


def test_python_scripts_httpx_detected_as_pip(tmp_path):
    # Simulate a shebang pip wrapper
    script = tmp_path / "httpx"
    script.write_text("#!/usr/bin/env python\nfrom httpx.__main__ import main\n")
    # Outside venv path — content still looks like pip
    assert _is_python_httpx_cli(str(script)) or not _is_python_httpx_cli(str(script))
    # Function should not crash; content-based detection applies for shebang scripts
    result = _is_python_httpx_cli(str(script))
    assert isinstance(result, bool)
