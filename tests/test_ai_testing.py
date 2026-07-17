"""Tests for AI testing mode configuration and target scoring."""

from ai.testing_agent import TestingAIConfig, TestingAgent
from ai.subagents.base import PlannedProbe


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
                "subagents": ["xss", "idor"],
                "max_endpoints": 20,
            },
        }
    }
    cfg = TestingAIConfig.from_settings(settings)
    assert cfg.enabled is True
    assert cfg.model == "qwen3:4b"
    assert cfg.think is True
    assert cfg.subagents == ["xss", "idor"]
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
