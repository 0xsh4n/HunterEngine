"""Tests for Ollama health check fix and per-domain learning."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from ai.ollama_client import OllamaClient, OllamaClientConfig
from memory.domain_learner import DomainLearner, normalize_domain


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_health_check_ok_when_model_installed(monkeypatch):
    client = OllamaClient(OllamaClientConfig(model="qwen3:4b"))

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers=None):
            return _FakeResponse(200, {"models": [{"name": "qwen3:4b"}, {"name": "llama3:8b"}]})

    monkeypatch.setattr("ai.ollama_client.httpx.AsyncClient", _FakeAsyncClient)
    report = await client.health_check()
    assert report["ok"] is True
    assert await client.available() is True
    assert "qwen3:4b" in report["models"]


@pytest.mark.asyncio
async def test_health_check_fails_when_model_missing(monkeypatch):
    client = OllamaClient(OllamaClientConfig(model="qwen3:4b"))

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url, headers=None):
            return _FakeResponse(200, {"models": [{"name": "llama3:8b"}]})

    monkeypatch.setattr("ai.ollama_client.httpx.AsyncClient", _FakeAsyncClient)
    report = await client.health_check()
    assert report["ok"] is False
    assert "not installed" in report["error"]
    assert await client.available() is False


def test_domain_learner_persists_and_ranks(tmp_path):
    learner = DomainLearner(str(tmp_path / "profiles"))
    state = SimpleNamespace(
        endpoints=[{"url": "https://app.example.com/api/user?id=1", "method": "GET", "status": 200}],
        live_hosts=[{"url": "https://app.example.com"}],
        findings=[{
            "url": "https://app.example.com/api/user?id=1",
            "detector": "ai_test_idor",
            "confidence": 0.8,
        }],
        weak_signals=[],
        behavior_model={"mechanisms": ["token_or_jwt"]},
        tech_stack={},
        phase_health={"ai_test": {"status": "ok"}},
        learning_events=[],
        ai_test_probes=3,
    )
    updated = learner.learn_from_scan(state)
    assert updated
    assert normalize_domain("https://app.example.com/x") == "app.example.com"
    profile = learner.load("app.example.com")
    assert profile["scan_count"] == 1
    assert "idor" in profile["preferred_subagents"] or "idor" in profile["successful_classes"]

    ctx = learner.context_for_targets(["https://app.example.com/api/orders"])
    ordered = learner.rank_subagents(["xss", "idor", "ssrf"], ctx)
    assert ordered[0] == "idor" or "idor" in ordered[:2]
    assert learner.interest_boost("https://app.example.com/api/user", ctx) >= 0

    path = tmp_path / "profiles" / "app.example.com.json"
    assert path.exists()
    disk = json.loads(path.read_text(encoding="utf-8"))
    assert disk["domain"] == "app.example.com"
