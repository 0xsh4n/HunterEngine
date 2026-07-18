"""Tests for pause / resume / quit checkpoint control."""

import json
from pathlib import Path

from core.checkpoint import CheckpointStore, serialize_state
from core.orchestrator import ScanState, ScanPhase, Orchestrator
from core.scan_control import ScanController, ControlAction


def test_serialize_and_restore(tmp_path: Path):
    state = ScanState()
    state.phase = ScanPhase.CRAWL
    state.subdomains = ["a.example.com"]
    state.live_hosts = [{"url": "https://a.example.com", "status": 200}]
    state.endpoints = [{"url": "https://a.example.com/api", "method": "GET"}]
    state.findings = [{"title": "test", "confidence": 0.9}]

    store = CheckpointStore(tmp_path)
    path = store.save(state, reason="test", completed_phases=["recon", "active_recon"], next_phase="crawl")
    assert path.exists()
    assert (tmp_path / "latest.json").exists()

    data = store.load()
    assert data is not None
    assert data["next_phase"] == "crawl"
    assert data["completed_phases"] == ["recon", "active_recon"]

    fresh = ScanState()
    completed = store.apply_to_state(fresh, data)
    assert completed == ["recon", "active_recon"]
    assert fresh.subdomains == ["a.example.com"]
    assert len(fresh.endpoints) == 1
    assert fresh.findings[0]["title"] == "test"


def test_orchestrator_resume_skip(tmp_path: Path):
    orch = Orchestrator(checkpoint_dir=str(tmp_path))
    state = orch.state
    state.phase = ScanPhase.AI_TEST
    state.endpoints = [{"url": "https://example.com", "method": "GET"}]
    store = orch.checkpoints
    store.save(
        state,
        reason="quit",
        completed_phases=["recon", "active_recon", "crawl"],
        next_phase="ai_test",
    )
    ok = orch.load_checkpoint()
    assert ok is True
    assert "recon" in orch._resume_skip
    assert "crawl" in orch._resume_skip
    assert "ai_test" not in orch._resume_skip


def test_controller_quit_noninteractive():
    ctrl = ScanController(interactive=False)
    ctrl._paused.set()
    action = ctrl._prompt_user("test")
    assert action == ControlAction.QUIT
    assert ctrl.should_quit is True


def test_phase_aliases_still_work():
    assert Orchestrator.normalize_phases(["enumeration"]) == ["crawl"]


def test_serialize_state_handles_enum():
    state = ScanState(phase=ScanPhase.DETECT)
    blob = serialize_state(state)
    assert blob["phase"] == "detect"
    # round-trip via json
    json.dumps(blob)
