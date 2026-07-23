"""
Scan checkpoint persistence — save / load ScanState for resume.

Checkpoints are JSON files under ``data/checkpoints/``.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("hunterengine.checkpoint")

DEFAULT_DIR = Path("data/checkpoints")
LATEST_NAME = "latest.json"


def _json_default(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if hasattr(obj, "value"):  # Enum
        try:
            return obj.value
        except Exception:
            pass
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, set):
        return list(obj)
    return str(obj)


def serialize_state(state: Any) -> dict[str, Any]:
    """Convert ScanState (and nested TechProfile etc.) to JSON-safe dict."""
    phase = getattr(state, "phase", None)
    phase_val = phase.value if hasattr(phase, "value") else str(phase or "init")

    tech_raw = getattr(state, "tech_stack", {}) or {}
    tech_out: dict[str, Any] = {}
    for url, profile in tech_raw.items():
        if is_dataclass(profile) and not isinstance(profile, type):
            tech_out[url] = asdict(profile)
        elif isinstance(profile, dict):
            tech_out[url] = profile
        else:
            tech_out[url] = {"url": url, "repr": str(profile)}

    return {
        "phase": phase_val,
        "start_time": getattr(state, "start_time", time.time()),
        "subdomains": list(getattr(state, "subdomains", []) or []),
        "live_hosts": list(getattr(state, "live_hosts", []) or []),
        "historical_urls": list(getattr(state, "historical_urls", []) or []),
        "tech_stack": tech_out,
        "endpoints": list(getattr(state, "endpoints", []) or []),
        "js_files": list(getattr(state, "js_files", []) or []),
        "params": dict(getattr(state, "params", {}) or {}),
        "graphql_schemas": list(getattr(state, "graphql_schemas", []) or []),
        "findings": list(getattr(state, "findings", []) or []),
        "weak_signals": list(getattr(state, "weak_signals", []) or []),
        "chained_findings": list(getattr(state, "chained_findings", []) or []),
        "ai_enriched_findings": int(getattr(state, "ai_enriched_findings", 0) or 0),
        "ai_test_probes": int(getattr(state, "ai_test_probes", 0) or 0),
        "ai_test_findings": int(getattr(state, "ai_test_findings", 0) or 0),
        "total_requests": int(getattr(state, "total_requests", 0) or 0),
        "errors": list(getattr(state, "errors", []) or []),
        "agentic_decisions": list(getattr(state, "agentic_decisions", []) or []),
        "phase_health": dict(getattr(state, "phase_health", {}) or {}),
        "behavior_model": dict(getattr(state, "behavior_model", {}) or {}),
        "learning_events": list(getattr(state, "learning_events", []) or [])[-500:],
        "ai_token_usage": dict(getattr(state, "ai_token_usage", {}) or {}),
        "ai_reasoning_traces": list(getattr(state, "ai_reasoning_traces", []) or [])[-300:],
        "ai_reasoning_summary": dict(getattr(state, "ai_reasoning_summary", {}) or {}),
        "impact_assessments": list(getattr(state, "impact_assessments", []) or [])[-100:],
    }


def restore_tech_stack(raw: dict[str, Any]) -> dict[str, Any]:
    """Rebuild TechProfile objects where possible."""
    try:
        from recon.tech_fingerprint import TechProfile
    except Exception:
        return raw

    out: dict[str, Any] = {}
    for url, profile in (raw or {}).items():
        if isinstance(profile, dict):
            known = {f.name for f in TechProfile.__dataclass_fields__.values()}  # type: ignore[attr-defined]
            kwargs = {k: v for k, v in profile.items() if k in known}
            try:
                out[url] = TechProfile(**kwargs)
            except Exception:
                out[url] = profile
        else:
            out[url] = profile
    return out


class CheckpointStore:
    """Save and load scan checkpoints."""

    def __init__(self, directory: str | Path | None = None) -> None:
        self.directory = Path(directory or DEFAULT_DIR)
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        state: Any,
        *,
        reason: str = "auto",
        completed_phases: Optional[list[str]] = None,
        next_phase: Optional[str] = None,
        meta: Optional[dict[str, Any]] = None,
    ) -> Path:
        """Persist scan state; also updates ``latest.json``."""
        payload = {
            "version": 1,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "completed_phases": completed_phases or [],
            "next_phase": next_phase,
            "meta": meta or {},
            "state": serialize_state(state),
        }
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = self.directory / f"checkpoint_{stamp}_{reason}.json"
        text = json.dumps(payload, indent=2, default=_json_default)
        path.write_text(text, encoding="utf-8")
        latest = self.directory / LATEST_NAME
        latest.write_text(text, encoding="utf-8")
        logger.info("Checkpoint saved → %s (reason=%s, next=%s)", path, reason, next_phase)
        return path

    def load(self, path: Optional[str | Path] = None) -> Optional[dict[str, Any]]:
        """Load a checkpoint file (defaults to latest)."""
        target = Path(path) if path else (self.directory / LATEST_NAME)
        if not target.exists():
            logger.warning("No checkpoint found at %s", target)
            return None
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.error("Failed to load checkpoint %s: %s", target, exc)
            return None
        logger.info(
            "Loaded checkpoint from %s (saved_at=%s, next=%s)",
            target,
            data.get("saved_at"),
            data.get("next_phase"),
        )
        return data

    def apply_to_state(self, state: Any, checkpoint: dict[str, Any]) -> list[str]:
        """
        Mutate ``state`` with checkpoint contents.

        Returns list of completed phase names to skip on resume.
        """
        from core.orchestrator import ScanPhase

        blob = checkpoint.get("state") or {}
        state.subdomains = list(blob.get("subdomains") or [])
        state.live_hosts = list(blob.get("live_hosts") or [])
        state.historical_urls = list(blob.get("historical_urls") or [])
        state.tech_stack = restore_tech_stack(blob.get("tech_stack") or {})
        state.endpoints = list(blob.get("endpoints") or [])
        state.js_files = list(blob.get("js_files") or [])
        state.params = dict(blob.get("params") or {})
        state.graphql_schemas = list(blob.get("graphql_schemas") or [])
        state.findings = list(blob.get("findings") or [])
        state.weak_signals = list(blob.get("weak_signals") or [])
        state.chained_findings = list(blob.get("chained_findings") or [])
        state.ai_enriched_findings = int(blob.get("ai_enriched_findings") or 0)
        state.ai_test_probes = int(blob.get("ai_test_probes") or 0)
        state.ai_test_findings = int(blob.get("ai_test_findings") or 0)
        state.total_requests = int(blob.get("total_requests") or 0)
        state.errors = list(blob.get("errors") or [])
        state.agentic_decisions = list(blob.get("agentic_decisions") or [])
        state.phase_health = dict(blob.get("phase_health") or {})
        state.behavior_model = dict(blob.get("behavior_model") or {})
        state.learning_events = list(blob.get("learning_events") or [])
        state.ai_token_usage = dict(blob.get("ai_token_usage") or {})
        state.ai_reasoning_traces = list(blob.get("ai_reasoning_traces") or [])
        state.ai_reasoning_summary = dict(blob.get("ai_reasoning_summary") or {})
        state.impact_assessments = list(blob.get("impact_assessments") or [])
        state.start_time = float(blob.get("start_time") or time.time())

        phase_str = blob.get("phase") or checkpoint.get("next_phase") or "init"
        try:
            state.phase = ScanPhase(phase_str)
        except ValueError:
            state.phase = ScanPhase.INIT

        completed = list(checkpoint.get("completed_phases") or [])
        return completed

    def list_checkpoints(self) -> list[dict[str, Any]]:
        """Return summary rows for available checkpoints (newest first)."""
        rows: list[dict[str, Any]] = []
        for path in sorted(self.directory.glob("checkpoint_*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                st = data.get("state") or {}
                rows.append({
                    "path": str(path),
                    "saved_at": data.get("saved_at", ""),
                    "reason": data.get("reason", ""),
                    "next_phase": data.get("next_phase"),
                    "completed": data.get("completed_phases") or [],
                    "endpoints": len(st.get("endpoints") or []),
                    "findings": len(st.get("findings") or []),
                    "live_hosts": len(st.get("live_hosts") or []),
                })
            except Exception:
                continue
        return rows

    def latest_path(self) -> Optional[Path]:
        p = self.directory / LATEST_NAME
        return p if p.exists() else None
