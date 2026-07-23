"""
HunterEngine MCP server — drive the engine from Claude Desktop / Claude Code.

Instead of using a local LLM as a token backend, this exposes HunterEngine's
capabilities as MCP tools. Claude becomes the reasoning brain in the loop: it
starts scans, watches the 8-step pipeline, and reads back findings, the
behaviour model, and the engine's own reasoning traces to decide what to do
next. All active testing still runs behind scope + safety gates.

The tool *logic* lives in ``HunterEngineTools`` (no MCP dependency, unit
testable). ``build_server`` wraps it with FastMCP, imported lazily so the rest
of the project works without the ``mcp`` package installed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("hunterengine.mcp")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS = str(ROOT / "config" / "settings.yaml")
DEFAULT_SCOPE = str(ROOT / "config" / "scope.yaml")


class HunterEngineTools:
    """Transport-agnostic implementation of every MCP tool.

    Returns plain JSON-serializable dicts so it can be unit-tested without a
    running MCP client and reused by any transport.
    """

    def __init__(self, settings_path: str = DEFAULT_SETTINGS, scope_path: str = DEFAULT_SCOPE) -> None:
        # MCP clients launch the server with an arbitrary working directory, so
        # anchor any relative config path at the project root — otherwise
        # `config/scope.yaml` resolves against the client's cwd and vanishes.
        self.settings_path = self._resolve(settings_path)
        self.scope_path = self._resolve(scope_path)
        self._scan_manager: Any = None

    @staticmethod
    def _resolve(path: str) -> str:
        p = Path(path)
        if p.is_absolute():
            return str(p)
        anchored = ROOT / p
        # Prefer the root-anchored path when it exists; else fall back to cwd.
        return str(anchored if anchored.exists() else (p if p.exists() else anchored))

    # ── lazy singletons ───────────────────────────────────────────────────
    @property
    def scan_manager(self):
        if self._scan_manager is None:
            from dashboard.scan_manager import ScanManager
            self._scan_manager = ScanManager(self.settings_path, self.scope_path)
        return self._scan_manager

    def _settings(self) -> dict[str, Any]:
        from dashboard.app import _load_yaml
        return _load_yaml(Path(self.settings_path))

    def _run(self) -> dict[str, Any]:
        from dashboard.app import _load_latest_run
        return _load_latest_run(self._settings())

    # ── read-only context ─────────────────────────────────────────────────
    def methodology(self) -> dict[str, Any]:
        """The classic 8-step pentest pipeline HunterEngine follows."""
        from core.methodology import manifest
        return {"steps": manifest()}

    def get_scope(self) -> dict[str, Any]:
        """Current authorized scope (targets, out-of-scope rules)."""
        from dashboard.app import _load_yaml
        return _load_yaml(Path(self.scope_path)) or {"note": "scope.yaml not found"}

    async def ai_health(self) -> dict[str, Any]:
        """Probe the configured local model backend (optional when using MCP)."""
        from ai.ollama_client import OllamaClient
        from ai.testing_agent import TestingAIConfig
        cfg = TestingAIConfig.from_settings(self._settings())
        report = await OllamaClient(cfg.to_client_config()).health_check()
        return {"ok": bool(report.get("ok")), "report": report}

    # ── scan lifecycle ────────────────────────────────────────────────────
    def start_scan(self, target: str = "", profile: str = "blackbox",
                   phases: Optional[list[str]] = None) -> dict[str, Any]:
        """Start a background scan.

        target: single authorized URL/host (optional; overrides scope targets).
        profile: 'blackbox' or 'greybox' (greybox needs written authorization).
        phases: optional subset of the 8 steps; empty = full pipeline.
        Scope and safety gates are always enforced.
        """
        try:
            status = self.scan_manager.start(target=target, profile=profile, phases=phases)
            return {"ok": True, "status": status}
        except (RuntimeError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    def scan_status(self) -> dict[str, Any]:
        """Live scan status: current phase, 8-step progress, counts, reasoning."""
        return self.scan_manager.status()

    def stop_scan(self, save: bool = True) -> dict[str, Any]:
        """Stop the running scan at the next safe boundary (save=checkpoint)."""
        return {"ok": True, "status": self.scan_manager.stop(save=save)}

    # ── results ───────────────────────────────────────────────────────────
    def run_summary(self) -> dict[str, Any]:
        """Overview of the latest scan: phase, counts, severity breakdown."""
        run = self._run()
        if not run.get("available"):
            return {"available": False, "note": "No scan checkpoint yet — start_scan first."}
        return {
            "available": True,
            "phase": run.get("phase"),
            "saved_at": run.get("saved_at"),
            "counts": run.get("counts", {}),
            "severity_counts": run.get("severity_counts", {}),
            "ai_test_probes": run.get("ai_test_probes", 0),
            "errors": run.get("errors", [])[:5],
        }

    def list_findings(self, severity: str = "", limit: int = 50) -> dict[str, Any]:
        """Findings from the latest scan, optionally filtered by severity."""
        run = self._run()
        findings = [f for f in run.get("findings", []) if isinstance(f, dict)]
        if severity:
            sev = severity.lower().strip()
            findings = [f for f in findings if str(f.get("severity", "")).lower() == sev]
        trimmed = []
        for f in findings[: max(1, min(int(limit), 200))]:
            ai = (f.get("metadata") or {}).get("ai_analysis") or {}
            impact = (f.get("metadata") or {}).get("impact_assessment") or {}
            trimmed.append({
                "title": f.get("title"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "detector": f.get("detector"),
                "url": f.get("url"),
                "parameter": f.get("parameter"),
                "ai_priority": f.get("ai_priority"),
                "exploitability": ai.get("exploitability"),
                "impact_area": ai.get("impact_area"),
                "reasoning_steps": ai.get("reasoning_steps"),
                "blast_radius": impact.get("blast_radius"),
                "chainable_with": impact.get("chainable_with"),
                "remediation": f.get("remediation"),
                "tags": f.get("tags"),
            })
        return {"count": len(findings), "returned": len(trimmed), "findings": trimmed}

    def get_reasoning(self) -> dict[str, Any]:
        """The engine's captured reasoning: triage summary, thinking traces, decisions."""
        run = self._run()
        return {
            "available": run.get("available", False),
            "summary": run.get("reasoning_summary", {}),
            "traces": run.get("reasoning_traces", [])[-40:],
            "decisions": run.get("agentic_decisions", [])[-20:],
            "impact_assessments": (run.get("impact_assessments") or [])[:20]
            if isinstance(run, dict) else [],
        }

    def get_behavior(self) -> dict[str, Any]:
        """The scored attack-surface / behaviour model from threat modeling."""
        run = self._run()
        return {"available": run.get("available", False), "behavior": run.get("behavior_model", {})}

    def list_domains(self) -> dict[str, Any]:
        """Per-domain learning profiles + aggregate analytics."""
        from memory.domain_learner import DomainLearner
        from dashboard.app import _data_dir
        learner = DomainLearner(f"{_data_dir(self._settings())}/domain_profiles")
        return {"analytics": learner.analytics(), "profiles": learner.list_profiles()[:20]}


def build_server(settings_path: str = DEFAULT_SETTINGS, scope_path: str = DEFAULT_SCOPE):
    """Create a FastMCP server exposing HunterEngine tools (lazy mcp import)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise ImportError(
            "The MCP server needs the 'mcp' package. Install with: pip install \"mcp[cli]\""
        ) from exc

    tools = HunterEngineTools(settings_path, scope_path)
    server = FastMCP(
        "HunterEngine",
        instructions=(
            "HunterEngine is an authorized, safety-gated bug-bounty engine. Use these "
            "tools to run the classic 8-step pentest pipeline and reason over the "
            "results. Typical flow: get_scope → start_scan → poll scan_status until it "
            "is not running → run_summary → list_findings / get_reasoning / get_behavior. "
            "Only test targets the operator is authorized to test; scope and safety gates "
            "are enforced by the engine. Never attempt destructive actions."
        ),
    )

    # Register each tool method. FastMCP reads the docstring as the description.
    server.tool()(tools.methodology)
    server.tool()(tools.get_scope)
    server.tool()(tools.ai_health)
    server.tool()(tools.start_scan)
    server.tool()(tools.scan_status)
    server.tool()(tools.stop_scan)
    server.tool()(tools.run_summary)
    server.tool()(tools.list_findings)
    server.tool()(tools.get_reasoning)
    server.tool()(tools.get_behavior)
    server.tool()(tools.list_domains)
    return server


def run_stdio(settings_path: str = DEFAULT_SETTINGS, scope_path: str = DEFAULT_SCOPE) -> None:
    """Run the MCP server over stdio (for Claude Desktop / Claude Code)."""
    server = build_server(settings_path, scope_path)
    logger.info("HunterEngine MCP server starting on stdio")
    server.run()
