"""
Background scan controller for the dashboard.

Runs the async Orchestrator in a daemon thread (uvicorn owns the main event
loop), tracks live status, and supports graceful start/stop. Stop is
cooperative: it sets the ScanController's abort/quit flag, which the pipeline
honours at the next phase boundary (and detectors check mid-phase), so a scan
never gets hard-killed with half-written state.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Any, Optional

logger = logging.getLogger("hunterengine.dashboard.scan_manager")

VALID_PROFILES = {"blackbox", "greybox"}


class ScanManager:
    """Owns at most one background scan at a time."""

    def __init__(self, settings_path: str, scope_path: str) -> None:
        self.settings_path = settings_path
        self.scope_path = scope_path
        self._thread: Optional[threading.Thread] = None
        self._orch: Any = None
        self._controller: Any = None
        self._lock = threading.Lock()
        self._started_at: Optional[float] = None
        self._finished_at: Optional[float] = None
        self._outcome: str = "idle"  # idle|running|completed|stopped|quit|error
        self._error: str = ""
        self._target: str = ""
        self._profile: str = "blackbox"
        self._phases: Optional[list[str]] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, target: str = "", profile: str = "blackbox",
              phases: Optional[list[str]] = None) -> dict[str, Any]:
        with self._lock:
            if self.running:
                raise RuntimeError("A scan is already running")
            profile = (profile or "blackbox").lower().strip()
            if profile not in VALID_PROFILES:
                raise ValueError(f"profile must be one of {sorted(VALID_PROFILES)}")
            self._error = ""
            self._outcome = "running"
            self._target = (target or "").strip()
            self._profile = profile
            self._phases = phases or None
            self._orch = None
            self._controller = None
            self._started_at = time.time()
            self._finished_at = None
            self._thread = threading.Thread(
                target=self._run, name="he-scan", daemon=True,
                args=(self._target, profile, self._phases),
            )
            self._thread.start()
        logger.info("Dashboard scan started (target=%s profile=%s)", self._target or "scope", profile)
        return self.status()

    def stop(self, save: bool = False) -> dict[str, Any]:
        controller = self._controller
        if not self.running or controller is None:
            return self.status()
        if save:
            controller.request_quit()
        else:
            controller.request_abort()
        logger.info("Dashboard scan stop requested (save=%s)", save)
        return self.status()

    def _run(self, target: str, profile: str, phases: Optional[list[str]]) -> None:
        from core.orchestrator import Orchestrator, ScanStopped
        from core.scan_control import ScanController

        controller = ScanController(interactive=False)
        self._controller = controller
        orch = Orchestrator(
            scope_path=self.scope_path,
            settings_path=self.settings_path,
            controller=controller,
            profile=profile,
        )
        self._orch = orch

        async def go() -> None:
            await orch.setup()
            if target:
                value = target if target.startswith(("http://", "https://")) else f"https://{target}"
                loader = orch.scope_loader
                if loader:
                    loader.scope.in_scope_domains = []
                    loader.scope.in_scope_urls = [value]
                    loader._compile_patterns()
            await orch.run(phases=phases)

        try:
            asyncio.run(go())
            self._outcome = "completed"
        except ScanStopped as stop:
            self._outcome = "stopped" if stop.action == "abort" else "quit"
        except Exception as exc:  # pragma: no cover - defensive
            self._error = f"{type(exc).__name__}: {exc}"
            self._outcome = "error"
            logger.exception("Dashboard scan crashed")
        finally:
            self._finished_at = time.time()

    def status(self) -> dict[str, Any]:
        running = self.running
        out: dict[str, Any] = {
            "running": running,
            "outcome": "running" if running else self._outcome,
            "target": self._target,
            "profile": self._profile,
            "phases": self._phases,
            "error": self._error,
            "started_at": self._started_at,
            "finished_at": self._finished_at,
        }
        orch = self._orch
        if orch is not None:
            try:
                stats = orch.get_stats()
                state = orch.state
                out.update({
                    "phase": stats.get("phase"),
                    "progress": stats.get("phase_progress", []),
                    "elapsed": stats.get("elapsed_seconds"),
                    "counts": {
                        "live_hosts": stats.get("live_hosts", 0),
                        "endpoints": stats.get("endpoints", 0),
                        "findings": stats.get("findings", 0),
                        "weak_signals": stats.get("weak_signals", 0),
                    },
                    "ai_token_usage": stats.get("ai_token_usage", {}),
                    "recent_decisions": (getattr(state, "agentic_decisions", []) or [])[-8:],
                    "recent_traces": (getattr(state, "ai_reasoning_traces", []) or [])[-6:],
                    "errors": (getattr(state, "errors", []) or [])[-5:],
                })
            except Exception as exc:  # pragma: no cover
                out["stat_error"] = str(exc)
        return out
