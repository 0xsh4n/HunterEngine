"""
Pipeline orchestrator.

Coordinates the full scan lifecycle via hierarchical agents:
  Scope → Recon → Active Recon → Enumeration → AI Vuln Hunt → Detect → Correlate → AI Triage → Report

Manages concurrency, module loading, and data flow between stages.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

from core.scope_loader import ScopeLoader
from core.rate_limiter import RateLimiter
from core.waf_bypass import WAFBypass, BypassConfig
from core.session_manager import SessionManager
from core.browser_engine import BrowserEngine, BrowserConfig
from core.proxy_engine import ProxyEngine, ProxyConfig, find_available_port, is_port_available
from core.scan_control import ScanController, ControlAction
from core.checkpoint import CheckpointStore
from core.methodology import PIPELINE_ORDER, RUNNER_TO_STEP, METHODOLOGY

logger = logging.getLogger("hunterengine.orchestrator")


class ScanStopped(Exception):
    """Raised when the user quits or aborts a scan via ScanController."""

    def __init__(self, action: str, message: str = "", saved: bool = False) -> None:
        self.action = action
        self.saved = saved
        super().__init__(message or f"Scan stopped ({action})")


class ScanPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ACTIVE_RECON = "active_recon"
    CRAWL = "crawl"  # enumeration (alias: enumeration)
    THREAT_MODEL = "threat_model"
    DETECT = "detect"
    AI_TEST = "ai_test"
    POST_EXPLOIT = "post_exploit"
    CORRELATE = "correlate"
    AI = "ai"
    REPORT = "report"
    DONE = "done"


# CLI aliases → canonical phase value. Classic-pentest step names map onto the
# internal runner phases so `--phase exploitation` etc. work as expected.
PHASE_ALIASES: dict[str, str] = {
    "enumeration": ScanPhase.CRAWL.value,
    "enum": ScanPhase.CRAWL.value,
    "scanning": ScanPhase.ACTIVE_RECON.value,
    "threat_modeling": ScanPhase.THREAT_MODEL.value,
    "threatmodel": ScanPhase.THREAT_MODEL.value,
    "vuln": ScanPhase.AI_TEST.value,
    "vuln_analysis": ScanPhase.DETECT.value,
    "vulnerability_analysis": ScanPhase.DETECT.value,
    "vuln_hunt": ScanPhase.AI_TEST.value,
    "exploit": ScanPhase.AI_TEST.value,
    "exploitation": ScanPhase.AI_TEST.value,
    "post_exploitation": ScanPhase.POST_EXPLOIT.value,
    "postexploit": ScanPhase.POST_EXPLOIT.value,
    "passive_recon": ScanPhase.RECON.value,
    "reporting": ScanPhase.REPORT.value,
    "triage": ScanPhase.AI.value,
}


@dataclass
class ScanState:
    """Mutable scan state passed between pipeline stages."""
    phase: ScanPhase = ScanPhase.INIT
    start_time: float = field(default_factory=time.time)

    # Recon outputs
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    historical_urls: list[str] = field(default_factory=list)
    tech_stack: dict[str, Any] = field(default_factory=dict)

    # Crawl / enumeration outputs
    endpoints: list[dict] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    params: dict[str, list[str]] = field(default_factory=dict)
    graphql_schemas: list[dict] = field(default_factory=list)

    # Detection outputs
    findings: list[dict] = field(default_factory=list)
    weak_signals: list[dict] = field(default_factory=list)

    # Correlation outputs
    chained_findings: list[dict] = field(default_factory=list)
    ai_enriched_findings: int = 0
    ai_test_probes: int = 0
    ai_test_findings: int = 0

    # Stats
    total_requests: int = 0
    errors: list[str] = field(default_factory=list)
    # Explainable autonomous planning/health telemetry
    agentic_decisions: list[dict] = field(default_factory=list)
    phase_health: dict[str, dict] = field(default_factory=dict)
    behavior_model: dict[str, Any] = field(default_factory=dict)
    learning_events: list[dict] = field(default_factory=list)
    ai_token_usage: dict[str, int] = field(default_factory=dict)
    # Explainability: retained model chain-of-thought and a triage summary.
    ai_reasoning_traces: list[dict] = field(default_factory=list)
    ai_reasoning_summary: dict[str, Any] = field(default_factory=dict)
    # Post-exploitation (non-destructive) impact assessments.
    impact_assessments: list[dict] = field(default_factory=list)


class Orchestrator:
    """
    Central pipeline coordinator.

    Loads settings, initializes subsystems, and runs hierarchical agents
    in phase order with error handling and state management.
    """

    def __init__(
        self,
        scope_path: str = "config/scope.yaml",
        settings_path: str = "config/settings.yaml",
        auto_crawl: bool = False,
        headed: bool = False,
        skip_enum: bool = False,
        controller: Optional[ScanController] = None,
        checkpoint_dir: Optional[str] = None,
        profile: Optional[str] = None,
    ) -> None:
        self.scope_path = scope_path
        self.settings_path = settings_path
        self.settings: dict[str, Any] = {}
        self.state = ScanState()
        self.auto_crawl = auto_crawl
        self.headed = headed
        self.skip_enum = skip_enum
        self.profile = (profile or "").lower().strip() or None

        self.scope_loader: Optional[ScopeLoader] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.waf_bypass: Optional[WAFBypass] = None
        self.session_mgr: Optional[SessionManager] = None
        self.browser: Optional[BrowserEngine] = None
        self.proxy: Optional[ProxyEngine] = None
        self.knowledge_base = None
        self._proxy_host = "127.0.0.1"
        self._proxy_port = 8080
        self._proxy_enabled = False

        self.controller = controller or ScanController()
        self.checkpoints = CheckpointStore(checkpoint_dir)
        self._completed_phases: list[str] = []
        self._resume_skip: set[str] = set()
        self.last_checkpoint_path: Optional[Path] = None
        self._phase_reasoner: Any = None
        self._phase_progress: list[dict[str, Any]] = []

    def load_settings(self) -> dict[str, Any]:
        """Load settings.yaml."""
        path = Path(self.settings_path)
        if not path.exists():
            logger.warning(f"Settings not found at {path}, using defaults")
            return {}
        self.settings = yaml.safe_load(path.read_text()) or {}
        return self.settings

    def _agent_context(self):
        from ai.agents import AgentContext

        return AgentContext(
            settings=self.settings,
            scope_loader=self.scope_loader,
            rate_limiter=self.rate_limiter,
            waf_bypass=self.waf_bypass,
            browser=self.browser,
            session_mgr=self.session_mgr,
            auto_crawl=self.auto_crawl,
            headed=self.headed,
            skip_enum=self.skip_enum,
            proxy_enabled=self._proxy_enabled,
            proxy_host=self._proxy_host,
            proxy_port=self._proxy_port,
            extras={"controller": self.controller, "profile": self.profile or "blackbox", "knowledge_base": self.knowledge_base},
        )

    def load_checkpoint(self, path: Optional[str] = None) -> bool:
        """Load scan state from a checkpoint; prepare phase skip set for resume."""
        data = self.checkpoints.load(path)
        if not data:
            return False
        completed = self.checkpoints.apply_to_state(self.state, data)
        self._completed_phases = list(completed)
        self._resume_skip = set(completed)
        next_phase = data.get("next_phase")
        if next_phase:
            # Skip everything before next_phase in the methodology pipeline order
            order = list(PIPELINE_ORDER)
            if next_phase in order:
                idx = order.index(next_phase)
                self._resume_skip.update(order[:idx])
        logger.info(
            "Resume ready — skipping completed phases: %s (next=%s)",
            sorted(self._resume_skip) or "(none)",
            next_phase,
        )
        return True

    def _save_checkpoint(
        self,
        reason: str,
        next_phase: Optional[str] = None,
    ) -> Optional[Path]:
        try:
            path = self.checkpoints.save(
                self.state,
                reason=reason,
                completed_phases=list(self._completed_phases),
                next_phase=next_phase,
                meta={
                    "scope_path": self.scope_path,
                    "settings_path": self.settings_path,
                    "auto_crawl": self.auto_crawl,
                    "headed": self.headed,
                    "skip_enum": self.skip_enum,
                },
            )
            self.last_checkpoint_path = path
            return path
        except Exception as exc:
            logger.error("Failed to save checkpoint: %s", exc)
            return None

    async def _handle_control(self, label: str, next_phase: Optional[str] = None) -> None:
        """Process pause/quit/abort at a safe boundary."""
        action = await self.controller.checkpoint(label)
        if action == ControlAction.CONTINUE:
            return
        if action == ControlAction.QUIT:
            path = self._save_checkpoint("quit", next_phase=next_phase or label)
            raise ScanStopped("quit", saved=bool(path), message=f"Quit — checkpoint: {path}")
        if action == ControlAction.ABORT:
            raise ScanStopped("abort", saved=False, message="Aborted without saving")
        # PAUSE shouldn't remain after prompt; treat as continue
        return

    @staticmethod
    def normalize_phases(phases: Optional[list[str]]) -> Optional[list[str]]:
        """Resolve CLI aliases (enumeration → crawl, vuln → ai_test, …)."""
        if not phases:
            return None
        resolved = []
        for p in phases:
            key = (p or "").strip().lower()
            resolved.append(PHASE_ALIASES.get(key, key))
        return resolved

    async def setup(self) -> None:
        """Initialize all subsystems from config."""
        self.load_settings()
        # CLI profile overrides config, while unknown values safely fall back.
        configured_profile = str((self.settings.get("testing", {}) or {}).get("profile", "blackbox")).lower()
        self.profile = self.profile if self.profile in {"blackbox", "greybox"} else configured_profile
        if self.profile not in {"blackbox", "greybox"}:
            self.profile = "blackbox"
        self.settings.setdefault("safety", {}).setdefault("active_testing", {})["profile"] = self.profile
        try:
            from knowledge.rag import KnowledgeBase
            kb_conf = self.settings.get("knowledge", {}) or {}
            if kb_conf.get("enabled", True):
                self.knowledge_base = KnowledgeBase(kb_conf.get("index_path", "data/knowledge/index.json"),
                    chunk_size=kb_conf.get("chunk_size", 1200), overlap=kb_conf.get("chunk_overlap", 180))
                self.knowledge_base.load()
                logger.info("Knowledge RAG loaded: %d chunks", len(self.knowledge_base.chunks))
        except Exception as exc:
            logger.warning("Knowledge RAG unavailable; continuing without it: %s", exc)

        self.scope_loader = ScopeLoader(self.scope_path)
        self.scope_loader.load()
        logger.info(f"Scope loaded:\n{self.scope_loader.summary()}")

        rl_conf = self.settings.get("rate_limiting", {})
        self.rate_limiter = RateLimiter(
            global_rps=rl_conf.get("requests_per_second", 10),
            per_host_rps=rl_conf.get("per_host_rps", 5),
            burst_size=rl_conf.get("burst_size", 20),
            adaptive=rl_conf.get("adaptive", True),
            backoff_factor=rl_conf.get("backoff_factor", 2.0),
            backoff_max=rl_conf.get("backoff_max", 120),
        )

        waf_conf = self.settings.get("waf_bypass", {})
        ip_conf = waf_conf.get("ip_rotation", {})
        self.waf_bypass = WAFBypass(BypassConfig(
            ua_rotation=waf_conf.get("ua_rotation", True),
            referrer_spoof=waf_conf.get("referrer_spoof", True),
            delay_range=tuple(waf_conf.get("delay_range", [0.5, 2.0])),
            ip_rotation_enabled=ip_conf.get("enabled", False),
            ip_rotation_provider=ip_conf.get("provider", "aws"),
            ip_rotation_regions=ip_conf.get("regions", ["us-east-1"]),
        ))

        self.session_mgr = SessionManager(
            sessions_dir=Path(self.settings.get("general", {}).get("data_dir", "data")) / "sessions"
        )

        proxy_conf = self.settings.get("proxy", {})
        proxy_host = proxy_conf.get("listen_host", "127.0.0.1")
        proxy_port = proxy_conf.get("listen_port", 8080)
        if proxy_conf.get("enabled", True):
            if not is_port_available(proxy_host, proxy_port):
                if proxy_conf.get("auto_port", True):
                    new_port = find_available_port(proxy_host, proxy_port + 1)
                    logger.warning(
                        "Proxy port %s:%s is in use; using %s for this scan",
                        proxy_host,
                        proxy_port,
                        new_port,
                    )
                    proxy_port = new_port
                else:
                    logger.warning(
                        "Proxy port %s:%s is in use; proxy and browser proxying disabled",
                        proxy_host,
                        proxy_port,
                    )
                    proxy_conf["enabled"] = False

        if proxy_conf.get("enabled", True):
            self.proxy = ProxyEngine(ProxyConfig(
                listen_host=proxy_host,
                listen_port=proxy_port,
                auto_port=proxy_conf.get("auto_port", True),
                upstream_proxy=proxy_conf.get("upstream_proxy", ""),
                log_requests=proxy_conf.get("log_requests", True),
                intercept_mode=proxy_conf.get("intercept_mode", False),
            ))

        browser_conf = self.settings.get("browser", {})
        effective_proxy_enabled = bool(proxy_conf.get("enabled", True) and self.proxy)
        self.browser = BrowserEngine(BrowserConfig(
            headless=browser_conf.get("headless", True),
            proxy_url=f"http://{proxy_host}:{proxy_port}",
            use_proxy=effective_proxy_enabled,
            page_timeout=browser_conf.get("page_timeout", 30000),
            screenshot_dir=browser_conf.get("screenshot_dir", "data/screenshots"),
            chromium_args=browser_conf.get("chromium_args", []),
        ))
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_enabled = effective_proxy_enabled

        self.state.phase = ScanPhase.INIT

    async def run(self, phases: Optional[list[str]] = None) -> ScanState:
        """
        Run the full scan pipeline, or specific phases.

        Supports Ctrl+C pause → resume / quit (save) / abort.
        Auto-checkpoints after each completed phase for ``--resume``.

        Args:
            phases: Optional list of phase names to run.
                    If None, runs all phases in order.
        """
        phases = self.normalize_phases(phases)

        runner_map = {
            ScanPhase.RECON.value: self._run_recon,
            ScanPhase.ACTIVE_RECON.value: self._run_active_recon,
            ScanPhase.CRAWL.value: self._run_crawl,
            ScanPhase.THREAT_MODEL.value: self._run_threat_model,
            ScanPhase.DETECT.value: self._run_detect,
            ScanPhase.AI_TEST.value: self._run_ai_test,
            ScanPhase.POST_EXPLOIT.value: self._run_post_exploit,
            ScanPhase.CORRELATE.value: self._run_correlate,
            ScanPhase.AI.value: self._run_ai,
            ScanPhase.REPORT.value: self._run_report,
        }
        # Order follows the classic 8-step methodology (single source of truth).
        all_phases = [(ScanPhase(value), runner_map[value]) for value in PIPELINE_ORDER]
        self._init_phase_progress(all_phases, phases)

        self.controller.install()
        logger.info("Controls: Ctrl+C to pause → [r]esume / [q]uit+save / [a]bort")

        if self.proxy:
            await self.proxy.start()
        if self.browser:
            await self.browser.start()

        try:
            for i, (phase, runner) in enumerate(all_phases):
                if phases and phase.value not in phases:
                    continue
                if phase.value in self._resume_skip:
                    logger.info("═══ Skipping completed phase: %s ═══", phase.value.upper())
                    if phase.value not in self._completed_phases:
                        self._completed_phases.append(phase.value)
                    continue

                # Pause/quit check before starting a phase
                next_name = phase.value
                await self._handle_control(f"before:{next_name}", next_phase=next_name)

                self.state.phase = phase
                self._mark_phase(phase.value, "running")
                logger.info(f"═══ Starting phase: {phase.value.upper()} ═══")
                phase_start = time.time()

                # AI-in-every-phase: reason about what this phase will do first.
                await self._reason_phase(phase.value)

                try:
                    await runner()
                except ScanStopped:
                    raise
                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    logger.error(f"Phase {phase.value} failed: {e}")
                    logger.debug(tb)
                    # Record full traceback in state errors for diagnostics
                    self.state.errors.append(f"{phase.value}: {str(e)}")
                    self.state.errors.append(tb)
                    self.state.phase_health[phase.value] = {"status": "failed", "error": str(e)[:300], "traceback": tb[:4000]}
                    self.state.learning_events.append({"phase": phase.value, "result": "failure", "error": str(e)[:300]})
                    self._save_checkpoint("error", next_phase=phase.value)
                    self._mark_phase(phase.value, "failed", elapsed=round(time.time() - phase_start, 2))
                    # Continue by default: partial results are more useful than
                    # a crash. Strict mode can retain fail-fast behavior.
                    strict = bool((self.settings.get("general", {}) or {}).get("strict_failures", False))
                    if strict and phase in (ScanPhase.RECON, ScanPhase.ACTIVE_RECON):
                        raise
                else:
                    self.state.phase_health[phase.value] = {"status": "ok", "elapsed": round(time.time() - phase_start, 2)}
                    self.state.learning_events.append({"phase": phase.value, "result": "success", "elapsed": round(time.time() - phase_start, 2)})
                    self._mark_phase(phase.value, "done", elapsed=round(time.time() - phase_start, 2))

                elapsed = time.time() - phase_start
                logger.info(f"═══ Phase {phase.value} completed in {elapsed:.1f}s ═══")

                if phase.value not in self._completed_phases:
                    self._completed_phases.append(phase.value)

                # Determine next phase for checkpoint metadata
                upcoming = None
                for later_phase, _ in all_phases[i + 1:]:
                    if phases and later_phase.value not in phases:
                        continue
                    if later_phase.value in self._resume_skip:
                        continue
                    upcoming = later_phase.value
                    break

                self._save_checkpoint("phase", next_phase=upcoming)

                # Pause/quit check after phase
                await self._handle_control(phase.value, next_phase=upcoming)

            self.state.phase = ScanPhase.DONE
            self._persist_domain_learning()
            # Clear latest resume pointer on successful completion
            try:
                latest = self.checkpoints.directory / "latest.json"
                if latest.exists():
                    done_path = self._save_checkpoint("done", next_phase=None)
                    logger.info("Scan finished — final checkpoint: %s", done_path)
            except Exception:
                pass

        except ScanStopped as stop:
            logger.warning("%s", stop)
            if stop.action == "quit" and not stop.saved:
                self._persist_domain_learning()
                self._save_checkpoint("quit", next_phase=self.state.phase.value)
            raise
        finally:
            self.controller.uninstall()
            if self.browser:
                await self.browser.stop()
            if self.proxy:
                await self.proxy.stop()

        return self.state

    # ── Per-phase AI reasoning + progress ─────────────────────────────────
    def _get_phase_reasoner(self):
        if self._phase_reasoner is None:
            from ai.phase_reasoner import PhaseReasoner

            ai_conf = self.settings.get("ai", {}) or {}
            use_llm = bool(ai_conf.get("enabled")) and bool(ai_conf.get("phase_reasoning", False))
            client = None
            if use_llm:
                try:
                    from ai.ollama_client import OllamaClient
                    from ai.testing_agent import TestingAIConfig
                    client = OllamaClient(TestingAIConfig.from_settings(self.settings).to_client_config())
                except Exception as exc:
                    logger.debug("Phase reasoner LLM unavailable: %s", exc)
                    use_llm = False
            self._phase_reasoner = PhaseReasoner(client, use_llm=use_llm)
        return self._phase_reasoner

    async def _reason_phase(self, phase: str) -> None:
        """AI/deterministic rationale for the upcoming phase (never blocks it)."""
        try:
            decision = await self._get_phase_reasoner().reason(phase, self.state)
            logger.info("AI plan [%s]: %s", phase, decision.get("rationale", ""))
        except Exception as exc:
            logger.debug("Phase reasoning failed for %s: %s", phase, exc)

    def _init_phase_progress(self, all_phases, selected) -> None:
        prog: list[dict[str, Any]] = []
        for phase, _ in all_phases:
            if selected and phase.value not in selected:
                continue
            prog.append({
                "phase": phase.value,
                "step": RUNNER_TO_STEP.get(phase.value, phase.value),
                "status": "pending",
                "elapsed": None,
            })
        self._phase_progress = prog

    def _mark_phase(self, value: str, status: str, elapsed: Optional[float] = None) -> None:
        for row in self._phase_progress:
            if row["phase"] == value:
                row["status"] = status
                if elapsed is not None:
                    row["elapsed"] = elapsed
                break

    def _persist_domain_learning(self) -> None:
        """Write per-domain behaviour profiles once per run."""
        if getattr(self, "_domain_learned", False):
            return
        from memory.domain_learner import DomainLearner

        data_dir = (self.settings.get("general", {}) or {}).get("data_dir", "data")
        learner = DomainLearner(f"{data_dir}/domain_profiles")
        try:
            updated = learner.learn_from_scan(self.state, self.scope_loader)
            self._domain_learned = True
            if updated:
                logger.info("Domain learning wrote %d profile(s)", len(updated))
        except Exception as exc:
            logger.warning("Domain learning failed: %s", exc)
            self.state.errors.append(f"domain_learn: {exc}")

    async def _run_recon(self) -> None:
        """Passive recon agent: subdomain enum → DNS → historical URLs."""
        from ai.agents import ReconAgent

        await ReconAgent(self._agent_context()).run(self.state)

    async def _run_active_recon(self) -> None:
        """Active recon agent: live probe → tech fingerprint."""
        from ai.agents import ActiveReconAgent

        await ActiveReconAgent(self._agent_context()).run(self.state)

    async def _run_crawl(self) -> None:
        """Enumeration agent: crawl → JS → GraphQL → params."""
        from ai.agents import EnumerationAgent

        await EnumerationAgent(self._agent_context()).run(self.state)

    async def _run_threat_model(self) -> None:
        """Step 3 — Threat Modeling: scored attack surface + AI planning."""
        from ai.behavior import analyze_behavior
        from ai.agentic import AgenticPlanner

        model = analyze_behavior(self.state)
        AgenticPlanner(self.profile or "blackbox").apply(self.state)
        logger.info(
            "Threat model: risk=%s focus=%s state-changing=%s object-refs=%s",
            model.get("risk_score", 0),
            ",".join(a.get("area", "") for a in model.get("focus_areas", [])[:5]) or "none",
            model.get("state_changing_endpoints", 0),
            model.get("object_reference_endpoints", 0),
        )

    async def _run_ai_test(self) -> None:
        """Step 5 — Exploitation (safe validation): nested AI vuln hunters."""
        from ai.agents import VulnHuntAgent

        # Threat modeling normally runs first; ensure a model exists for
        # phase-only (`--phase exploitation`) runs.
        if not getattr(self.state, "behavior_model", None):
            await self._run_threat_model()

        await VulnHuntAgent(self._agent_context()).run(self.state)

    async def _run_post_exploit(self) -> None:
        """Step 6 — Post-Exploitation (impact): non-destructive impact assessment."""
        from ai.impact import assess_impact

        assess_impact(self.state)

    # Detectors that are cheap/passive — always worth running regardless of the
    # behaviour model, so behaviour-driven pruning never drops baseline coverage.
    _DETECTOR_MAP = {
        "secrets": "detection.secrets_detector.SecretsDetector",
        "cors": "detection.cors_detector.CORSDetector",
        "xss": "detection.xss_detector.XSSDetector",
        "jwt": "detection.jwt_detector.JWTDetector",
        "prototype_pollution": "detection.prototype_pollution.PrototypePollutionDetector",
        "ssrf": "detection.ssrf_detector.SSRFDetector",
        "idor": "detection.idor_detector.IDORDetector",
        "graphql": "detection.graphql_detector.GraphQLDetector",
        "auth": "detection.auth_detector.AuthDetector",
        "open_redirect": "detection.open_redirect.OpenRedirectDetector",
        "csp": "detection.csp_analyzer.CSPAnalyzer",
        "subdomain_takeover": "detection.subdomain_takeover.SubdomainTakeoverDetector",
        "dependency": "detection.dependency_scanner.DependencyScanner",
        "race_condition": "detection.race_condition.RaceConditionDetector",
        "crypto": "detection.crypto_specific.CryptoDetector",
    }
    _DETECTOR_BASELINE = {"secrets", "csp", "dependency", "subdomain_takeover"}

    async def _run_detect(self) -> None:
        """Step 4 — Vulnerability Analysis.

        Detectors are prioritized by the threat model and run concurrently
        (bounded) instead of one-at-a-time, which is where the old sequential
        loop spent most of its wall-clock time.
        """
        det_conf = self.settings.get("detection", {}) or {}
        modules_conf = det_conf.get("modules", {}) or {}
        threshold = det_conf.get("confidence_threshold", 0.6)
        behavior = getattr(self.state, "behavior_model", {}) or {}

        enabled = [n for n in self._DETECTOR_MAP if modules_conf.get(n, False)]
        ranked = self._rank_detectors(enabled, behavior)

        # Behaviour-driven pruning (opt-in): skip detectors with zero relevance
        # to the observed surface, except the cheap passive baseline.
        behaviour_driven = bool(det_conf.get("behaviour_driven", det_conf.get("behavior_driven", False)))
        if behaviour_driven and behavior.get("focus_areas"):
            pruned = [(n, s) for n, s in ranked if s > 0 or n in self._DETECTOR_BASELINE]
            if pruned:
                skipped = [n for n, _ in ranked if n not in {p for p, _ in pruned}]
                if skipped:
                    logger.info("Behaviour-driven detection skipped low-relevance: %s", ",".join(skipped))
                ranked = pruned

        concurrency = int(det_conf.get("concurrency", (self.settings.get("general", {}) or {}).get("concurrency", 6)))
        sem = asyncio.Semaphore(max(1, min(concurrency, 8)))
        logger.info(
            "Detection: %d detector(s) by relevance [%s], concurrency=%d",
            len(ranked), ",".join(n for n, _ in ranked) or "none", max(1, min(concurrency, 8)),
        )

        async def run_one(name: str) -> list[dict]:
            async with sem:
                if self.controller.should_stop:
                    return []
                try:
                    module_name, class_name = self._DETECTOR_MAP[name].rsplit(".", 1)
                    import importlib
                    mod = importlib.import_module(module_name)
                    detector = getattr(mod, class_name)(
                        rate_limiter=self.rate_limiter,
                        waf_bypass=self.waf_bypass,
                        scope_loader=self.scope_loader,
                        browser=self.browser,
                    )
                    return list(await detector.run(self.state) or [])
                except Exception as exc:
                    logger.error("Detector %s failed: %s", name, exc)
                    self.state.errors.append(f"detector.{name}: {exc}")
                    return []

        results = await asyncio.gather(*(run_one(name) for name, _ in ranked))
        for findings in results:
            for finding in findings:
                if finding.get("confidence", 0) >= threshold:
                    self.state.findings.append(finding)
                else:
                    self.state.weak_signals.append(finding)

    @staticmethod
    def _rank_detectors(enabled: list[str], behavior: dict[str, Any]) -> list[tuple[str, float]]:
        """Score detectors by relevance to the observed behaviour/surface."""
        focus_to_detectors = {
            "admin": ("auth", "idor"), "auth": ("auth", "jwt"),
            "account": ("idor", "auth"), "payment": ("idor", "auth"),
            "file": ("ssrf", "xss"), "api": ("idor", "ssrf", "graphql", "cors"),
            "graphql": ("graphql",), "idor_prone": ("idor",),
            "redirect": ("open_redirect",), "debug": ("secrets", "ssrf", "subdomain_takeover"),
        }
        scores: dict[str, float] = {name: 0.0 for name in enabled}
        for area in behavior.get("focus_areas", []) or []:
            name = area.get("area") if isinstance(area, dict) else area
            weight = float(area.get("score", 1.0)) if isinstance(area, dict) else 1.0
            for det in focus_to_detectors.get(str(name), ()):  # type: ignore[arg-type]
                if det in scores:
                    scores[det] += weight
        mechanisms = set(behavior.get("mechanisms", []) or [])
        if "token_or_jwt" in mechanisms and "jwt" in scores:
            scores["jwt"] += 1.5
        if "oauth_or_sso" in mechanisms:
            for det in ("auth", "open_redirect"):
                if det in scores:
                    scores[det] += 1.0
        # Stable order: relevance desc, then original config order.
        order = {name: i for i, name in enumerate(enabled)}
        return sorted(scores.items(), key=lambda kv: (-kv[1], order.get(kv[0], 99)))

    async def _run_correlate(self) -> None:
        """Correlation phase: chain weak signals into higher-severity findings."""
        from confidence.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        chained = engine.correlate(
            findings=self.state.findings,
            weak_signals=self.state.weak_signals,
            scan_state=self.state,
        )
        self.state.chained_findings = chained
        self.state.findings.extend(chained)

    async def _run_ai(self) -> None:
        """AI triage phase: reporting enrichment only (not bug hunting)."""
        from ai import LocalAIConfig, LocalAIReasoner

        config = LocalAIConfig.from_settings(self.settings)
        if not config.enabled:
            logger.info("AI triage (reporting) disabled")
            return

        reasoner = LocalAIReasoner(config)
        await reasoner.enrich_findings(self.state.findings, self.state)

    async def _run_report(self) -> None:
        """Report phase: generate output reports."""
        from reporting.triage_report import TriageReporter

        report_conf = self.settings.get("reporting", {})
        reporter = TriageReporter(
            output_dir=report_conf.get("output_dir", "data/reports"),
            formats=report_conf.get("format", ["markdown"]),
            include_evidence=report_conf.get("include_evidence", True),
            evidence_dirs=report_conf.get("evidence_dirs", [
                "data/screenshots", "data/eyewitness", "data/gowitness",
            ]),
            scope_name=getattr(getattr(self.scope_loader, "scope", None), "program_name", ""),
        )
        await reporter.generate(self.state)

    def get_stats(self) -> dict[str, Any]:
        """Return current scan statistics."""
        elapsed = time.time() - self.state.start_time
        return {
            "phase": self.state.phase.value,
            "elapsed_seconds": round(elapsed, 1),
            "subdomains": len(self.state.subdomains),
            "live_hosts": len(self.state.live_hosts),
            "endpoints": len(self.state.endpoints),
            "findings": len(self.state.findings),
            "weak_signals": len(self.state.weak_signals),
            "chained_findings": len(self.state.chained_findings),
            "ai_enriched_findings": self.state.ai_enriched_findings,
            "ai_test_probes": self.state.ai_test_probes,
            "ai_test_findings": self.state.ai_test_findings,
            "errors": len(self.state.errors),
            "profile": self.profile or "blackbox",
            "agentic_decisions": len(self.state.agentic_decisions),
            "ai_token_usage": self.state.ai_token_usage,
            "phase_health": self.state.phase_health,
            "phase_progress": self._phase_progress,
            "rate_limiter": self.rate_limiter.get_stats() if self.rate_limiter else {},
        }
