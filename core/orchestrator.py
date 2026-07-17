"""
Pipeline orchestrator.

Coordinates the full scan lifecycle:
  Scope → Recon → Crawl → AI Test → Detect → Correlate → AI Triage → Report

Manages concurrency, module loading, and data flow between stages.
"""

from __future__ import annotations

import asyncio
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

logger = logging.getLogger("hunterengine.orchestrator")


class ScanPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    CRAWL = "crawl"
    AI_TEST = "ai_test"
    DETECT = "detect"
    CORRELATE = "correlate"
    AI = "ai"
    REPORT = "report"
    DONE = "done"


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

    # Crawl outputs
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


class Orchestrator:
    """
    Central pipeline coordinator.

    Loads settings, initializes all subsystems, and runs the
    scan pipeline in order with proper error handling and state management.
    """

    def __init__(
        self,
        scope_path: str = "config/scope.yaml",
        settings_path: str = "config/settings.yaml",
        auto_crawl: bool = False,
        headed: bool = False,
        skip_enum: bool = False,
    ) -> None:
        self.scope_path = scope_path
        self.settings_path = settings_path
        self.settings: dict[str, Any] = {}
        self.state = ScanState()
        self.auto_crawl = auto_crawl
        self.headed = headed
        self.skip_enum = skip_enum

        # Subsystems (initialized in setup())
        self.scope_loader: Optional[ScopeLoader] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.waf_bypass: Optional[WAFBypass] = None
        self.session_mgr: Optional[SessionManager] = None
        self.browser: Optional[BrowserEngine] = None
        self.proxy: Optional[ProxyEngine] = None

    # ── Setup ─────────────────────────────────────────────────────────────

    def load_settings(self) -> dict[str, Any]:
        """Load settings.yaml."""
        path = Path(self.settings_path)
        if not path.exists():
            logger.warning(f"Settings not found at {path}, using defaults")
            return {}
        self.settings = yaml.safe_load(path.read_text()) or {}
        return self.settings

    async def setup(self) -> None:
        """Initialize all subsystems from config."""
        self.load_settings()

        # Scope
        self.scope_loader = ScopeLoader(self.scope_path)
        self.scope_loader.load()
        logger.info(f"Scope loaded:\n{self.scope_loader.summary()}")

        # Rate limiter
        rl_conf = self.settings.get("rate_limiting", {})
        self.rate_limiter = RateLimiter(
            global_rps=rl_conf.get("requests_per_second", 10),
            per_host_rps=rl_conf.get("per_host_rps", 5),
            burst_size=rl_conf.get("burst_size", 20),
            adaptive=rl_conf.get("adaptive", True),
            backoff_factor=rl_conf.get("backoff_factor", 2.0),
            backoff_max=rl_conf.get("backoff_max", 120),
        )

        # WAF bypass
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

        # Session manager
        db_conf = self.settings.get("database", {})
        self.session_mgr = SessionManager(
            sessions_dir=Path(self.settings.get("general", {}).get("data_dir", "data")) / "sessions"
        )

        # Proxy
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

        # Browser — use the effective proxy port (may have been remapped)
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
        # Stash effective proxy for crawl/auto-navigator (avoids listen_port desync)
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_enabled = effective_proxy_enabled

        self.state.phase = ScanPhase.INIT

    # ── Pipeline ──────────────────────────────────────────────────────────

    async def run(self, phases: Optional[list[str]] = None) -> ScanState:
        """
        Run the full scan pipeline, or specific phases.

        Args:
            phases: Optional list of phase names to run.
                    If None, runs all phases in order.
        """
        all_phases = [
            (ScanPhase.RECON, self._run_recon),
            (ScanPhase.CRAWL, self._run_crawl),
            (ScanPhase.AI_TEST, self._run_ai_test),
            (ScanPhase.DETECT, self._run_detect),
            (ScanPhase.CORRELATE, self._run_correlate),
            (ScanPhase.AI, self._run_ai),
            (ScanPhase.REPORT, self._run_report),
        ]

        # Start proxy and browser
        if self.proxy:
            await self.proxy.start()
        if self.browser:
            await self.browser.start()

        try:
            for phase, runner in all_phases:
                if phases and phase.value not in phases:
                    continue

                self.state.phase = phase
                logger.info(f"═══ Starting phase: {phase.value.upper()} ═══")
                phase_start = time.time()

                try:
                    await runner()
                except Exception as e:
                    logger.error(f"Phase {phase.value} failed: {e}")
                    self.state.errors.append(f"{phase.value}: {str(e)}")
                    if phase in (ScanPhase.RECON,):
                        raise  # Critical phase — abort

                elapsed = time.time() - phase_start
                logger.info(f"═══ Phase {phase.value} completed in {elapsed:.1f}s ═══")

            self.state.phase = ScanPhase.DONE

        finally:
            # Cleanup
            if self.browser:
                await self.browser.stop()
            if self.proxy:
                await self.proxy.stop()

        return self.state

    # ── Phase runners ─────────────────────────────────────────────────────

    async def _run_recon(self) -> None:
        """Recon phase: subdomain enum → DNS resolve → live probe → historical URLs."""
        from recon.subdomain_enum import SubdomainEnumerator
        from recon.dns_resolver import DNSResolver
        from recon.live_prober import LiveProber
        from recon.historical_urls import HistoricalURLCollector
        from recon.tech_fingerprint import TechFingerprinter

        domains = self.scope_loader.get_root_domains()
        logger.info(f"Recon targets: {domains}")

        # Subdomain enumeration
        if self.skip_enum:
            logger.info("Skipping subdomain enumeration (using provided domains only)")
            self.state.subdomains = domains[:]
        else:
            enumerator = SubdomainEnumerator()
            for domain in domains:
                subs = await enumerator.enumerate(domain)
                self.state.subdomains.extend(subs)
            self.state.subdomains = list(set(self.state.subdomains))
            logger.info(f"Found {len(self.state.subdomains)} unique subdomains")

        # Filter to in-scope
        old_subdomains = self.state.subdomains[:]
        original_count = len(old_subdomains)
        if original_count > 0:
            logger.debug(f"Sample before filtering: {old_subdomains[:3]}")
            
        self.state.subdomains = self.scope_loader.filter_in_scope(self.state.subdomains)
        
        if original_count > 0 and len(self.state.subdomains) == 0:
            logger.warning("All subdomains were filtered out by ScopeLoader! Check if scope.yaml has a wildcard (e.g., *.domain.com).")
            logger.warning(f"First rejected item was exactly: {repr(old_subdomains[0] if old_subdomains else 'none')}")

        # DNS resolution
        resolver = DNSResolver()
        resolved = await resolver.resolve_bulk(self.state.subdomains)
        self.state.subdomains = [r["hostname"] for r in resolved if r.get("resolved")]

        # Live host probing
        prober = LiveProber(rate_limiter=self.rate_limiter, waf_bypass=self.waf_bypass)
        self.state.live_hosts = await prober.probe_hosts(self.state.subdomains)
        logger.info(f"Live hosts: {len(self.state.live_hosts)}")

        # Historical URLs
        collector = HistoricalURLCollector()
        for domain in domains:
            urls = await collector.collect(domain)
            self.state.historical_urls.extend(urls)
        self.state.historical_urls = self.scope_loader.filter_in_scope(
            list(set(self.state.historical_urls))
        )

        # Tech fingerprinting
        fingerprinter = TechFingerprinter()
        for host_info in self.state.live_hosts[:50]:  # Top 50
            tech = await fingerprinter.detect(host_info.get("url", ""))
            url = host_info.get("url", "")
            self.state.tech_stack[url] = tech

    async def _run_crawl(self) -> None:
        """Crawl phase: auto-navigator + active crawl → JS crawl → JS analysis → param mining."""
        from crawl.active_crawler import ActiveCrawler
        from crawl.js_crawler import JSCrawler
        from crawl.js_analyzer import JSAnalyzer
        from crawl.param_miner import ParamMiner
        from crawl.graphql_mapper import GraphQLMapper

        crawl_conf = self.settings.get("crawl", {})
        live_urls = [h.get("url", "") for h in self.state.live_hosts if h.get("url")]
        # Seed with historical URLs (in-scope) so crawl covers Wayback/gau surface
        historical_seeds = [
            u for u in (self.state.historical_urls or [])[:150]
            if u and (not self.scope_loader or self.scope_loader.is_in_scope(u))
        ]
        urls_to_crawl = list(dict.fromkeys(live_urls + historical_seeds))

        # Merge tech_stack fingerprints into live_hosts for SPA detection
        self._enrich_live_hosts_tech()

        # ── Auto-navigator (integrated browser crawl) ─────────────────────
        if self.auto_crawl:
            from crawl.auto_navigator import AutoNavigator, NavigatorConfig

            proxy_url = ""
            if getattr(self, "_proxy_enabled", False):
                proxy_url = f"http://{self._proxy_host}:{self._proxy_port}"

            nav_config = NavigatorConfig(
                headless=not self.headed,  # headed=True → visible browser
                max_pages=crawl_conf.get("max_pages", 500),
                max_depth=crawl_conf.get("max_depth", 10),
                page_timeout=self.settings.get("browser", {}).get("page_timeout", 30_000),
                form_submit=crawl_conf.get("form_fill", False),
                screenshot_dir=self.settings.get("browser", {}).get("screenshot_dir", "data/screenshots"),
                proxy_url=proxy_url,
                chromium_args=self.settings.get("browser", {}).get("chromium_args", [
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ]),
            )
            navigator = AutoNavigator(config=nav_config, scope_loader=self.scope_loader)
            nav_results = await navigator.crawl(urls_to_crawl[:50] or live_urls)
            self.state.endpoints.extend(nav_results.get("endpoints", []))
            self.state.js_files.extend(nav_results.get("js_files", []))
            # Promote in-scope network XHR/fetch into endpoints
            for req in nav_results.get("network_requests", []) or []:
                req_url = req.get("url", "")
                if not req_url:
                    continue
                if self.scope_loader and not self.scope_loader.is_in_scope(req_url):
                    continue
                if req.get("resource_type") in ("xhr", "fetch", "websocket", "document"):
                    self.state.endpoints.append({
                        "url": req_url,
                        "method": req.get("method", "GET"),
                        "source": "auto_navigator_network",
                        "status": req.get("status", 0),
                    })
            logger.info(
                "Auto-navigator: %d endpoints, %d JS files, %d network requests",
                len(nav_results.get("endpoints", [])),
                len(nav_results.get("js_files", [])),
                len(nav_results.get("network_requests", [])),
            )

        # ── External tool crawling (katana, gospider, hakrawler) ──────────
        crawler = ActiveCrawler(
            rate_limiter=self.rate_limiter,
            waf_bypass=self.waf_bypass,
            max_depth=crawl_conf.get("max_depth", 5),
        )
        crawl_results = await crawler.crawl(urls_to_crawl[:80] or live_urls)
        self.state.endpoints.extend(crawl_results.get("endpoints", []))
        self.state.js_files.extend(crawl_results.get("js_files", []))

        # JS rendering for SPAs (uses tech on live_hosts + tech_stack)
        if crawl_conf.get("js_rendering", True) and self.browser:
            js_crawler = JSCrawler(
                browser=self.browser,
                scope_loader=self.scope_loader,
                tech_stack=self.state.tech_stack,
            )
            spa_endpoints = await js_crawler.crawl_spa_targets(self.state.live_hosts)
            self.state.endpoints.extend(spa_endpoints)

        # GraphQL discovery / introspection
        try:
            mapper = GraphQLMapper()
            graphql_maps = await mapper.map_all(live_urls[:30])
            self.state.graphql_schemas = graphql_maps
            for gq in graphql_maps:
                self.state.endpoints.append({
                    "url": gq.get("url", ""),
                    "method": "POST",
                    "source": "graphql_mapper",
                    "introspection": gq.get("introspection_enabled", False),
                })
            if graphql_maps:
                logger.info("GraphQL mapper: %d endpoint(s)", len(graphql_maps))
        except Exception as exc:
            logger.warning("GraphQL mapping failed: %s", exc)

        # JS analysis
        analyzer = JSAnalyzer()
        for js_url in list(dict.fromkeys(self.state.js_files))[:200]:
            findings = await analyzer.analyze(js_url)
            self.state.weak_signals.extend(findings.get("secrets", []))
            self.state.endpoints.extend(findings.get("endpoints", []))

        # Parameter mining
        miner = ParamMiner(rate_limiter=self.rate_limiter)
        target_urls = [ep.get("url", "") for ep in self.state.endpoints[:100]]
        params = await miner.discover(target_urls)
        self.state.params.update(params)

        # Deduplicate endpoints by method+url (keep distinct verbs)
        seen: set[str] = set()
        unique: list[dict] = []
        for ep in self.state.endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            if self.scope_loader and not self.scope_loader.is_in_scope(url):
                continue
            key = f"{(ep.get('method') or 'GET').upper()}:{url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        self.state.endpoints = unique
        self.state.js_files = list(dict.fromkeys(self.state.js_files))

    async def _run_ai_test(self) -> None:
        """AI testing phase: local Ollama bug-hunt subagents (not reporting)."""
        from ai import TestingAIConfig, TestingAgent

        config = TestingAIConfig.from_settings(self.settings)
        if not config.enabled:
            logger.info("AI testing mode disabled")
            return

        agent = TestingAgent(
            config=config,
            rate_limiter=self.rate_limiter,
            waf_bypass=self.waf_bypass,
            scope_loader=self.scope_loader,
        )
        findings = await agent.run(self.state)
        threshold = self.settings.get("detection", {}).get("confidence_threshold", 0.6)
        for finding in findings:
            if finding.get("confidence", 0) >= threshold:
                self.state.findings.append(finding)
            else:
                self.state.weak_signals.append(finding)

    async def _run_detect(self) -> None:
        """Detection phase: run enabled detection modules."""
        det_conf = self.settings.get("detection", {})
        modules_conf = det_conf.get("modules", {})
        threshold = det_conf.get("confidence_threshold", 0.6)

        # Dynamic module loading
        detector_map = {
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

        for name, module_path in detector_map.items():
            if not modules_conf.get(name, False):
                continue

            logger.info(f"Running detector: {name}")
            try:
                module_name, class_name = module_path.rsplit(".", 1)
                import importlib
                mod = importlib.import_module(module_name)
                detector_cls = getattr(mod, class_name)
                detector = detector_cls(
                    rate_limiter=self.rate_limiter,
                    waf_bypass=self.waf_bypass,
                    scope_loader=self.scope_loader,
                    browser=self.browser,
                )
                results = await detector.run(self.state)
                for finding in results:
                    if finding.get("confidence", 0) >= threshold:
                        self.state.findings.append(finding)
                    else:
                        self.state.weak_signals.append(finding)
            except Exception as e:
                logger.error(f"Detector {name} failed: {e}")
                self.state.errors.append(f"detector.{name}: {str(e)}")

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

    def _enrich_live_hosts_tech(self) -> None:
        """Merge TechProfile fingerprints into live_hosts.tech for SPA gating."""
        for host in self.state.live_hosts:
            url = host.get("url", "")
            profile = self.state.tech_stack.get(url)
            existing = list(host.get("tech") or [])
            if profile is None:
                continue
            names: list[str] = []
            if hasattr(profile, "frameworks"):
                names.extend(getattr(profile, "frameworks", []) or [])
                names.extend(getattr(profile, "js_libraries", []) or [])
                if getattr(profile, "is_spa", False):
                    host["is_spa"] = True
                if getattr(profile, "has_graphql", False):
                    host["has_graphql"] = True
            elif isinstance(profile, dict):
                names.extend(profile.get("frameworks", []) or [])
                names.extend(profile.get("tech", []) or [])
                host["is_spa"] = bool(profile.get("is_spa", host.get("is_spa", False)))
            merged = []
            seen_lower: set[str] = set()
            for name in existing + [str(n) for n in names]:
                key = name.lower()
                if key and key not in seen_lower:
                    seen_lower.add(key)
                    merged.append(name)
            host["tech"] = merged

    async def _run_report(self) -> None:
        """Report phase: generate output reports."""
        from reporting.triage_report import TriageReporter

        report_conf = self.settings.get("reporting", {})
        reporter = TriageReporter(
            output_dir=report_conf.get("output_dir", "data/reports"),
            formats=report_conf.get("format", ["markdown"]),
            include_evidence=report_conf.get("include_evidence", True),
        )
        await reporter.generate(self.state)

    # ── Utilities ─────────────────────────────────────────────────────────

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
            "rate_limiter": self.rate_limiter.get_stats() if self.rate_limiter else {},
        }
