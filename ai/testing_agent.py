"""
AI testing mode — local bug hunter via pentest subagents.

Runs after crawl / alongside detection. Uses Ollama (Qwen3 + reasoning)
to prioritize targets and propose scoped probes, then executes those probes
through rate-limited, scope-gated HTTP — never via the reporting triage path.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from ai.ollama_client import OllamaClient, OllamaClientConfig
from ai.subagents import SUBAGENT_REGISTRY, HunterSubagent, PlannedProbe, ProbePlan
from core.rate_limiter import RateLimiter
from core.scope_loader import ScopeLoader
from core.waf_bypass import WAFBypass
from detection.base_detector import Severity

logger = logging.getLogger("hunterengine.ai.testing_agent")

STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".mp4", ".webp",
)


@dataclass
class TestingAIConfig:
    """Configuration for AI-driven testing (separate from report triage)."""

    enabled: bool = False
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen3:4b"
    timeout: float = 90.0
    temperature: float = 0.2
    think: Any = True
    concurrency: int = 3
    max_endpoints: int = 40
    max_probes_per_agent: int = 8
    max_total_probes: int = 60
    subagents: list[str] = field(
        default_factory=lambda: [
            "xss", "idor", "ssti", "ssrf", "auth", "open_redirect",
            "request_smuggling", "cors", "jwt",
        ]
    )
    min_confidence: float = 0.55
    num_ctx: int = 8192
    num_predict: int = 1536
    api_key_env: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: dict[str, Any]) -> "TestingAIConfig":
        ai_conf = settings.get("ai", {}) or {}
        testing = ai_conf.get("testing", {}) or {}
        model_block = ai_conf.get("testing_model") or testing.get("model") or {}
        if not isinstance(model_block, dict):
            model_block = {}

        # Prefer testing_model; fall back to local_model only for connection bits
        local = ai_conf.get("local_model", {}) or {}
        client_cfg = OllamaClientConfig.from_model_block(
            model_block,
            provider=ai_conf.get("provider", "ollama"),
            defaults={
                "provider": ai_conf.get("provider", "ollama"),
                "base_url": local.get("base_url", "http://127.0.0.1:11434"),
                "model": "qwen3:4b",
                "timeout": 90,
                "temperature": 0.2,
                "think": True,
                "num_ctx": 8192,
                "num_predict": 1536,
                "api_key_env": "",
            },
        )

        mode = str(ai_conf.get("mode", "triage")).lower().strip()
        testing_enabled = bool(testing.get("enabled", mode in ("testing", "both")))
        if not ai_conf.get("enabled", False):
            testing_enabled = False

        subagents = testing.get("subagents") or [
            "xss", "idor", "ssti", "ssrf", "auth", "open_redirect",
            "request_smuggling", "cors", "jwt",
        ]

        return cls(
            enabled=testing_enabled,
            provider=client_cfg.provider,
            base_url=client_cfg.base_url,
            model=client_cfg.model,
            timeout=client_cfg.timeout,
            temperature=client_cfg.temperature,
            think=client_cfg.think,
            concurrency=int(testing.get("concurrency", 3)),
            max_endpoints=int(testing.get("max_endpoints", 40)),
            max_probes_per_agent=int(testing.get("max_probes_per_agent", 8)),
            max_total_probes=int(testing.get("max_total_probes", 60)),
            subagents=[str(s).lower() for s in subagents],
            min_confidence=float(testing.get("min_confidence", 0.55)),
            num_ctx=client_cfg.num_ctx,
            num_predict=client_cfg.num_predict,
            api_key_env=client_cfg.api_key_env,
            extra_headers=client_cfg.extra_headers,
        )

    def to_client_config(self) -> OllamaClientConfig:
        return OllamaClientConfig(
            provider=self.provider,
            base_url=self.base_url,
            model=self.model,
            timeout=self.timeout,
            temperature=self.temperature,
            think=self.think,
            num_ctx=self.num_ctx,
            num_predict=self.num_predict,
            api_key_env=self.api_key_env,
            extra_headers=self.extra_headers,
        )


TestingAIConfig.__test__ = False  # type: ignore[attr-defined]


class TestingAgent:
    """
    Local AI bug hunter.

    1. Rank crawl endpoints for interestingness (no LLM).
    2. Run specialist subagents in parallel against compact target batches.
    3. Execute planned probes under scope + rate limits.
    4. Emit findings / weak signals into scan state.
    """

    __test__ = False

    def __init__(
        self,
        config: TestingAIConfig,
        rate_limiter: Optional[RateLimiter] = None,
        waf_bypass: Optional[WAFBypass] = None,
        scope_loader: Optional[ScopeLoader] = None,
        controller: Any = None,
    ) -> None:
        self.config = config
        self.rate_limiter = rate_limiter
        self.waf_bypass = waf_bypass
        self.scope = scope_loader
        self.controller = controller
        self.client = OllamaClient(config.to_client_config())
        self._sem = asyncio.Semaphore(max(1, config.concurrency))
        self._probe_sem = asyncio.Semaphore(max(1, config.concurrency))

    @staticmethod
    def seed_targets_from_scope(scan_state: Any, scope_loader: Any = None) -> int:
        """
        When ``--phase ai_test`` runs alone, endpoints are empty.

        Seed from live_hosts, historical URLs, and in-scope root domains so
        nested hunters still have something to plan against.
        """
        existing = list(getattr(scan_state, "endpoints", []) or [])
        if existing:
            return 0

        seeded: list[dict] = []
        seen: set[str] = set()

        def add(url: str, source: str, method: str = "GET") -> None:
            url = (url or "").strip()
            if not url:
                return
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            if scope_loader and not scope_loader.is_in_scope(url):
                return
            key = f"{method}:{url}"
            if key in seen:
                return
            seen.add(key)
            seeded.append({
                "url": url,
                "method": method,
                "source": source,
                "status": 0,
            })

        for host in getattr(scan_state, "live_hosts", []) or []:
            add(host.get("url", ""), "seed_live_host")

        for url in (getattr(scan_state, "historical_urls", []) or [])[:80]:
            add(url, "seed_historical")

        if scope_loader:
            for domain in scope_loader.get_root_domains() or []:
                clean = domain.removeprefix("*.")
                add(clean, "seed_scope")
                # Common API/app entry points for hunters when crawl was skipped
                for path in ("/", "/api", "/api/v1", "/graphql", "/login", "/admin"):
                    add(f"https://{clean}{path}", "seed_scope_path")

            for url in getattr(getattr(scope_loader, "scope", None), "in_scope_urls", []) or []:
                add(str(url), "seed_scope_url")

        if not seeded:
            return 0

        scan_state.endpoints = seeded
        return len(seeded)

    async def run(self, scan_state: Any) -> list[dict]:
        if not self.config.enabled:
            logger.info(
                "AI testing mode disabled — set ai.enabled=true and "
                "ai.mode=testing|both (or ai.testing.enabled=true)"
            )
            return []

        if not await self.client.available():
            logger.warning(
                "AI testing skipped: %s unreachable at %s "
                "(start Ollama and pull the testing model, e.g. `ollama pull qwen3:4b`)",
                self.config.provider,
                self.config.base_url,
            )
            return []

        # Ensure phase-only runs have seed targets
        seeded = self.seed_targets_from_scope(scan_state, self.scope)
        if seeded:
            logger.info("AI testing: seeded %d endpoint(s) for empty scan state", seeded)

        targets = self._select_targets(scan_state)
        if not targets:
            logger.warning(
                "AI testing skipped: no interesting endpoints. "
                "Run recon/crawl first, or ensure scope.yaml has in-scope domains. "
                "Example: python main.py scan  (full pipeline) "
                "or python main.py scan --phase crawl && python main.py scan --phase ai_test"
            )
            return []

        logger.info(
            "AI bug hunter: %d targets via %s/%s (think=%s) subagents=%s",
            len(targets),
            self.config.provider,
            self.config.model,
            self.config.think,
            ",".join(self.config.subagents),
        )

        context = self._compact_context(scan_state)
        await self._control_gate("ai_test:plan")
        plans = await self._run_subagents(targets, context)
        probes = self._merge_probes(plans)
        if not probes:
            logger.info("AI bug hunter: subagents proposed no probes")
            return []

        logger.info("AI bug hunter executing %d probe(s)", len(probes))
        await self._control_gate("ai_test:execute")
        findings = await self._execute_probes(probes)

        setattr(scan_state, "ai_test_probes", len(probes))
        setattr(scan_state, "ai_test_findings", len(findings))
        logger.info("AI bug hunter produced %d finding(s)", len(findings))
        return findings

    # ── Target selection ──────────────────────────────────────────────────

    def _select_targets(self, scan_state: Any) -> list[dict[str, Any]]:
        endpoints = list(getattr(scan_state, "endpoints", []) or [])
        params_map = getattr(scan_state, "params", {}) or {}
        scored: list[tuple[float, dict]] = []

        for ep in endpoints:
            url = ep.get("url", "")
            if not url or self._is_static(url):
                continue
            if self.scope and not self.scope.is_in_scope(url):
                continue
            method = (ep.get("method") or "GET").upper()
            parsed = urlparse(url)
            query_keys = list(parse_qs(parsed.query).keys())
            mined = list(params_map.get(url, []) or [])[:12]
            score = self._interest_score(url, method, query_keys + mined, ep)
            # Keep scope-seeded targets even without params (phase-only ai_test)
            if score <= 0 and str(ep.get("source", "")).startswith("seed_"):
                score = 0.5
            if score <= 0:
                continue
            scored.append((score, {
                "url": url,
                "method": method,
                "source": ep.get("source", ""),
                "params": sorted(set(query_keys + mined))[:15],
                "status": ep.get("status", 0),
            }))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in scored[: self.config.max_endpoints]]

    def _interest_score(
        self,
        url: str,
        method: str,
        params: list[str],
        ep: dict,
    ) -> float:
        lower = url.lower()
        score = 0.0
        if params:
            score += 2.0 + min(len(params), 6) * 0.25
        if "?" in url:
            score += 1.0
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 1.5
        hot_paths = (
            "/api/", "/admin", "/user", "/account", "/auth", "/login",
            "/graphql", "/internal", "/debug", "/manage", "/dashboard",
            "/settings", "/order", "/file", "/download", "/redirect",
            "/callback", "/webhook", "/proxy", "/fetch",
        )
        if any(p in lower for p in hot_paths):
            score += 2.0
        hot_params = {
            "id", "user_id", "account_id", "url", "redirect", "next",
            "callback", "q", "search", "query", "token", "file", "path",
            "dest", "return", "redirect_uri",
        }
        score += sum(0.4 for p in params if p.lower() in hot_params)
        if ep.get("source", "").startswith("auto_navigator"):
            score += 0.3
        return score

    @staticmethod
    def _is_static(url: str) -> bool:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in STATIC_EXT)

    def _compact_context(self, scan_state: Any) -> dict[str, Any]:
        tech = getattr(scan_state, "tech_stack", {}) or {}
        tech_summary: dict[str, Any] = {}
        for url, profile in list(tech.items())[:15]:
            if hasattr(profile, "frameworks"):
                tech_summary[url] = {
                    "frameworks": getattr(profile, "frameworks", [])[:8],
                    "is_spa": bool(getattr(profile, "is_spa", False)),
                    "has_graphql": bool(getattr(profile, "has_graphql", False)),
                }
            elif isinstance(profile, dict):
                tech_summary[url] = profile

        return {
            "live_hosts": len(getattr(scan_state, "live_hosts", []) or []),
            "endpoint_count": len(getattr(scan_state, "endpoints", []) or []),
            "tech": tech_summary,
            "graphql": (getattr(scan_state, "graphql_schemas", []) or [])[:5],
        }

    # ── Subagents ─────────────────────────────────────────────────────────

    async def _run_subagents(
        self,
        targets: list[dict[str, Any]],
        context: dict[str, Any],
    ) -> list[ProbePlan]:
        agents: list[HunterSubagent] = []
        for name in self.config.subagents:
            cls = SUBAGENT_REGISTRY.get(name)
            if not cls:
                logger.warning("Unknown testing subagent: %s", name)
                continue
            agents.append(cls(self.client, max_probes=self.config.max_probes_per_agent))

        if not agents:
            return []

        # Split targets so each agent gets a focused slice (faster for 4B)
        async def run_one(agent: HunterSubagent) -> ProbePlan:
            async with self._sem:
                focused = self._targets_for_agent(agent.name, targets)
                return await agent.plan(focused, context)

        return list(await asyncio.gather(*[run_one(a) for a in agents]))

    def _targets_for_agent(self, agent: str, targets: list[dict]) -> list[dict]:
        """Cheap heuristic pre-filter so the 4B model sees relevant rows only."""
        if agent == "xss":
            return [t for t in targets if t.get("params") or "?" in t["url"]][:20] or targets[:12]
        if agent == "idor":
            id_like = re.compile(r"(^|_)(id|uuid|user|account|order|file)(_|$)", re.I)
            return [
                t for t in targets
                if any(id_like.search(p) for p in t.get("params", []))
                or re.search(r"/\d+(/|$)", t["url"])
            ][:20] or targets[:12]
        if agent == "ssti":
            keys = {
                "template", "tpl", "view", "page", "name", "message", "email",
                "subject", "body", "preview", "render", "format", "layout", "theme", "q",
            }
            return [
                t for t in targets
                if any(p.lower() in keys for p in t.get("params", []))
                or any(x in t["url"].lower() for x in ("/render", "/preview", "/template", "/email"))
            ][:15] or targets[:10]
        if agent == "ssrf":
            keys = {"url", "uri", "path", "dest", "destination", "webhook", "callback",
                    "link", "fetch", "proxy", "image", "src", "host", "redirect"}
            return [
                t for t in targets
                if any(p.lower() in keys for p in t.get("params", []))
            ][:15] or targets[:8]
        if agent == "auth":
            return [
                t for t in targets
                if any(x in t["url"].lower() for x in (
                    "/admin", "/api/", "/dashboard", "/settings", "/user",
                    "/account", "/internal", "/debug", "/manage", "/graphql",
                ))
            ][:20] or targets[:12]
        if agent == "open_redirect":
            keys = {"next", "return", "returnurl", "redirect", "redirect_uri",
                    "url", "continue", "goto", "dest", "destination", "callback", "redir"}
            return [
                t for t in targets
                if any(p.lower() in keys for p in t.get("params", []))
            ][:15] or targets[:8]
        if agent in ("request_smuggling", "smuggling"):
            return [
                t for t in targets
                if any(x in t["url"].lower() for x in ("/api/", "/gateway", "/v1/", "/v2/", "/proxy"))
            ][:15] or targets[:10]
        if agent == "cors":
            return [
                t for t in targets
                if any(x in t["url"].lower() for x in ("/api/", "/graphql", "/auth", "/user", "/account"))
            ][:15] or targets[:10]
        if agent == "jwt":
            return [
                t for t in targets
                if any(x in t["url"].lower() for x in (
                    "/api/", "/auth", "/login", "/token", "/oauth", "/session", "/jwt",
                ))
            ][:15] or targets[:10]
        return targets[:20]

    def _merge_probes(self, plans: list[ProbePlan]) -> list[PlannedProbe]:
        seen: set[str] = set()
        merged: list[PlannedProbe] = []
        for plan in plans:
            for probe in plan.probes:
                if self.scope and not self.scope.is_in_scope(probe.url):
                    continue
                key = f"{probe.method}:{probe.url}:{probe.parameter}:{probe.payload}:{probe.check}"
                if key in seen:
                    continue
                seen.add(key)
                merged.append(probe)
                if len(merged) >= self.config.max_total_probes:
                    return merged
        return merged

    # ── Probe execution ───────────────────────────────────────────────────

    async def _execute_probes(self, probes: list[PlannedProbe]) -> list[dict]:
        tasks = [self._safe_execute(p) for p in probes]
        results = await asyncio.gather(*tasks)
        return [f for f in results if f]

    async def _safe_execute(self, probe: PlannedProbe) -> Optional[dict]:
        async with self._probe_sem:
            try:
                return await self._execute_one(probe)
            except Exception as exc:
                logger.debug("Probe failed (%s): %s", probe.vuln_class, exc)
                return None

    async def _execute_one(self, probe: PlannedProbe) -> Optional[dict]:
        if self.scope and not self.scope.is_in_scope(probe.url):
            return None

        request_url, headers, data, json_body, params = self._build_request(probe)
        host = urlparse(request_url).hostname or ""
        if self.rate_limiter:
            await self.rate_limiter.acquire(host)

        merged_headers: dict[str, str] = {}
        if self.waf_bypass:
            merged_headers.update(self.waf_bypass.get_headers(host))
        merged_headers.update(headers)

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=False,
                timeout=12.0,
            ) as client:
                resp = await client.request(
                    method=probe.method,
                    url=request_url,
                    headers=merged_headers,
                    params=params,
                    data=data,
                    json=json_body,
                )
                if self.rate_limiter:
                    self.rate_limiter.report_response(host, resp.status_code)
        except Exception:
            return None

        return self._evaluate(probe, resp, request_url)

    def _build_request(
        self,
        probe: PlannedProbe,
    ) -> tuple[str, dict, Any, Any, Optional[dict]]:
        headers: dict[str, str] = {}
        data = None
        json_body = None
        params = None
        url = probe.url
        payload = probe.payload or "he_canary"

        if probe.location == "header" and probe.parameter:
            headers[probe.parameter] = payload
            return url, headers, data, json_body, params

        if probe.location == "body":
            if probe.method == "GET":
                probe_method_url = self._inject_query(url, probe.parameter, payload)
                return probe_method_url, headers, data, json_body, params
            if probe.parameter:
                data = {probe.parameter: payload}
            else:
                data = payload
            return url, headers, data, json_body, params

        if probe.location == "path" and probe.parameter:
            # Replace trailing id segment or append
            if re.search(r"/\d+(/|$)", url):
                url = re.sub(r"/\d+(/|$)", f"/{payload}\\1", url, count=1)
            elif probe.parameter:
                url = url.rstrip("/") + f"/{payload}"
            return url, headers, data, json_body, params

        # default: query
        url = self._inject_query(url, probe.parameter or "q", payload)
        return url, headers, data, json_body, params

    @staticmethod
    def _inject_query(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if param:
            query[param] = [value]
        else:
            query["he_probe"] = [value]
        new_query = urlencode({k: v[0] if len(v) == 1 else v for k, v in query.items()}, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _evaluate(
        self,
        probe: PlannedProbe,
        resp: httpx.Response,
        request_url: str,
    ) -> Optional[dict]:
        body = ""
        try:
            body = resp.text[:8000]
        except Exception:
            body = ""

        check = probe.check
        hit = False
        evidence = ""
        confidence = self.config.min_confidence
        severity = _severity(probe.severity_hint)

        if check == "reflect" or probe.vuln_class == "xss":
            canary = probe.payload
            if canary and canary in body:
                hit = True
                confidence = 0.72 if "<" in canary or "script" in canary.lower() else 0.62
                evidence = f"Payload reflected in response body (status {resp.status_code})."
            elif canary and canary in (resp.headers.get("location") or ""):
                hit = True
                confidence = 0.6
                evidence = "Payload reflected in Location header."

        elif check == "redirect" or probe.vuln_class == "open_redirect":
            location = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                if "example.com" in location.lower() or location.startswith("//"):
                    hit = True
                    confidence = 0.8
                    severity = Severity.MEDIUM
                    evidence = f"Redirected to {location} (status {resp.status_code})."

        elif check == "auth_bypass" or probe.vuln_class == "auth":
            if resp.status_code == 200 and _looks_sensitive(body, request_url):
                hit = True
                confidence = 0.65
                severity = Severity.HIGH
                evidence = (
                    f"Unauthenticated {probe.method} returned 200 with sensitive-looking body "
                    f"({len(body)} bytes)."
                )

        elif check in ("status_diff", "error_leak") or probe.vuln_class in (
            "idor", "ssrf", "ssti", "request_smuggling", "smuggling", "cors", "jwt",
        ):
            if check == "error_leak" or probe.vuln_class == "ssrf":
                leak_markers = (
                    "connection refused", "failed to connect", "timeout",
                    "169.254.169.254", "metadata", "errno", "curl error",
                    "socket hang up", "name or service not known",
                )
                lower = body.lower()
                matched = [m for m in leak_markers if m in lower]
                if matched and resp.status_code < 500:
                    hit = True
                    confidence = 0.68
                    severity = Severity.HIGH if probe.vuln_class == "ssrf" else Severity.MEDIUM
                    evidence = f"SSRF/error leak indicators: {', '.join(matched[:3])}."
            if probe.vuln_class == "idor" and resp.status_code == 200 and len(body) > 40:
                # Soft signal — mark as weak unless JSON object data present
                if body.strip().startswith(("{", "[")) or "id" in body.lower():
                    hit = True
                    confidence = 0.58
                    severity = Severity.MEDIUM
                    evidence = (
                        f"IDOR candidate: object-like 200 response after ID swap "
                        f"({probe.parameter}={probe.payload})."
                    )
            if probe.vuln_class == "ssti":
                # Math canary evaluation e.g. {{7*7}} → 49
                if "49" in body and any(
                    m in (probe.payload or "") for m in ("7*7", "7 * 7")
                ):
                    hit = True
                    confidence = 0.78
                    severity = Severity.HIGH
                    evidence = "SSTI canary evaluated (49) in response body."
                elif any(
                    m in body.lower()
                    for m in ("jinja", "freemarker", "twig", "velocity", "templateerror", "templating")
                ):
                    hit = True
                    confidence = 0.62
                    severity = Severity.MEDIUM
                    evidence = "Template engine error/leak indicators in response."
            if probe.vuln_class in ("request_smuggling", "smuggling"):
                # Soft differential: unusual 4xx/timeout-style bodies after TE/CL canaries
                if resp.status_code in (400, 408, 411, 413, 502, 503) or "bad request" in body.lower():
                    hit = True
                    confidence = 0.55
                    severity = Severity.MEDIUM
                    evidence = (
                        f"Smuggling differential: status {resp.status_code} after "
                        f"TE/CL header canary."
                    )
            if probe.vuln_class == "cors":
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")
                if acao and ("evil.example" in acao.lower() or acao == "*"):
                    hit = True
                    confidence = 0.75 if acac.lower() == "true" else 0.65
                    severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    evidence = f"CORS reflection: ACAO={acao!r} ACAC={acac!r}."
            if probe.vuln_class == "jwt" and check == "auth_bypass":
                if resp.status_code == 200 and _looks_sensitive(body, request_url):
                    hit = True
                    confidence = 0.6
                    severity = Severity.HIGH
                    evidence = "JWT/auth probe returned sensitive-looking 200 response."

        if not hit:
            return None

        title = f"AI/{probe.vuln_class or 'probe'}: {probe.parameter or urlparse(request_url).path}"
        return {
            "title": title[:160],
            "description": (
                probe.rationale
                or f"Local AI bug hunter ({probe.vuln_class}) flagged this probe as interesting."
            ),
            "severity": severity.value if isinstance(severity, Severity) else str(severity),
            "confidence": round(confidence, 3),
            "detector": f"ai_test_{probe.vuln_class or 'generic'}",
            "url": request_url,
            "method": probe.method,
            "parameter": probe.parameter,
            "evidence": evidence[:2000],
            "request": f"{probe.method} {request_url}",
            "response": f"status={resp.status_code} len={len(body)}",
            "reproduction": f"{probe.method} {request_url}",
            "impact": "Potential security weakness identified by local AI-guided testing.",
            "remediation": "Validate access controls / input handling for this parameter and path.",
            "references": [],
            "tags": sorted({"ai-testing", "ai-bug-hunter", probe.vuln_class or "probe"}),
            "metadata": {
                "ai_testing": True,
                "model": self.config.model,
                "provider": self.config.provider,
                "check": probe.check,
                "payload": probe.payload[:200],
                "rationale": probe.rationale,
            },
        }


def _severity(hint: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get((hint or "medium").lower(), Severity.MEDIUM)


def _looks_sensitive(body: str, url: str) -> bool:
    lower = body.lower()
    url_l = url.lower()
    if any(x in url_l for x in ("/admin", "/internal", "/debug", "/manage", "/actuator")):
        if body.strip() and "login" not in lower[:400]:
            return True
    markers = (
        '"role"', '"email"', '"admin"', "password", "api_key", "access_token",
        "secret", '"users"', "internal",
    )
    return sum(1 for m in markers if m in lower) >= 2 and len(body) > 80
