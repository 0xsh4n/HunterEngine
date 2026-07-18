"""Enumeration agent — crawl, JS analysis, params, GraphQL."""

from __future__ import annotations

from typing import Any

from ai.agents.base import AgentContext, PhaseAgent


class EnumerationAgent(PhaseAgent):
    """
    Endpoint enumeration agent.

    Maps the application surface after active recon:
      auto-navigator / katana / gospider → SPA JS crawl → GraphQL → JS analysis → params
    """

    name = "enumeration"
    description = "Endpoint enumeration: crawl, JS, params, GraphQL"

    def __init__(self, ctx: AgentContext) -> None:
        super().__init__(ctx)

    async def run(self, state: Any) -> None:
        from crawl.active_crawler import ActiveCrawler
        from crawl.js_crawler import JSCrawler
        from crawl.js_analyzer import JSAnalyzer
        from crawl.param_miner import ParamMiner
        from crawl.graphql_mapper import GraphQLMapper

        crawl_conf = self.ctx.crawl_config()
        scope = self.ctx.scope_loader
        live_urls = [h.get("url", "") for h in (state.live_hosts or []) if h.get("url")]
        historical_seeds = [
            u for u in (state.historical_urls or [])[:150]
            if u and (not scope or scope.is_in_scope(u))
        ]
        urls_to_crawl = list(dict.fromkeys(live_urls + historical_seeds))

        self._enrich_live_hosts_tech(state)

        # Auto-navigator
        if self.ctx.auto_crawl:
            await self._run_auto_navigator(state, urls_to_crawl, live_urls, crawl_conf)

        # External crawlers
        crawler = ActiveCrawler(
            rate_limiter=self.ctx.rate_limiter,
            waf_bypass=self.ctx.waf_bypass,
            max_depth=crawl_conf.get("max_depth", 5),
        )
        crawl_results = await crawler.crawl(urls_to_crawl[:80] or live_urls)
        state.endpoints.extend(crawl_results.get("endpoints", []))
        state.js_files.extend(crawl_results.get("js_files", []))

        # SPA / JS rendering
        if crawl_conf.get("js_rendering", True) and self.ctx.browser:
            js_crawler = JSCrawler(
                browser=self.ctx.browser,
                scope_loader=scope,
                tech_stack=state.tech_stack,
            )
            spa_endpoints = await js_crawler.crawl_spa_targets(state.live_hosts)
            state.endpoints.extend(spa_endpoints)

        # GraphQL
        try:
            mapper = GraphQLMapper()
            graphql_maps = await mapper.map_all(live_urls[:30])
            state.graphql_schemas = graphql_maps
            for gq in graphql_maps:
                state.endpoints.append({
                    "url": gq.get("url", ""),
                    "method": "POST",
                    "source": "graphql_mapper",
                    "introspection": gq.get("introspection_enabled", False),
                })
            if graphql_maps:
                self.info("GraphQL endpoint(s): %d", len(graphql_maps))
        except Exception as exc:
            self.warn("GraphQL mapping failed: %s", exc)

        # JS analysis
        analyzer = JSAnalyzer()
        for js_url in list(dict.fromkeys(state.js_files))[:200]:
            findings = await analyzer.analyze(js_url)
            state.weak_signals.extend(findings.get("secrets", []))
            state.endpoints.extend(findings.get("endpoints", []))

        # Parameter mining
        miner = ParamMiner(rate_limiter=self.ctx.rate_limiter)
        target_urls = [ep.get("url", "") for ep in state.endpoints[:100]]
        params = await miner.discover(target_urls)
        state.params.update(params)

        self._dedupe_endpoints(state, scope)
        self.info(
            "enumerated %d endpoints, %d JS files, %d param maps",
            len(state.endpoints),
            len(state.js_files),
            len(state.params),
        )

    async def _run_auto_navigator(
        self,
        state: Any,
        urls_to_crawl: list[str],
        live_urls: list[str],
        crawl_conf: dict,
    ) -> None:
        from crawl.auto_navigator import AutoNavigator, NavigatorConfig

        proxy_url = ""
        if self.ctx.proxy_enabled:
            proxy_url = f"http://{self.ctx.proxy_host}:{self.ctx.proxy_port}"

        browser_conf = self.ctx.settings.get("browser", {}) or {}
        nav_config = NavigatorConfig(
            headless=not self.ctx.headed,
            max_pages=crawl_conf.get("max_pages", 500),
            max_depth=crawl_conf.get("max_depth", 10),
            page_timeout=browser_conf.get("page_timeout", 30_000),
            form_submit=crawl_conf.get("form_fill", False),
            screenshot_dir=browser_conf.get("screenshot_dir", "data/screenshots"),
            proxy_url=proxy_url,
            chromium_args=browser_conf.get("chromium_args", [
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
            ]),
        )
        navigator = AutoNavigator(config=nav_config, scope_loader=self.ctx.scope_loader)
        nav_results = await navigator.crawl(urls_to_crawl[:50] or live_urls)
        state.endpoints.extend(nav_results.get("endpoints", []))
        state.js_files.extend(nav_results.get("js_files", []))
        for req in nav_results.get("network_requests", []) or []:
            req_url = req.get("url", "")
            if not req_url:
                continue
            if self.ctx.scope_loader and not self.ctx.scope_loader.is_in_scope(req_url):
                continue
            if req.get("resource_type") in ("xhr", "fetch", "websocket", "document"):
                state.endpoints.append({
                    "url": req_url,
                    "method": req.get("method", "GET"),
                    "source": "auto_navigator_network",
                    "status": req.get("status", 0),
                })
        self.info(
            "auto-navigator: %d endpoints, %d JS, %d network",
            len(nav_results.get("endpoints", [])),
            len(nav_results.get("js_files", [])),
            len(nav_results.get("network_requests", [])),
        )

    @staticmethod
    def _enrich_live_hosts_tech(state: Any) -> None:
        tech = getattr(state, "tech_stack", {}) or {}
        for host in getattr(state, "live_hosts", []) or []:
            url = host.get("url", "")
            if not url or url not in tech:
                continue
            profile = tech[url]
            if hasattr(profile, "technologies"):
                host.setdefault("tech", list(getattr(profile, "technologies", []) or [])[:20])
                host["is_spa"] = bool(getattr(profile, "is_spa", False))
            elif isinstance(profile, dict):
                host.setdefault("tech", profile.get("technologies", [])[:20])
                host["is_spa"] = bool(profile.get("is_spa", False))

    @staticmethod
    def _dedupe_endpoints(state: Any, scope: Any) -> None:
        seen: set[str] = set()
        unique: list[dict] = []
        for ep in state.endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            if scope and not scope.is_in_scope(url):
                continue
            key = f"{(ep.get('method') or 'GET').upper()}:{url}"
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        state.endpoints = unique
        state.js_files = list(dict.fromkeys(state.js_files))
