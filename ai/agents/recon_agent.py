"""Passive recon agent — subdomain enumeration, DNS, historical URLs."""

from __future__ import annotations

from typing import Any

from ai.agents.base import AgentContext, PhaseAgent


class ReconAgent(PhaseAgent):
    """
    Passive reconnaissance agent.

    Discovers attack surface without sending aggressive probes:
      subdomain enum → DNS resolve → historical URL collection
    """

    name = "recon"
    description = "Passive recon: subdomains, DNS, historical URLs"

    def __init__(self, ctx: AgentContext) -> None:
        super().__init__(ctx)

    async def run(self, state: Any) -> None:
        from recon.subdomain_enum import SubdomainEnumerator
        from recon.dns_resolver import DNSResolver
        from recon.historical_urls import HistoricalURLCollector

        scope = self.ctx.scope_loader
        domains = scope.get_root_domains() if scope else []
        self.info("targets: %s", domains)

        if self.ctx.skip_enum:
            self.info("skipping subdomain enumeration (using provided domains only)")
            state.subdomains = domains[:]
        else:
            enumerator = SubdomainEnumerator()
            for domain in domains:
                subs = await enumerator.enumerate(domain)
                state.subdomains.extend(subs)
            state.subdomains = list(set(state.subdomains))
            self.info("found %d unique subdomains", len(state.subdomains))

        # Scope filter
        old = state.subdomains[:]
        original_count = len(old)
        if scope:
            state.subdomains = scope.filter_in_scope(state.subdomains)
        if original_count > 0 and len(state.subdomains) == 0:
            self.warn(
                "all subdomains filtered out — check scope.yaml wildcards (e.g. *.domain.com)"
            )
            if old:
                self.warn("first rejected: %r", old[0])

        # DNS
        resolver = DNSResolver()
        resolved = await resolver.resolve_bulk(state.subdomains)
        state.subdomains = [r["hostname"] for r in resolved if r.get("resolved")]
        self.info("DNS-resolved hosts: %d", len(state.subdomains))

        # Historical URLs
        collector = HistoricalURLCollector()
        for domain in domains:
            urls = await collector.collect(domain)
            state.historical_urls.extend(urls)
        if scope:
            state.historical_urls = scope.filter_in_scope(list(set(state.historical_urls)))
        else:
            state.historical_urls = list(set(state.historical_urls))
        self.info("historical URLs: %d", len(state.historical_urls))
