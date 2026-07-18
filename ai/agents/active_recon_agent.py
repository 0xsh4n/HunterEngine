"""Active recon agent — live probing and technology fingerprinting."""

from __future__ import annotations

from typing import Any

from ai.agents.base import AgentContext, PhaseAgent


class ActiveReconAgent(PhaseAgent):
    """
    Active reconnaissance agent.

    Probes discovered hosts and fingerprints stacks:
      live HTTP probe (ProjectDiscovery httpx or pip fallback) → tech FP
    """

    name = "active_recon"
    description = "Active recon: live host probing + tech fingerprinting"

    def __init__(self, ctx: AgentContext) -> None:
        super().__init__(ctx)

    async def run(self, state: Any) -> None:
        from recon.live_prober import LiveProber
        from recon.tech_fingerprint import TechFingerprinter

        hosts = list(getattr(state, "subdomains", []) or [])
        if not hosts and self.ctx.scope_loader:
            hosts = self.ctx.scope_loader.get_root_domains()

        if not hosts:
            self.warn("no hosts to probe")
            return

        prober = LiveProber(
            rate_limiter=self.ctx.rate_limiter,
            waf_bypass=self.ctx.waf_bypass,
        )
        state.live_hosts = await prober.probe_hosts(hosts)
        self.info("live hosts: %d", len(state.live_hosts))

        fingerprinter = TechFingerprinter()
        for host_info in state.live_hosts[:50]:
            url = host_info.get("url", "")
            if not url:
                continue
            tech = await fingerprinter.detect(url)
            state.tech_stack[url] = tech
        self.info("tech fingerprints: %d", len(state.tech_stack))
