"""Vulnerability hunt agent — nests specialist subagents (IDOR, SSTI, smuggling, …)."""

from __future__ import annotations

from typing import Any

from ai.agents.base import AgentContext, PhaseAgent


class VulnHuntAgent(PhaseAgent):
    """
    Vulnerability hunting coordinator.

    Spawns nested specialist subagents under AI testing mode:
      xss · idor · ssti · ssrf · auth · open_redirect · request_smuggling · …

    Does not replace classic detectors; runs as the ``ai_test`` phase.
    """

    name = "vuln_hunt"
    description = "Nested AI vuln hunters (IDOR, SSTI, smuggling, XSS, …)"

    def __init__(self, ctx: AgentContext) -> None:
        super().__init__(ctx)

    async def run(self, state: Any) -> None:
        from ai.testing_agent import TestingAIConfig, TestingAgent

        config = TestingAIConfig.from_settings(self.ctx.settings)
        if not config.enabled:
            self.info("AI testing disabled (set ai.mode=testing|both and ai.enabled=true)")
            return

        # Seed endpoints from scope / live hosts when phase is run alone
        seeded = TestingAgent.seed_targets_from_scope(state, self.ctx.scope_loader)
        if seeded:
            self.info("seeded %d endpoint(s) from scope/live hosts for ai_test", seeded)

        agent = TestingAgent(
            config=config,
            rate_limiter=self.ctx.rate_limiter,
            waf_bypass=self.ctx.waf_bypass,
            scope_loader=self.ctx.scope_loader,
            controller=self.ctx.controller,
        )
        self.info(
            "dispatching nested hunters: %s",
            ", ".join(config.subagents),
        )
        await self.ctx.check_control("vuln_hunt:start")
        findings = await agent.run(state)

        threshold = (
            self.ctx.settings.get("detection", {}) or {}
        ).get("confidence_threshold", 0.6)
        for finding in findings:
            if finding.get("confidence", 0) >= threshold:
                state.findings.append(finding)
            else:
                state.weak_signals.append(finding)

        self.info(
            "nested hunters done — probes=%d findings=%d",
            getattr(state, "ai_test_probes", 0),
            getattr(state, "ai_test_findings", 0),
        )
