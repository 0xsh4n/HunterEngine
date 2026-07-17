"""Auth / session hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class AuthHunter(HunterSubagent):
    name = "auth"
    max_probes = 8

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty authn/authz hunter. "
            "Prioritize /admin, /api/, /dashboard, /settings, /user, /account, /internal, "
            "/debug, /actuator, /graphql, /manage paths. "
            "Suggest unauthenticated GETs with check=auth_bypass looking for 200 vs 401/403 "
            "or sensitive JSON leakage. "
            "No credential stuffing or password spraying. Return compact JSON only."
        )
