"""JWT / token weakness hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class JWTHunter(HunterSubagent):
    name = "jwt"
    max_probes = 6

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty JWT hunter. "
            "Target endpoints with Authorization, access_token, id_token, jwt, "
            "or cookie session tokens. "
            "Suggest SAFE probes: alg=none canary tokens, stripped signature markers, "
            "or missing Authorization with check=auth_bypass / status_diff. "
            "Do not brute-force secrets. Return compact JSON only."
        )
