"""Open redirect hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class RedirectHunter(HunterSubagent):
    name = "open_redirect"
    max_probes = 6

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty open-redirect hunter. "
            "Target redirect params: next, return, returnUrl, redirect, redirect_uri, "
            "url, continue, goto, dest, destination, callback, redir. "
            "Payload should be https://example.com or //example.com. "
            "Use check=redirect. Return compact JSON only."
        )
