"""SSRF hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class SSRFHunter(HunterSubagent):
    name = "ssrf"
    max_probes = 6

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty SSRF hunter. "
            "Target URL-accepting params: url, uri, path, dest, destination, redirect, "
            "webhook, callback, link, fetch, proxy, image, src, host. "
            "Use safe local canaries only: http://127.0.0.1/, http://localhost/, "
            "http://169.254.169.254/ — look for error_leak or status_diff. "
            "No cloud credential exfil instructions. Return compact JSON only."
        )
