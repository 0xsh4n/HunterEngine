"""SSTI (server-side template injection) hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class SSTIHunter(HunterSubagent):
    name = "ssti"
    max_probes = 8

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty SSTI hunter. "
            "Look for template-like parameters: template, tpl, view, page, name, "
            "message, email, subject, body, preview, render, format, layout, theme. "
            "Suggest safe math canaries only — e.g. {{7*7}}, ${7*7}, <%= 7*7 %>, "
            "#{7*7} — with check=reflect or check=error_leak. "
            "Never propose RCE payloads, file reads, or destructive expressions. "
            "Return compact JSON only."
        )
