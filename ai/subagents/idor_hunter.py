"""IDOR / access-control hunter subagent."""

from __future__ import annotations

from ai.subagents.base import HunterSubagent


class IDORHunter(HunterSubagent):
    name = "idor"
    max_probes = 8

    def system_prompt(self) -> str:
        return (
            "You are a senior bug bounty IDOR / broken-access-control hunter. "
            "Target object references: id, user_id, account_id, order_id, file_id, uuid, "
            "document, invoice, profile. "
            "Suggest safe ID swaps (adjacent ints, common test IDs like 1/2/0) with "
            "check=status_diff or check=auth_bypass. "
            "Do not attempt account takeover payloads. Return compact JSON only."
        )
