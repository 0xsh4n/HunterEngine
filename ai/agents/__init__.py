"""
Hierarchical phase agents for HunterEngine v3.

Pipeline agents:
  ReconAgent → ActiveReconAgent → EnumerationAgent → VulnHuntAgent
                                                          │
                    nested specialists: xss, idor, ssti, ssrf, …
"""

from __future__ import annotations

from ai.agents.base import AgentContext, PhaseAgent
from ai.agents.recon_agent import ReconAgent
from ai.agents.active_recon_agent import ActiveReconAgent
from ai.agents.enum_agent import EnumerationAgent
from ai.agents.vuln_agent import VulnHuntAgent

__all__ = [
    "AgentContext",
    "PhaseAgent",
    "ReconAgent",
    "ActiveReconAgent",
    "EnumerationAgent",
    "VulnHuntAgent",
]
