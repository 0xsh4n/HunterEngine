"""Base types for HunterEngine phase agents."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger("hunterengine.ai.agents")


@dataclass
class AgentContext:
    """Shared runtime context passed to every phase agent."""

    settings: dict[str, Any] = field(default_factory=dict)
    scope_loader: Any = None
    rate_limiter: Any = None
    waf_bypass: Any = None
    browser: Any = None
    session_mgr: Any = None
    auto_crawl: bool = False
    headed: bool = False
    skip_enum: bool = False
    # Effective proxy (may differ from settings listen_port)
    proxy_enabled: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    extras: dict[str, Any] = field(default_factory=dict)

    def crawl_config(self) -> dict[str, Any]:
        return self.settings.get("crawl", {}) or {}

    def recon_config(self) -> dict[str, Any]:
        return self.settings.get("recon", {}) or {}

    def ai_config(self) -> dict[str, Any]:
        return self.settings.get("ai", {}) or {}


class PhaseAgent(ABC):
    """
    Top-level pipeline agent.

    Each agent owns one phase of the hunt and may spawn nested specialists.
    """

    name: str = "base"
    description: str = ""

    def __init__(self, ctx: AgentContext) -> None:
        self.ctx = ctx
        self.log = logging.getLogger(f"hunterengine.ai.agents.{self.name}")

    @abstractmethod
    async def run(self, state: Any) -> None:
        """Execute this agent's phase, mutating ``state`` in place."""
        ...

    def info(self, msg: str, *args: Any) -> None:
        self.log.info("[%s] " + msg, self.name, *args)

    def warn(self, msg: str, *args: Any) -> None:
        self.log.warning("[%s] " + msg, self.name, *args)
