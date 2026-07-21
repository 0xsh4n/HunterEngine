"""Local AI reasoning support for HunterEngine."""

from ai.local_reasoner import LocalAIConfig, LocalAIReasoner
from ai.testing_agent import TestingAIConfig, TestingAgent
from ai.ollama_client import OllamaClient, OllamaClientConfig
from ai.agentic import AgenticDecision, AgenticPlanner
from ai.agents import (
    AgentContext,
    PhaseAgent,
    ReconAgent,
    ActiveReconAgent,
    EnumerationAgent,
    VulnHuntAgent,
)

__all__ = [
    "LocalAIConfig",
    "LocalAIReasoner",
    "TestingAIConfig",
    "TestingAgent",
    "OllamaClient",
    "OllamaClientConfig",
    "AgenticDecision",
    "AgenticPlanner",
    "AgentContext",
    "PhaseAgent",
    "ReconAgent",
    "ActiveReconAgent",
    "EnumerationAgent",
    "VulnHuntAgent",
]
