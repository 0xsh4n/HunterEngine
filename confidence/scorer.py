"""
Multi-signal confidence scoring.

Adjusts finding confidence based on multiple independent signals:
  - Verification method (browser-confirmed, OOB callback, etc.)
  - Response differential strength
  - Consistency across tests
  - Historical pattern match
  - Tech stack relevance
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("hunterengine.confidence.scorer")


class ConfidenceScorer:
    """Score and adjust finding confidence using multiple signals."""

    # Signal weights
    WEIGHTS = {
        "verified": 0.3,        # Browser/OOB verified
        "response_diff": 0.2,   # Clear response differential
        "consistency": 0.15,    # Consistent across multiple tests
        "tech_match": 0.1,      # Matches detected tech stack
        "historical": 0.1,      # Seen in previous scans
        "tool_agreement": 0.15, # Multiple tools agree
    }

    def score(self, finding: dict, context: dict | None = None) -> float:
        """
        Calculate adjusted confidence score for a finding.

        Args:
            finding: The finding dict with base confidence
            context: Optional context (tech_stack, historical patterns, etc.)

        Returns:
            Adjusted confidence score (0.0 – 1.0)
        """
        context = context or {}
        base = finding.get("confidence", 0.5)
        tags = set(finding.get("tags", []))

        adjustments = 0.0

        # 1. Verification bonus
        if "verified" in tags:
            adjustments += self.WEIGHTS["verified"]
        elif "needs-verification" in tags:
            adjustments -= 0.1

        # 2. Response differential
        evidence = finding.get("evidence", "")
        if "confirmed" in evidence.lower() or "triggered" in evidence.lower():
            adjustments += self.WEIGHTS["response_diff"]

        # 3. Tool agreement
        if "tool_agreement" in finding.get("metadata", {}):
            agreement_count = finding["metadata"]["tool_agreement"]
            if agreement_count >= 2:
                adjustments += self.WEIGHTS["tool_agreement"]

        # 4. Tech stack relevance
        tech_stack = context.get("tech_stack", {})
        detector = finding.get("detector", "")
        if self._is_tech_relevant(detector, tech_stack, tags):
            adjustments += self.WEIGHTS["tech_match"]

        # 5. Historical pattern match
        if context.get("historical_match"):
            adjustments += self.WEIGHTS["historical"]

        # 6. Severity-based floor
        severity = finding.get("severity", "")
        if severity == "critical" and base < 0.5:
            base = max(base, 0.5)  # Don't let critical findings be too low

        adjusted = min(max(base + adjustments, 0.0), 1.0)
        return round(adjusted, 3)

    def _is_tech_relevant(self, detector: str, tech_stack: dict, tags: set) -> bool:
        """Check if the finding is relevant to the detected tech stack."""
        relevance_map = {
            "prototype_pollution": ["node", "express", "next.js", "react"],
            "graphql": ["graphql", "apollo"],
            "jwt": ["express", "django", "flask", "fastapi"],
            "xss": [],  # Relevant to everything
            "crypto": ["web3", "ethers", "solana"],
        }

        if detector not in relevance_map:
            return False

        relevant_tech = relevance_map[detector]
        if not relevant_tech:
            return True  # Universal

        for url, tech in tech_stack.items():
            frameworks = []
            if hasattr(tech, "frameworks"):
                frameworks = [f.lower() for f in tech.frameworks]
            elif isinstance(tech, dict):
                frameworks = [f.lower() for f in tech.get("frameworks", [])]

            if any(rt in f for rt in relevant_tech for f in frameworks):
                return True

        return False

    def batch_score(self, findings: list[dict], context: dict | None = None) -> list[dict]:
        """Score a batch of findings, returning them with adjusted confidence."""
        for finding in findings:
            finding["confidence"] = self.score(finding, context)
        return findings

    def classify_priority(self, finding: dict) -> str:
        """Classify a finding into bug bounty priority tiers."""
        severity = finding.get("severity", "info")
        confidence = finding.get("confidence", 0.0)

        if severity == "critical" and confidence >= 0.8:
            return "P1"
        elif severity in ("critical", "high") and confidence >= 0.6:
            return "P2"
        elif severity in ("high", "medium") and confidence >= 0.5:
            return "P3"
        elif severity == "medium" and confidence >= 0.4:
            return "P4"
        else:
            return "P5"
