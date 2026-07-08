"""
Weak signal aggregation and correlation engine.

Combines individually low-confidence signals into higher-confidence
composite findings. Connects to the vulnerability chaining engine.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from confidence.scorer import ConfidenceScorer
from memory.vuln_chaining import VulnChaining

logger = logging.getLogger("hunterengine.confidence.correlation")


class CorrelationEngine:
    """Aggregate weak signals and chain findings for escalation."""

    def __init__(self) -> None:
        self.scorer = ConfidenceScorer()
        self.chainer = VulnChaining()

    def correlate(
        self,
        findings: list[dict],
        weak_signals: list[dict],
        scan_state: Any = None,
    ) -> list[dict]:
        """
        Run full correlation pipeline:
          1. Aggregate weak signals by host/type
          2. Promote clusters of weak signals to findings
          3. Chain findings into escalated vulnerabilities
          4. Re-score everything

        Returns:
            List of new/escalated finding dicts
        """
        new_findings: list[dict] = []

        # 1. Aggregate weak signals
        aggregated = self._aggregate_weak_signals(weak_signals)
        for agg in aggregated:
            new_findings.append(agg)

        # 2. Chain findings
        chained = self.chainer.find_chains(findings, weak_signals)
        new_findings.extend(chained)

        # 3. Host-level correlation
        host_findings = self._correlate_by_host(findings + weak_signals)
        new_findings.extend(host_findings)

        # 4. Re-score all
        context = {}
        if scan_state:
            context["tech_stack"] = getattr(scan_state, "tech_stack", {})

        for finding in new_findings:
            finding["confidence"] = self.scorer.score(finding, context)
            finding["priority"] = self.scorer.classify_priority(finding)

        logger.info(f"Correlation produced {len(new_findings)} new/escalated findings")
        return new_findings

    def _aggregate_weak_signals(self, weak_signals: list[dict]) -> list[dict]:
        """
        Group weak signals by type and host.
        If multiple weak signals of the same type hit the same host,
        promote to a medium-confidence finding.
        """
        findings = []

        # Group by (detector, host)
        groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for signal in weak_signals:
            detector = signal.get("detector", "unknown")
            host = urlparse(signal.get("url", "")).netloc
            groups[(detector, host)].append(signal)

        for (detector, host), signals in groups.items():
            if len(signals) < 3:
                continue

            # Multiple weak signals of same type on same host → promote
            sample = signals[0]
            combined_evidence = "\n---\n".join(
                f"[{s.get('url', '')}] {s.get('evidence', s.get('description', ''))[:200]}"
                for s in signals[:5]
            )

            findings.append({
                "title": f"Multiple {detector} Indicators on {host}",
                "description": (
                    f"{len(signals)} separate {detector} indicators were found on {host}. "
                    "While each individual signal is low-confidence, the cluster "
                    "strongly suggests a systemic issue worth investigating."
                ),
                "severity": self._escalate_severity(sample.get("severity", "info")),
                "confidence": min(0.3 + (len(signals) * 0.1), 0.85),
                "detector": "correlation_engine",
                "url": signals[0].get("url", ""),
                "evidence": combined_evidence,
                "tags": ["aggregated", "correlation", detector],
                "metadata": {
                    "signal_count": len(signals),
                    "original_detector": detector,
                    "host": host,
                },
            })

        return findings

    def _correlate_by_host(self, all_findings: list[dict]) -> list[dict]:
        """
        Look for hosts with findings across multiple categories.
        A host with diverse vulnerability types is likely poorly secured overall.
        """
        findings = []

        # Group by host
        host_findings: dict[str, list[dict]] = defaultdict(list)
        for f in all_findings:
            host = urlparse(f.get("url", "")).netloc
            if host:
                host_findings[host].append(f)

        for host, host_f in host_findings.items():
            detectors = set(f.get("detector", "") for f in host_f)
            if len(detectors) >= 4:
                findings.append({
                    "title": f"Systemic Security Issues on {host}",
                    "description": (
                        f"{host} has findings from {len(detectors)} different detection modules: "
                        f"{', '.join(sorted(detectors))}. This indicates broad security weaknesses "
                        "that may reflect deeper architectural or process issues."
                    ),
                    "severity": "medium",
                    "confidence": 0.7,
                    "detector": "correlation_engine",
                    "url": f"https://{host}",
                    "tags": ["systemic", "correlation", "multi-category"],
                    "metadata": {
                        "detectors": sorted(detectors),
                        "finding_count": len(host_f),
                    },
                })

        return findings

    @staticmethod
    def _escalate_severity(current: str) -> str:
        """Escalate severity by one level."""
        escalation = {
            "info": "low",
            "low": "medium",
            "medium": "high",
            "high": "critical",
            "critical": "critical",
        }
        return escalation.get(current, "medium")
