"""
Triage report generator.

Produces per-finding Markdown reports and HTML summary dashboards
from scan results.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from confidence.scorer import ConfidenceScorer

logger = logging.getLogger("hunterengine.reporting.triage")


class TriageReporter:
    """Generate triage reports from scan findings."""

    def __init__(
        self,
        output_dir: str = "data/reports",
        formats: Optional[list[str]] = None,
        include_evidence: bool = True,
        template_dir: str = "reporting/templates",
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.formats = formats or ["markdown"]
        self.include_evidence = include_evidence
        self.scorer = ConfidenceScorer()

        # Jinja2 environment
        tmpl_path = Path(template_dir)
        if tmpl_path.exists():
            self._jinja = Environment(
                loader=FileSystemLoader(str(tmpl_path)),
                autoescape=select_autoescape(["html"]),
            )
        else:
            self._jinja = None

    async def generate(self, scan_state: Any) -> dict[str, Path]:
        """
        Generate reports in all configured formats.

        Returns dict mapping format → output file path.
        """
        outputs: dict[str, Path] = {}
        timestamp = time.strftime("%Y%m%d_%H%M%S")

        # Sort findings by severity and confidence
        findings = sorted(
            scan_state.findings,
            key=lambda f: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    f.get("severity", "info"), 5
                ),
                -f.get("confidence", 0),
            ),
        )

        # Assign priority tiers
        for f in findings:
            f["priority"] = self.scorer.classify_priority(f)

        if "markdown" in self.formats:
            path = await self._generate_markdown(findings, scan_state, timestamp)
            outputs["markdown"] = path

        if "html" in self.formats:
            path = await self._generate_html(findings, scan_state, timestamp)
            outputs["html"] = path

        if "hackerone" in self.formats:
            from reporting.h1_formatter import H1Formatter
            formatter = H1Formatter(self.output_dir)
            paths = await formatter.format_all(findings)
            outputs["hackerone"] = paths[0] if paths else self.output_dir

        if "bugcrowd" in self.formats:
            from reporting.bugcrowd_formatter import BugcrowdFormatter
            formatter = BugcrowdFormatter(self.output_dir)
            paths = await formatter.format_all(findings)
            outputs["bugcrowd"] = paths[0] if paths else self.output_dir

        logger.info(f"Reports generated: {list(outputs.keys())}")
        return outputs

    async def _generate_markdown(
        self,
        findings: list[dict],
        scan_state: Any,
        timestamp: str,
    ) -> Path:
        """Generate a Markdown summary report."""
        lines = [
            f"# HunterEngine Scan Report",
            f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {time.time() - scan_state.start_time:.0f}s",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Subdomains | {len(scan_state.subdomains)} |",
            f"| Live Hosts | {len(scan_state.live_hosts)} |",
            f"| Endpoints | {len(scan_state.endpoints)} |",
            f"| Total Findings | {len(findings)} |",
            f"| Chained Findings | {len(scan_state.chained_findings)} |",
            "",
        ]

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "info")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        lines.append("### Severity Breakdown")
        lines.append("")
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
            lines.append(f"- {emoji} **{sev.upper()}**: {count}")
        lines.append("")

        # Findings
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for i, finding in enumerate(findings, 1):
            sev = finding.get("severity", "info").upper()
            priority = finding.get("priority", "P5")
            conf = finding.get("confidence", 0)

            lines.append(f"### [{priority}] {finding.get('title', 'Untitled')}")
            lines.append("")
            lines.append(f"**Severity:** {sev} | **Confidence:** {conf:.0%} | **Detector:** {finding.get('detector', '')}")
            lines.append(f"**URL:** `{finding.get('url', '')}`")
            if finding.get("parameter"):
                lines.append(f"**Parameter:** `{finding['parameter']}`")
            lines.append("")
            lines.append(finding.get("description", ""))
            lines.append("")

            if self.include_evidence and finding.get("evidence"):
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(finding["evidence"][:2000])
                lines.append("```")
                lines.append("")

            if finding.get("impact"):
                lines.append(f"**Impact:** {finding['impact']}")
                lines.append("")

            if finding.get("ai_summary") or finding.get("metadata", {}).get("ai_analysis"):
                analysis = finding.get("metadata", {}).get("ai_analysis", {})
                lines.append("**AI Triage:**")
                if finding.get("ai_summary"):
                    lines.append(finding["ai_summary"])
                if analysis.get("false_positive_risk"):
                    lines.append(f"- False-positive risk: `{analysis['false_positive_risk']}`")
                if analysis.get("rationale"):
                    lines.append(f"- Rationale: {analysis['rationale']}")
                if finding.get("ai_validation_steps"):
                    lines.append("- Suggested safe validation:")
                    for step in finding["ai_validation_steps"]:
                        lines.append(f"  - {step}")
                lines.append("")

            if finding.get("remediation"):
                lines.append(f"**Remediation:** {finding['remediation']}")
                lines.append("")

            lines.append("---")
            lines.append("")

        # Errors
        if scan_state.errors:
            lines.append("## Errors")
            lines.append("")
            for err in scan_state.errors:
                lines.append(f"- {err}")
            lines.append("")

        output_path = self.output_dir / f"report_{timestamp}.md"
        output_path.write_text("\n".join(lines))
        logger.info(f"Markdown report: {output_path}")
        return output_path

    async def _generate_html(
        self,
        findings: list[dict],
        scan_state: Any,
        timestamp: str,
    ) -> Path:
        """Generate an HTML summary report."""
        if self._jinja:
            try:
                template = self._jinja.get_template("summary.html.j2")
                html = template.render(
                    findings=findings,
                    scan_state=scan_state,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
                    duration=time.time() - scan_state.start_time,
                )
                output_path = self.output_dir / f"report_{timestamp}.html"
                output_path.write_text(html)
                return output_path
            except Exception as e:
                logger.warning(f"Template rendering failed, using fallback: {e}")

        # Fallback: simple HTML
        md_path = await self._generate_markdown(findings, scan_state, timestamp)
        md_content = md_path.read_text()

        html = f"""<!DOCTYPE html>
<html><head><title>HunterEngine Report</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
pre {{ background: #f4f4f4; padding: 12px; overflow-x: auto; border-radius: 4px; }}
h1 {{ color: #1a1a2e; }} h2 {{ color: #16213e; }} h3 {{ color: #0f3460; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #f8f9fa; }}
hr {{ border: 0; border-top: 1px solid #eee; margin: 30px 0; }}
</style></head><body>
<pre>{md_content}</pre>
</body></html>"""

        output_path = self.output_dir / f"report_{timestamp}.html"
        output_path.write_text(html)
        return output_path
