"""
Local model reasoning layer.

The reasoner is intentionally a second-pass analyst: it reviews already
discovered findings, adjusts triage conservatively, and improves reporting.
It does not generate new traffic or autonomous exploit attempts.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx

logger = logging.getLogger("hunterengine.ai.local_reasoner")


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
PRIORITY_ORDER = ["P5", "P4", "P3", "P2", "P1"]


@dataclass
class LocalAIConfig:
    """Configuration for local AI *reporting* triage (not testing)."""

    enabled: bool = False
    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b-instruct"
    timeout: float = 45.0
    temperature: float = 0.1
    max_findings: int = 50
    min_confidence: float = 0.2
    concurrency: int = 2
    max_context_chars: int = 6000
    redact_sensitive: bool = True
    api_key_env: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_settings(cls, settings: dict[str, Any]) -> "LocalAIConfig":
        ai_conf = settings.get("ai", {}) or {}
        local_conf = ai_conf.get("local_model", {}) or {}
        mode = str(ai_conf.get("mode", "triage")).lower().strip()
        # Triage/reporting only when mode is triage or both
        triage_on = bool(ai_conf.get("enabled", False)) and mode in ("triage", "both", "reporting")
        env_base = os.getenv("OLLAMA_BASE_URL", "").strip()
        return cls(
            enabled=triage_on,
            provider=local_conf.get("provider", ai_conf.get("provider", "ollama")),
            base_url=local_conf.get(
                "base_url",
                ai_conf.get("base_url", env_base or "http://127.0.0.1:11434"),
            ) or (env_base or "http://127.0.0.1:11434"),
            model=local_conf.get("model", ai_conf.get("model", "qwen2.5:7b-instruct")),
            timeout=float(local_conf.get("timeout", ai_conf.get("timeout", 45))),
            temperature=float(local_conf.get("temperature", ai_conf.get("temperature", 0.1))),
            max_findings=int(ai_conf.get("max_findings", 50)),
            min_confidence=float(ai_conf.get("min_confidence", 0.2)),
            concurrency=int(ai_conf.get("concurrency", 2)),
            max_context_chars=int(ai_conf.get("max_context_chars", 6000)),
            redact_sensitive=bool(ai_conf.get("redact_sensitive", True)),
            api_key_env=local_conf.get("api_key_env", ai_conf.get("api_key_env", "")),
            extra_headers=dict(local_conf.get("headers", {}) or {}),
        )


class LocalAIReasoner:
    """Enrich findings with a local LLM triage pass."""

    def __init__(self, config: LocalAIConfig) -> None:
        self.config = config
        self._sem = asyncio.Semaphore(max(1, config.concurrency))

    async def enrich_findings(self, findings: list[dict], scan_state: Any) -> list[dict]:
        """Analyze and enrich eligible findings in place."""
        if not self.config.enabled:
            return findings
        if not findings:
            return findings

        eligible = [
            finding for finding in findings
            if finding.get("confidence", 0.0) >= self.config.min_confidence
        ][: self.config.max_findings]

        if not eligible:
            logger.info("AI reasoner skipped: no findings met min_confidence")
            return findings

        if not await self._provider_available():
            logger.warning(
                "AI reasoner skipped: %s provider is not reachable at %s",
                self.config.provider,
                self.config.base_url,
            )
            return findings

        logger.info(
            "AI reasoner analyzing %d finding(s) with %s/%s",
            len(eligible),
            self.config.provider,
            self.config.model,
        )

        context = self._scan_context(scan_state)
        tasks = [self._safe_enrich(finding, context) for finding in eligible]
        results = await asyncio.gather(*tasks)

        enriched = sum(1 for ok in results if ok)
        if enriched:
            setattr(scan_state, "ai_enriched_findings", enriched)
            logger.info("AI reasoner enriched %d finding(s)", enriched)
        else:
            logger.warning("AI reasoner did not enrich any findings")

        return findings

    async def _safe_enrich(self, finding: dict, context: dict[str, Any]) -> bool:
        async with self._sem:
            try:
                analysis = await self._analyze_finding(finding, context)
                if not analysis:
                    return False
                self._apply_analysis(finding, analysis)
                return True
            except Exception as exc:
                logger.warning("AI analysis failed for %s: %s", finding.get("title", "finding"), exc)
                return False

    async def _analyze_finding(
        self,
        finding: dict,
        context: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        prompt = self._build_prompt(finding, context)
        content = await self._chat(prompt)
        return self._parse_json(content)

    async def _provider_available(self) -> bool:
        provider = self.config.provider.lower().strip()
        base_url = self.config.base_url.rstrip("/")
        health_url = base_url + ("/api/tags" if provider == "ollama" else "/v1/models")
        try:
            async with httpx.AsyncClient(timeout=min(self.config.timeout, 3.0)) as client:
                response = await client.get(health_url, headers=self._headers())
            return response.status_code < 500
        except Exception:
            return False

    async def _chat(self, prompt: str) -> str:
        provider = self.config.provider.lower().strip()
        if provider == "ollama":
            return await self._chat_ollama(prompt)
        if provider in {"openai-compatible", "openai_compatible", "lmstudio", "llama.cpp"}:
            return await self._chat_openai_compatible(prompt)
        raise ValueError(f"Unsupported local AI provider: {self.config.provider}")

    async def _chat_ollama(self, prompt: str) -> str:
        url = self.config.base_url.rstrip("/") + "/api/chat"
        payload = {
            "model": self.config.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.config.temperature},
            "messages": [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self._headers())
            if response.status_code in (400, 404):
                return await self._generate_ollama(prompt)
            response.raise_for_status()
            data = response.json()
            return data.get("message", {}).get("content", "")

    async def _generate_ollama(self, prompt: str) -> str:
        url = self.config.base_url.rstrip("/") + "/api/generate"
        payload = {
            "model": self.config.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.config.temperature},
            "prompt": f"{self._system_prompt()}\n\n{prompt}",
        }
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self._headers())
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")

    async def _chat_openai_compatible(self, prompt: str) -> str:
        url = self.config.base_url.rstrip("/") + "/v1/chat/completions"
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self._headers())
            response.raise_for_status()
            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                return ""
            return choices[0].get("message", {}).get("content", "")

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        headers.update(self.config.extra_headers)
        if self.config.api_key_env:
            api_key = os.getenv(self.config.api_key_env, "")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _system_prompt(self) -> str:
        return (
            "You are a defensive application security triage analyst reviewing "
            "authorized bug bounty scanner findings. Return only compact JSON. "
            "Do not provide offensive exploit development, persistence, evasion, "
            "credential theft, or instructions for attacking third parties. "
            "Focus on plausibility, false-positive risk, impact, safe validation, "
            "and remediation."
        )

    def _build_prompt(self, finding: dict, context: dict[str, Any]) -> str:
        payload = {
            "task": "Review this scanner finding and improve triage.",
            "required_json_schema": {
                "plausible": "boolean",
                "false_positive_risk": "low|medium|high",
                "severity": "info|low|medium|high|critical",
                "confidence_delta": "number between -0.25 and 0.25",
                "priority": "P1|P2|P3|P4|P5",
                "rationale": "short explanation",
                "report_summary": "one or two report-ready sentences",
                "remediation": "short actionable fix guidance",
                "recommended_validation": ["safe non-destructive validation step"],
                "tags": ["short lowercase tags"],
            },
            "rules": [
                "Be skeptical of weak evidence and lower confidence when needed.",
                "Only raise severity when evidence and impact justify it.",
                "Recommended validation must be non-destructive and scoped.",
                "Do not invent proof that is not present in the evidence.",
            ],
            "scan_context": context,
            "finding": self._safe_finding_payload(finding),
        }
        text = json.dumps(payload, ensure_ascii=True, default=str)
        return text[: self.config.max_context_chars]

    def _safe_finding_payload(self, finding: dict) -> dict[str, Any]:
        allowed = {
            "title",
            "description",
            "severity",
            "confidence",
            "detector",
            "url",
            "method",
            "parameter",
            "evidence",
            "impact",
            "remediation",
            "references",
            "tags",
            "metadata",
        }
        payload = {key: finding.get(key) for key in allowed if key in finding}
        for key in ("evidence", "description", "impact", "remediation"):
            if isinstance(payload.get(key), str):
                payload[key] = self._sanitize(payload[key])[:1800]
        return payload

    def _scan_context(self, scan_state: Any) -> dict[str, Any]:
        live_hosts = getattr(scan_state, "live_hosts", [])[:20]
        endpoints = getattr(scan_state, "endpoints", [])[:30]
        tech_stack = getattr(scan_state, "tech_stack", {})
        weak_signals = getattr(scan_state, "weak_signals", [])[:20]

        return {
            "live_host_count": len(getattr(scan_state, "live_hosts", [])),
            "endpoint_count": len(getattr(scan_state, "endpoints", [])),
            "weak_signal_count": len(getattr(scan_state, "weak_signals", [])),
            "sample_live_hosts": self._sanitize(live_hosts),
            "sample_endpoints": self._sanitize(endpoints),
            "tech_stack": self._sanitize(tech_stack),
            "weak_signal_types": [
                {
                    "title": signal.get("title", ""),
                    "detector": signal.get("detector", ""),
                    "severity": signal.get("severity", ""),
                    "confidence": signal.get("confidence", 0),
                }
                for signal in weak_signals
                if isinstance(signal, dict)
            ],
        }

    def _sanitize(self, value: Any) -> Any:
        if not self.config.redact_sensitive:
            return value
        if isinstance(value, str):
            return _redact(value)
        if isinstance(value, list):
            return [self._sanitize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._sanitize(item) for item in value)
        if isinstance(value, dict):
            sanitized = {}
            for key, item in value.items():
                key_str = str(key)
                if _looks_sensitive_key(key_str):
                    sanitized[key_str] = "[REDACTED]"
                else:
                    sanitized[key_str] = self._sanitize(item)
            return sanitized
        return value

    def _parse_json(self, content: str) -> Optional[dict[str, Any]]:
        if not content:
            return None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if not match:
                return None
            data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None

    def _apply_analysis(self, finding: dict, analysis: dict[str, Any]) -> None:
        metadata = finding.setdefault("metadata", {})
        ai_meta = {
            "provider": self.config.provider,
            "model": self.config.model,
            "plausible": bool(analysis.get("plausible", True)),
            "false_positive_risk": _choice(
                analysis.get("false_positive_risk"),
                {"low", "medium", "high"},
                "medium",
            ),
            "rationale": _short_text(analysis.get("rationale", ""), 800),
            "recommended_validation": _string_list(analysis.get("recommended_validation", []), 5),
        }
        metadata["ai_analysis"] = ai_meta

        current_conf = float(finding.get("confidence", 0.0) or 0.0)
        delta = _clamp_float(analysis.get("confidence_delta", 0.0), -0.25, 0.25)
        if ai_meta["false_positive_risk"] == "high":
            delta = min(delta, -0.15)
        if not ai_meta["plausible"]:
            delta = min(delta, -0.2)
        finding["confidence"] = round(_clamp_float(current_conf + delta, 0.0, 1.0), 3)

        suggested_severity = _choice(analysis.get("severity"), set(SEVERITY_ORDER), finding.get("severity", "info"))
        finding["severity"] = self._bounded_severity(finding.get("severity", "info"), suggested_severity, finding["confidence"])

        priority = _choice(analysis.get("priority"), set(PRIORITY_ORDER), "")
        if priority:
            finding["ai_priority"] = priority

        report_summary = _short_text(analysis.get("report_summary", ""), 1200)
        if report_summary:
            finding["ai_summary"] = report_summary

        remediation = _short_text(analysis.get("remediation", ""), 1200)
        if remediation and len(remediation) > len(str(finding.get("remediation", ""))):
            finding["remediation"] = remediation

        validation = ai_meta["recommended_validation"]
        if validation:
            finding["ai_validation_steps"] = validation

        tags = set(finding.get("tags", []))
        tags.add("ai-reviewed")
        tags.update(_string_list(analysis.get("tags", []), 8))
        if ai_meta["false_positive_risk"] == "high" or not ai_meta["plausible"]:
            tags.add("ai-needs-review")
        finding["tags"] = sorted(str(tag).lower() for tag in tags if str(tag).strip())

    def _bounded_severity(self, current: str, suggested: str, confidence: float) -> str:
        if current not in SEVERITY_ORDER:
            current = "info"
        if suggested not in SEVERITY_ORDER:
            return current

        current_idx = SEVERITY_ORDER.index(current)
        suggested_idx = SEVERITY_ORDER.index(suggested)

        if suggested_idx > current_idx:
            max_raise = 1 if confidence >= 0.75 else 0
            return SEVERITY_ORDER[min(current_idx + max_raise, suggested_idx)]
        return suggested


def _redact(text: str) -> str:
    replacements = [
        (r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key[\"'\s:=]+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]"),
        (r"(?i)(token[\"'\s:=]+)[A-Za-z0-9._~+/=-]{12,}", r"\1[REDACTED]"),
        (r"(?i)(password[\"'\s:=]+)[^&\s\"']+", r"\1[REDACTED]"),
        (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ]
    redacted = text
    for pattern, repl in replacements:
        redacted = re.sub(pattern, repl, redacted, flags=re.DOTALL)
    return redacted


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in ("password", "secret", "token", "authorization", "cookie", "api_key", "apikey"))


def _choice(value: Any, allowed: set[str], default: str) -> str:
    if not isinstance(value, str):
        return default
    normalized = value.strip().lower()
    if allowed == set(PRIORITY_ORDER):
        normalized = normalized.upper()
    return normalized if normalized in allowed else default


def _clamp_float(value: Any, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = 0.0
    return min(max(number, minimum), maximum)


def _short_text(value: Any, max_len: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _string_list(value: Any, max_items: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    results = []
    for item in value[:max_items]:
        text = str(item).strip()
        if text:
            results.append(text[:300])
    return results
