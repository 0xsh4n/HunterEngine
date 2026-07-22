"""
Shared Ollama / OpenAI-compatible client for HunterEngine AI layers.

Optimized for local models (especially Qwen3 with thinking/reasoning).
Used by both triage (reporting) and testing (bug-hunt) modes.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Union

import httpx

logger = logging.getLogger("hunterengine.ai.ollama_client")

ThinkValue = Union[bool, str]  # true/false or "low"|"medium"|"high"


@dataclass
class OllamaClientConfig:
    """Connection settings for a local LLM endpoint."""

    provider: str = "ollama"
    base_url: str = "http://127.0.0.1:11434"
    model: str = "qwen3:4b"
    timeout: float = 90.0
    temperature: float = 0.2
    think: Optional[ThinkValue] = True
    num_ctx: int = 8192
    num_predict: int = 2048
    api_key_env: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_model_block(
        cls,
        block: dict[str, Any],
        *,
        provider: str = "ollama",
        defaults: Optional[dict[str, Any]] = None,
    ) -> "OllamaClientConfig":
        defaults = defaults or {}
        env_base = os.getenv("OLLAMA_BASE_URL", "").strip()
        return cls(
            provider=block.get("provider", defaults.get("provider", provider)),
            base_url=(
                block.get("base_url")
                or env_base
                or defaults.get("base_url")
                or "http://127.0.0.1:11434"
            ),
            model=block.get("model", defaults.get("model", "qwen3:4b")),
            timeout=float(block.get("timeout", defaults.get("timeout", 90))),
            temperature=float(block.get("temperature", defaults.get("temperature", 0.2))),
            think=_parse_think(block.get("think", defaults.get("think", True))),
            num_ctx=int(block.get("num_ctx", defaults.get("num_ctx", 8192))),
            num_predict=int(block.get("num_predict", defaults.get("num_predict", 2048))),
            api_key_env=block.get("api_key_env", defaults.get("api_key_env", "")),
            extra_headers=dict(block.get("headers", {}) or {}),
        )


class OllamaClient:
    """Thin async client over Ollama native API (preferred) or OpenAI-compatible."""

    def __init__(self, config: OllamaClientConfig) -> None:
        self.config = config
        self.usage = {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
            "requests": 0, "requests_started": 0, "failed_requests": 0,
            "prompt_tokens_estimated": 0,
        }
        self.availability_error = ""

    def _record_usage(self, data: dict[str, Any]) -> None:
        """Accumulate provider usage fields across concurrent specialist calls."""
        usage = data.get("usage", {}) if isinstance(data, dict) else {}
        prompt = usage.get("prompt_tokens", data.get("prompt_eval_count", 0)) or 0
        completion = usage.get("completion_tokens", data.get("eval_count", 0)) or 0
        self.usage["prompt_tokens"] += int(prompt)
        self.usage["completion_tokens"] += int(completion)
        self.usage["total_tokens"] += int(usage.get("total_tokens", int(prompt) + int(completion)) or 0)
        self.usage["requests"] += 1

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        headers.update(self.config.extra_headers)
        if self.config.api_key_env:
            api_key = os.getenv(self.config.api_key_env, "")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        return headers

    async def available(self) -> bool:
        provider = self.config.provider.lower().strip()
        base = self.config.base_url.rstrip("/")
        health = base + ("/api/tags" if provider == "ollama" else "/v1/models")
        try:
            async with httpx.AsyncClient(timeout=min(self.config.timeout, 3.0)) as client:
                response = await client.get(health, headers=self.headers())
            if response.status_code >= 500:
                self.availability_error = f"HTTP {response.status_code} from {health}"
                return False
                if provider == "ollama" and response.status_code == 200:
                    # A healthy daemon without the configured model cannot answer
                    # planner calls; detect this before launching nine timeouts.
                    try:
                        models = response.json().get("models", [])
                        names = {str(row.get("name", "")) for row in models if isinstance(row, dict)}
                        if not names:
                            self.availability_error = "Ollama is running but returned no models"
                            return False
                        if not any(self.config.model == name or self.config.model.split(":")[0] == name.split(":")[0] for name in names):
                            self.availability_error = f"Configured model not installed: {self.config.model}"
                            return False
                    except (ValueError, TypeError, AttributeError):
                        self.availability_error = "Ollama /api/tags returned invalid JSON"
                        return False
                return response.status_code < 500
        except Exception as exc:
            self.availability_error = f"{type(exc).__name__}: {exc}"
            return False

    async def chat(
        self,
        *,
        system: str,
        user: str,
        json_mode: bool = True,
        think: Optional[ThinkValue] = None,
    ) -> str:
        """Return assistant content (thinking traces are stripped / kept separate)."""
        self.usage["requests_started"] += 1
        self.usage["prompt_tokens_estimated"] += max(1, (len(system) + len(user)) // 4)
        provider = self.config.provider.lower().strip()
        try:
            if provider == "ollama":
                return await self._chat_ollama(system=system, user=user, json_mode=json_mode, think=think)
            if provider in {"openai-compatible", "openai_compatible", "lmstudio", "llama.cpp"}:
                return await self._chat_openai(system=system, user=user, json_mode=json_mode)
            raise ValueError(f"Unsupported local AI provider: {self.config.provider}")
        except Exception:
            self.usage["failed_requests"] += 1
            raise

    async def chat_json(
        self,
        *,
        system: str,
        user: str,
        think: Optional[ThinkValue] = None,
    ) -> Optional[dict[str, Any]]:
        content = await self.chat(system=system, user=user, json_mode=True, think=think)
        return parse_json_object(content)

    async def _chat_ollama(
        self,
        *,
        system: str,
        user: str,
        json_mode: bool,
        think: Optional[ThinkValue],
    ) -> str:
        url = self.config.base_url.rstrip("/") + "/api/chat"
        think_value = self.config.think if think is None else think
        payload: dict[str, Any] = {
            "model": self.config.model,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
                "num_predict": self.config.num_predict,
            },
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["format"] = "json"
        if think_value is not None:
            payload["think"] = think_value

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self.headers())
            if response.status_code in (400, 404):
                # Older Ollama / non-chat models: fall back without think
                return await self._generate_ollama(system=system, user=user, json_mode=json_mode)
            response.raise_for_status()
            data = response.json()
            self._record_usage(data)

        message = data.get("message", {}) or {}
        content = message.get("content", "") or ""
        # Some builds leave thinking markers in content — strip them
        return strip_thinking(content)

    async def _generate_ollama(self, *, system: str, user: str, json_mode: bool) -> str:
        url = self.config.base_url.rstrip("/") + "/api/generate"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_ctx": self.config.num_ctx,
                "num_predict": self.config.num_predict,
            },
            "prompt": f"{system}\n\n{user}",
        }
        if json_mode:
            payload["format"] = "json"
        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self.headers())
            response.raise_for_status()
            data = response.json()
            self._record_usage(data)
        return strip_thinking(data.get("response", "") or "")

    async def _chat_openai(self, *, system: str, user: str, json_mode: bool) -> str:
        url = self.config.base_url.rstrip("/") + "/v1/chat/completions"
        payload: dict[str, Any] = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.num_predict,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        # Qwen3 thinking control on OpenAI-compat path
        if self.config.think is False:
            payload["reasoning_effort"] = "none"
        elif self.config.think in ("low", "medium", "high"):
            payload["reasoning_effort"] = self.config.think

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload, headers=self.headers())
            response.raise_for_status()
            data = response.json()
            self._record_usage(data)
        choices = data.get("choices", [])
        if not choices:
            return ""
        return strip_thinking(choices[0].get("message", {}).get("content", "") or "")


def _parse_think(value: Any) -> Optional[ThinkValue]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off", "none"}:
            return False
        if lowered in {"low", "medium", "high", "max"}:
            return lowered
    return True


def strip_thinking(text: str) -> str:
    """Remove Qwen-style thinking blocks if they leaked into content."""
    if not text:
        return ""
    cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<thinking>.*?</thinking>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    return cleaned.strip()


def parse_json_object(content: str) -> Optional[dict[str, Any]]:
    if not content:
        return None
    text = strip_thinking(content)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None
