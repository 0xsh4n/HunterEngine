"""
Small FastAPI dashboard for HunterEngine configuration and AI health checks.

Ollama stays external — the dashboard only probes whatever base_url is configured.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("hunterengine.dashboard")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS = ROOT / "config" / "settings.yaml"
DEFAULT_SCOPE = ROOT / "config" / "scope.yaml"

# Keys editable from the UI (nested paths as tuples)
EDITABLE_AI = {
    "enabled", "mode", "provider",
}
EDITABLE_LOCAL = {"base_url", "model", "timeout", "temperature"}
EDITABLE_TESTING_MODEL = {"base_url", "model", "timeout", "temperature", "think", "num_ctx", "num_predict"}
EDITABLE_TESTING = {
    "enabled", "concurrency", "max_endpoints", "max_probes_per_agent",
    "max_total_probes", "min_confidence", "planner_deadline", "generated_agent", "subagents",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def _dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def create_app(
    settings_path: str | Path = DEFAULT_SETTINGS,
    scope_path: str | Path = DEFAULT_SCOPE,
):
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import HTMLResponse
    except ImportError as exc:
        raise ImportError(
            "Dashboard requires fastapi and uvicorn. Install with: pip install fastapi uvicorn"
        ) from exc

    settings_file = Path(settings_path)
    scope_file = Path(scope_path)

    app = FastAPI(title="HunterEngine Dashboard", version="3.1.0")

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/api/settings")
    async def get_settings() -> dict[str, Any]:
        return _load_yaml(settings_file)

    @app.post("/api/settings")
    async def save_settings(payload: dict[str, Any]) -> dict[str, Any]:
        current = _load_yaml(settings_file)
        updated = _merge_settings(current, payload)
        _dump_yaml(settings_file, updated)
        return {"ok": True, "settings": updated}

    @app.get("/api/scope")
    async def get_scope() -> dict[str, Any]:
        return _load_yaml(scope_file)

    @app.post("/api/scope")
    async def save_scope(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(400, "Scope must be a JSON object")
        _dump_yaml(scope_file, payload)
        return {"ok": True, "scope": payload}

    @app.get("/api/health/ai")
    async def ai_health() -> dict[str, Any]:
        from ai.ollama_client import OllamaClient
        from ai.testing_agent import TestingAIConfig
        from ai.local_reasoner import LocalAIConfig

        settings = _load_yaml(settings_file)
        testing_cfg = TestingAIConfig.from_settings(settings)
        triage_cfg = LocalAIConfig.from_settings(settings)

        testing_client = OllamaClient(testing_cfg.to_client_config())
        testing_report = await testing_client.health_check()

        triage_report: dict[str, Any]
        if (
            triage_cfg.base_url == testing_cfg.base_url
            and triage_cfg.model == testing_cfg.model
            and triage_cfg.provider == testing_cfg.provider
        ):
            triage_report = dict(testing_report)
        else:
            from ai.ollama_client import OllamaClientConfig
            triage_client = OllamaClient(OllamaClientConfig(
                provider=triage_cfg.provider,
                base_url=triage_cfg.base_url,
                model=triage_cfg.model,
                timeout=triage_cfg.timeout,
            ))
            triage_report = await triage_client.health_check()

        probe: dict[str, Any] = {"ok": False, "reply": "", "error": ""}
        if testing_report.get("ok"):
            try:
                reply = await asyncio.wait_for(
                    testing_client.chat(
                        system="Reply with exactly: pong",
                        user="ping",
                        json_mode=False,
                        think=False,
                    ),
                    timeout=min(testing_cfg.timeout, 45.0),
                )
                probe["ok"] = "pong" in (reply or "").lower() or bool(reply.strip())
                probe["reply"] = (reply or "")[:200]
                if not probe["ok"]:
                    probe["error"] = "Model responded but did not look healthy"
            except Exception as exc:
                probe["error"] = f"{type(exc).__name__}: {exc}"

        overall = bool(testing_report.get("ok") and probe.get("ok"))
        return {
            "ok": overall,
            "testing": testing_report,
            "triage": triage_report,
            "chat_probe": probe,
            "config": {
                "ai_enabled": bool((settings.get("ai") or {}).get("enabled")),
                "mode": (settings.get("ai") or {}).get("mode"),
                "testing_model": testing_cfg.model,
                "testing_base_url": testing_cfg.base_url,
                "provider": testing_cfg.provider,
            },
            "hints": _health_hints(testing_report, probe),
        }

    @app.get("/api/domains")
    async def list_domains() -> dict[str, Any]:
        from memory.domain_learner import DomainLearner

        settings = _load_yaml(settings_file)
        data_dir = (settings.get("general") or {}).get("data_dir", "data")
        learner = DomainLearner(f"{data_dir}/domain_profiles")
        return {"profiles": learner.list_profiles()}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        return {
            "app": "HunterEngine",
            "settings_path": str(settings_file),
            "scope_path": str(scope_file),
            "settings_exists": settings_file.exists(),
            "scope_exists": scope_file.exists(),
        }

    return app


def _merge_settings(current: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(current) if current else {}
    ai_in = payload.get("ai") if isinstance(payload.get("ai"), dict) else payload
    if not isinstance(ai_in, dict):
        return out

    ai = out.setdefault("ai", {})
    for key in EDITABLE_AI:
        if key in ai_in:
            ai[key] = ai_in[key]

    if isinstance(ai_in.get("local_model"), dict):
        block = ai.setdefault("local_model", {})
        for key in EDITABLE_LOCAL:
            if key in ai_in["local_model"]:
                block[key] = ai_in["local_model"][key]

    if isinstance(ai_in.get("testing_model"), dict):
        block = ai.setdefault("testing_model", {})
        for key in EDITABLE_TESTING_MODEL:
            if key in ai_in["testing_model"]:
                block[key] = ai_in["testing_model"][key]

    if isinstance(ai_in.get("testing"), dict):
        block = ai.setdefault("testing", {})
        for key in EDITABLE_TESTING:
            if key in ai_in["testing"]:
                block[key] = ai_in["testing"][key]

    testing_profile = payload.get("testing")
    if isinstance(testing_profile, dict) and "profile" in testing_profile:
        out.setdefault("testing", {})["profile"] = testing_profile["profile"]

    return out


def _health_hints(testing_report: dict[str, Any], probe: dict[str, Any]) -> list[str]:
    hints: list[str] = []
    err = str(testing_report.get("error") or "")
    if not testing_report.get("ok"):
        if "not installed" in err.lower():
            hints.append(f"Pull the model on the Ollama host: ollama pull {testing_report.get('model')}")
        elif "ConnectError" in err or "ConnectTimeout" in err or "timeout" in err.lower():
            hints.append(
                "Cannot reach Ollama. Start it on the host, set ai.testing_model.base_url "
                "(Docker: http://host.docker.internal:11434), and export OLLAMA_BASE_URL if needed."
            )
        elif err:
            hints.append(err)
        else:
            hints.append("AI provider health check failed.")
    elif not probe.get("ok"):
        hints.append(probe.get("error") or "Chat probe failed — model may be overloaded or incompatible.")
    else:
        hints.append("AI testing endpoint is healthy.")
    return hints


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8787,
    settings_path: str = str(DEFAULT_SETTINGS),
    scope_path: str = str(DEFAULT_SCOPE),
) -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError("Install uvicorn: pip install uvicorn fastapi") from exc

    app = create_app(settings_path=settings_path, scope_path=scope_path)
    logger.info("HunterEngine dashboard on http://%s:%s", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HunterEngine Dashboard</title>
  <style>
    :root {
      --bg: #0f1419;
      --panel: #1a222d;
      --ink: #e7eef7;
      --muted: #8b9bb0;
      --accent: #3d9cfd;
      --ok: #3ecf8e;
      --bad: #f07178;
      --line: #2a3544;
      --font: "IBM Plex Sans", "Segoe UI", sans-serif;
      --mono: "IBM Plex Mono", Consolas, monospace;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; color: var(--ink); font-family: var(--font);
      background:
        radial-gradient(1200px 600px at 10% -10%, #1b3a5a 0%, transparent 55%),
        radial-gradient(900px 500px at 100% 0%, #24301f 0%, transparent 50%),
        var(--bg);
    }
    header {
      padding: 1.5rem 2rem 0.5rem; display: flex; justify-content: space-between;
      align-items: flex-end; gap: 1rem; flex-wrap: wrap;
    }
    h1 { margin: 0; font-size: 1.6rem; letter-spacing: 0.04em; }
    header p { margin: 0.35rem 0 0; color: var(--muted); max-width: 42rem; }
    main { padding: 1rem 2rem 2.5rem; display: grid; gap: 1rem; grid-template-columns: 1.2fr 1fr; }
    @media (max-width: 960px) { main { grid-template-columns: 1fr; } }
    section {
      background: color-mix(in srgb, var(--panel) 92%, black);
      border: 1px solid var(--line); border-radius: 14px; padding: 1.1rem 1.2rem;
      box-shadow: 0 12px 40px rgba(0,0,0,0.25);
    }
    h2 { margin: 0 0 0.85rem; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
    label { display: block; font-size: 0.78rem; color: var(--muted); margin: 0.65rem 0 0.25rem; }
    input, select, textarea {
      width: 100%; background: #10161e; color: var(--ink); border: 1px solid var(--line);
      border-radius: 8px; padding: 0.55rem 0.7rem; font: inherit;
    }
    textarea { min-height: 140px; font-family: var(--mono); font-size: 0.85rem; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
    .actions { display: flex; gap: 0.6rem; flex-wrap: wrap; margin-top: 1rem; }
    button {
      border: 0; border-radius: 999px; padding: 0.65rem 1.1rem; cursor: pointer;
      font-weight: 600; background: var(--accent); color: #041018;
    }
    button.secondary { background: #2b3645; color: var(--ink); }
    button:disabled { opacity: 0.55; cursor: wait; }
    .pill {
      display: inline-flex; align-items: center; gap: 0.4rem; border-radius: 999px;
      padding: 0.35rem 0.75rem; font-size: 0.85rem; border: 1px solid var(--line);
    }
    .pill.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, var(--line)); }
    .pill.bad { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 40%, var(--line)); }
    .mono { font-family: var(--mono); font-size: 0.82rem; white-space: pre-wrap; color: var(--muted); }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th, td { text-align: left; padding: 0.45rem 0.3rem; border-bottom: 1px solid var(--line); }
    .span-2 { grid-column: 1 / -1; }
    #toast { min-height: 1.2rem; color: var(--muted); margin-top: 0.5rem; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>HunterEngine</h1>
      <p>Configure AI testing and scope here instead of hand-editing YAML. Ollama stays on the host — this panel only talks to the URL you set.</p>
    </div>
    <div id="statusPill" class="pill">Checking…</div>
  </header>
  <main>
    <section>
      <h2>AI settings</h2>
      <div class="row">
        <div>
          <label>AI enabled</label>
          <select id="aiEnabled"><option value="true">true</option><option value="false">false</option></select>
        </div>
        <div>
          <label>Mode</label>
          <select id="aiMode">
            <option value="testing">testing</option>
            <option value="triage">triage</option>
            <option value="both">both</option>
          </select>
        </div>
      </div>
      <div class="row">
        <div>
          <label>Provider</label>
          <select id="provider">
            <option value="ollama">ollama</option>
            <option value="openai-compatible">openai-compatible</option>
            <option value="lmstudio">lmstudio</option>
          </select>
        </div>
        <div>
          <label>Testing model</label>
          <input id="model" placeholder="qwen3:4b" />
        </div>
      </div>
      <label>Ollama / OpenAI base URL (external)</label>
      <input id="baseUrl" placeholder="http://127.0.0.1:11434" />
      <div class="row">
        <div>
          <label>Think / reasoning</label>
          <select id="think"><option value="true">true</option><option value="false">false</option></select>
        </div>
        <div>
          <label>Planner deadline (seconds)</label>
          <input id="plannerDeadline" type="number" min="3" step="1" />
        </div>
      </div>
      <label>Subagents (comma-separated)</label>
      <input id="subagents" />
      <div class="actions">
        <button id="saveBtn" type="button">Save settings</button>
        <button id="healthBtn" class="secondary" type="button">Health check</button>
      </div>
      <div id="toast"></div>
    </section>

    <section>
      <h2>AI health</h2>
      <div id="healthSummary" class="mono">Click Health check to probe Ollama and run a short chat test.</div>
      <div class="actions">
        <button id="healthBtn2" class="secondary" type="button">Run health check</button>
      </div>
    </section>

    <section>
      <h2>Scope (YAML)</h2>
      <textarea id="scopeYaml" spellcheck="false"></textarea>
      <div class="actions">
        <button id="saveScopeBtn" type="button">Save scope</button>
        <button id="reloadScopeBtn" class="secondary" type="button">Reload</button>
      </div>
    </section>

    <section>
      <h2>Domain learning</h2>
      <div id="domains" class="mono">Loading…</div>
    </section>

    <section class="span-2">
      <h2>Quick commands</h2>
      <div class="mono">python main.py scan --phase ai_test
python main.py ai-health
python main.py dashboard --host 0.0.0.0 --port 8787
docker compose up -d   # Ollama stays on the host</div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const toast = (msg) => { $("toast").textContent = msg; };

    async function loadSettings() {
      const s = await fetch("/api/settings").then(r => r.json());
      const ai = s.ai || {};
      const tm = ai.testing_model || ai.local_model || {};
      const testing = ai.testing || {};
      $("aiEnabled").value = String(!!ai.enabled);
      $("aiMode").value = ai.mode || "testing";
      $("provider").value = ai.provider || "ollama";
      $("model").value = tm.model || "qwen3:4b";
      $("baseUrl").value = tm.base_url || "http://127.0.0.1:11434";
      $("think").value = String(tm.think !== false);
      $("plannerDeadline").value = testing.planner_deadline ?? 25;
      $("subagents").value = (testing.subagents || []).join(", ");
    }

    async function loadScope() {
      const scope = await fetch("/api/scope").then(r => r.json());
      $("scopeYaml").value = jsyamlDump(scope);
    }

    function jsyamlDump(obj) {
      // tiny YAML-ish dump for editing; server re-parses via js? we send JSON from textarea YAML
      return JSON.stringify(obj, null, 2);
    }

    async function saveSettings() {
      const body = {
        ai: {
          enabled: $("aiEnabled").value === "true",
          mode: $("aiMode").value,
          provider: $("provider").value,
          testing_model: {
            base_url: $("baseUrl").value.trim(),
            model: $("model").value.trim(),
            think: $("think").value === "true",
          },
          local_model: {
            base_url: $("baseUrl").value.trim(),
            model: $("model").value.trim(),
          },
          testing: {
            enabled: true,
            planner_deadline: Number($("plannerDeadline").value || 25),
            subagents: $("subagents").value.split(",").map(s => s.trim()).filter(Boolean),
          }
        }
      };
      const res = await fetch("/api/settings", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
      }).then(r => r.json());
      toast(res.ok ? "Settings saved to config/settings.yaml" : "Save failed");
    }

    async function saveScope() {
      let parsed;
      try { parsed = JSON.parse($("scopeYaml").value); }
      catch (e) { toast("Scope editor expects JSON (loaded from YAML). Fix JSON and retry."); return; }
      const res = await fetch("/api/scope", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify(parsed)
      }).then(r => r.json());
      toast(res.ok ? "Scope saved" : "Scope save failed");
    }

    async function healthCheck() {
      ["healthBtn", "healthBtn2"].forEach(id => $(id).disabled = true);
      $("healthSummary").textContent = "Probing…";
      $("statusPill").textContent = "Checking…";
      $("statusPill").className = "pill";
      try {
        const h = await fetch("/api/health/ai").then(r => r.json());
        const ok = !!h.ok;
        $("statusPill").textContent = ok ? "AI healthy" : "AI issue";
        $("statusPill").className = "pill " + (ok ? "ok" : "bad");
        const lines = [
          `overall: ${ok ? "OK" : "FAIL"}`,
          `provider: ${h.config?.provider}  model: ${h.config?.testing_model}`,
          `base_url: ${h.config?.testing_base_url}`,
          `daemon: ${h.testing?.ok ? "ok" : "fail"}  latency: ${h.testing?.latency_ms ?? "?"} ms`,
          `models: ${(h.testing?.models || []).slice(0, 8).join(", ") || "(none)"}`,
          `chat_probe: ${h.chat_probe?.ok ? "ok" : "fail"}  reply: ${JSON.stringify(h.chat_probe?.reply || "")}`,
          `error: ${h.testing?.error || h.chat_probe?.error || "(none)"}`,
          `hints: ${(h.hints || []).join(" | ")}`,
        ];
        $("healthSummary").textContent = lines.join("\\n");
      } catch (e) {
        $("statusPill").textContent = "Health error";
        $("statusPill").className = "pill bad";
        $("healthSummary").textContent = String(e);
      } finally {
        ["healthBtn", "healthBtn2"].forEach(id => $(id).disabled = false);
      }
    }

    async function loadDomains() {
      const data = await fetch("/api/domains").then(r => r.json());
      const rows = data.profiles || [];
      if (!rows.length) {
        $("domains").textContent = "No domain profiles yet. Run a scan to start learning.";
        return;
      }
      const html = ["<table><tr><th>Domain</th><th>Scans</th><th>Preferred hunters</th></tr>"];
      for (const r of rows) {
        html.push(`<tr><td>${r.domain}</td><td>${r.scan_count || 0}</td><td>${(r.preferred_subagents || []).join(", ")}</td></tr>`);
      }
      html.push("</table>");
      $("domains").innerHTML = html.join("");
    }

    $("saveBtn").onclick = saveSettings;
    $("saveScopeBtn").onclick = saveScope;
    $("reloadScopeBtn").onclick = loadScope;
    $("healthBtn").onclick = healthCheck;
    $("healthBtn2").onclick = healthCheck;

    loadSettings();
    loadScope();
    loadDomains();
    healthCheck();
  </script>
</body>
</html>
"""
