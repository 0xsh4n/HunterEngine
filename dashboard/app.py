"""
Operational FastAPI dashboard for HunterEngine.

More than a health monitor: it reads the latest scan checkpoint and surfaces
findings, the model's captured reasoning / thinking, the behaviour model,
per-domain learning analytics, and live AI usage — plus editable settings and
scope. Ollama stays external; this panel only talks to the URL you configure.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import time
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("hunterengine.dashboard")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS = ROOT / "config" / "settings.yaml"
DEFAULT_SCOPE = ROOT / "config" / "scope.yaml"

# Keys editable from the UI (nested paths as tuples)
EDITABLE_AI = {"enabled", "mode", "provider"}
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


def _data_dir(settings: dict[str, Any]) -> str:
    return (settings.get("general") or {}).get("data_dir", "data")


def _load_latest_run(settings: dict[str, Any]) -> dict[str, Any]:
    """Read the most recent scan checkpoint into a normalized snapshot."""
    data_dir = _data_dir(settings)
    candidates = [
        ROOT / data_dir / "checkpoints" / "latest.json",
        Path(data_dir) / "checkpoints" / "latest.json",
    ]
    path = next((p for p in candidates if p.exists()), None)
    if not path:
        return {"available": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read checkpoint %s: %s", path, exc)
        return {"available": False, "error": str(exc)}

    state = payload.get("state") or {}
    findings = state.get("findings") or []
    sev_counts: dict[str, int] = {}
    for f in findings:
        if isinstance(f, dict):
            sev = str(f.get("severity", "info")).lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "available": True,
        "saved_at": payload.get("saved_at"),
        "reason": payload.get("reason"),
        "phase": state.get("phase"),
        "next_phase": payload.get("next_phase"),
        "completed_phases": payload.get("completed_phases") or [],
        "counts": {
            "subdomains": len(state.get("subdomains") or []),
            "live_hosts": len(state.get("live_hosts") or []),
            "endpoints": len(state.get("endpoints") or []),
            "js_files": len(state.get("js_files") or []),
            "findings": len(findings),
            "weak_signals": len(state.get("weak_signals") or []),
            "chained_findings": len(state.get("chained_findings") or []),
            "errors": len(state.get("errors") or []),
        },
        "severity_counts": sev_counts,
        "findings": findings,
        "weak_signals": state.get("weak_signals") or [],
        "behavior_model": state.get("behavior_model") or {},
        "agentic_decisions": state.get("agentic_decisions") or [],
        "reasoning_traces": state.get("ai_reasoning_traces") or [],
        "reasoning_summary": state.get("ai_reasoning_summary") or {},
        "ai_token_usage": state.get("ai_token_usage") or {},
        "learning_events": (state.get("learning_events") or [])[-40:],
        "phase_health": state.get("phase_health") or {},
        "errors": (state.get("errors") or [])[-40:],
        "ai_enriched_findings": state.get("ai_enriched_findings", 0),
        "ai_test_probes": state.get("ai_test_probes", 0),
        "ai_test_findings": state.get("ai_test_findings", 0),
    }


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

    from dashboard.scan_manager import ScanManager
    scan_manager = ScanManager(str(settings_file), str(scope_file))

    app = FastAPI(title="HunterEngine Dashboard", version="3.2.0")

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

    @app.get("/api/run")
    async def run_snapshot() -> dict[str, Any]:
        """Full latest-scan snapshot (counts, findings, reasoning, behaviour)."""
        return _load_latest_run(_load_yaml(settings_file))

    @app.get("/api/usage")
    async def usage() -> dict[str, Any]:
        """Lightweight AI usage + last-run header for the navbar (polled)."""
        settings = _load_yaml(settings_file)
        run = _load_latest_run(settings)
        ai = settings.get("ai") or {}
        tm = ai.get("testing_model") or ai.get("local_model") or {}
        return {
            "ai_enabled": bool(ai.get("enabled")),
            "mode": ai.get("mode"),
            "provider": ai.get("provider", "ollama"),
            "model": tm.get("model", "qwen3:4b"),
            "usage": run.get("ai_token_usage", {}) if run.get("available") else {},
            "phase": run.get("phase") if run.get("available") else None,
            "saved_at": run.get("saved_at") if run.get("available") else None,
            "findings": run.get("counts", {}).get("findings", 0) if run.get("available") else 0,
            "probes": run.get("ai_test_probes", 0) if run.get("available") else 0,
        }

    @app.get("/api/reasoning")
    async def reasoning() -> dict[str, Any]:
        run = _load_latest_run(_load_yaml(settings_file))
        if not run.get("available"):
            return {"available": False}
        return {
            "available": True,
            "summary": run.get("reasoning_summary", {}),
            "traces": run.get("reasoning_traces", []),
            "decisions": run.get("agentic_decisions", []),
            "usage": run.get("ai_token_usage", {}),
        }

    @app.get("/api/behavior")
    async def behavior() -> dict[str, Any]:
        run = _load_latest_run(_load_yaml(settings_file))
        return {"available": run.get("available", False), "behavior": run.get("behavior_model", {})}

    @app.get("/api/findings")
    async def findings() -> dict[str, Any]:
        run = _load_latest_run(_load_yaml(settings_file))
        return {
            "available": run.get("available", False),
            "findings": run.get("findings", []),
            "severity_counts": run.get("severity_counts", {}),
        }

    @app.get("/api/domains")
    async def list_domains() -> dict[str, Any]:
        from memory.domain_learner import DomainLearner

        settings = _load_yaml(settings_file)
        learner = DomainLearner(f"{_data_dir(settings)}/domain_profiles")
        return {"profiles": learner.list_profiles(), "analytics": learner.analytics()}

    @app.get("/api/status")
    async def status() -> dict[str, Any]:
        settings = _load_yaml(settings_file)
        run = _load_latest_run(settings)
        return {
            "app": "HunterEngine",
            "version": "3.2.0",
            "settings_path": str(settings_file),
            "scope_path": str(scope_file),
            "settings_exists": settings_file.exists(),
            "scope_exists": scope_file.exists(),
            "has_run": run.get("available", False),
            "scan_running": scan_manager.running,
        }

    @app.get("/api/methodology")
    async def methodology() -> dict[str, Any]:
        from core.methodology import manifest
        return {"steps": manifest()}

    @app.post("/api/scan/start")
    async def scan_start(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = payload or {}
        target = str(payload.get("target", "")).strip()
        profile = str(payload.get("profile", "blackbox")).strip() or "blackbox"
        phases = payload.get("phases") or None
        if isinstance(phases, str):
            phases = [p.strip() for p in phases.split(",") if p.strip()] or None
        try:
            return {"ok": True, "status": scan_manager.start(target, profile, phases)}
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/scan/stop")
    async def scan_stop(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        save = bool((payload or {}).get("save", False))
        return {"ok": True, "status": scan_manager.stop(save=save)}

    @app.get("/api/scan/status")
    async def scan_status() -> dict[str, Any]:
        return scan_manager.status()

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


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HunterEngine Console</title>
  <style>
    :root {
      --bg: #0c1016; --panel: #151c26; --panel2: #1a222d; --ink: #e7eef7;
      --muted: #8b9bb0; --accent: #3d9cfd; --accent2: #8b5cf6; --ok: #3ecf8e;
      --warn: #f0a848; --bad: #f07178; --line: #26313f;
      --font: "IBM Plex Sans","Segoe UI",system-ui,sans-serif;
      --mono: "IBM Plex Mono",Consolas,monospace;
    }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; color:var(--ink); font-family:var(--font);
      background: radial-gradient(1200px 600px at 8% -10%, #16324e 0%, transparent 55%),
                  radial-gradient(900px 500px at 100% 0%, #241b3a 0%, transparent 50%), var(--bg); }
    a { color: var(--accent); }
    /* Navbar */
    nav { position:sticky; top:0; z-index:20; display:flex; align-items:center; gap:1rem;
      padding:.6rem 1.2rem; background:rgba(12,16,22,.82); backdrop-filter:blur(10px);
      border-bottom:1px solid var(--line); flex-wrap:wrap; }
    .brand { font-weight:700; letter-spacing:.06em; font-size:1.05rem; display:flex; gap:.5rem; align-items:center; }
    .brand .dot { width:9px; height:9px; border-radius:50%; background:var(--muted); box-shadow:0 0 8px currentColor; }
    .brand .dot.ok{ background:var(--ok);} .brand .dot.bad{ background:var(--bad);} .brand .dot.warn{ background:var(--warn);}
    .usage { display:flex; gap:.4rem; flex-wrap:wrap; margin-left:auto; align-items:center; }
    .chip { display:inline-flex; align-items:center; gap:.35rem; font-size:.74rem; padding:.28rem .6rem;
      border:1px solid var(--line); border-radius:999px; background:var(--panel); color:var(--muted); white-space:nowrap; }
    .chip b { color:var(--ink); font-variant-numeric:tabular-nums; font-family:var(--mono); }
    .chip.model b { color:var(--accent); }
    .tabs { display:flex; gap:.25rem; padding:.4rem 1.2rem 0; flex-wrap:wrap; border-bottom:1px solid var(--line);
      background:rgba(12,16,22,.5); position:sticky; top:49px; z-index:19; }
    .tab { padding:.55rem .9rem; cursor:pointer; color:var(--muted); border:1px solid transparent;
      border-bottom:none; border-radius:9px 9px 0 0; font-size:.86rem; }
    .tab:hover { color:var(--ink); }
    .tab.active { color:var(--ink); background:var(--panel); border-color:var(--line); }
    main { padding:1.2rem; max-width:1200px; margin:0 auto; }
    .panel { display:none; }
    .panel.active { display:block; animation:fade .2s ease; }
    @keyframes fade { from{opacity:0; transform:translateY(4px);} to{opacity:1;} }
    .grid { display:grid; gap:1rem; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); }
    section { background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:1.1rem 1.2rem;
      box-shadow:0 12px 40px rgba(0,0,0,.25); margin-bottom:1rem; }
    h2 { margin:0 0 .85rem; font-size:.82rem; text-transform:uppercase; letter-spacing:.09em; color:var(--muted); }
    h3 { margin:.2rem 0 .4rem; font-size:.95rem; }
    label { display:block; font-size:.76rem; color:var(--muted); margin:.65rem 0 .25rem; }
    input, select, textarea { width:100%; background:#0d131b; color:var(--ink); border:1px solid var(--line);
      border-radius:8px; padding:.55rem .7rem; font:inherit; }
    textarea { min-height:150px; font-family:var(--mono); font-size:.85rem; }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:.75rem; }
    .actions { display:flex; gap:.6rem; flex-wrap:wrap; margin-top:1rem; }
    button { border:0; border-radius:999px; padding:.6rem 1.05rem; cursor:pointer; font-weight:600;
      background:var(--accent); color:#041018; }
    button.secondary { background:#26313f; color:var(--ink); }
    button:disabled { opacity:.55; cursor:wait; }
    .stat { background:var(--panel2); border:1px solid var(--line); border-radius:12px; padding:.8rem .9rem; }
    .stat .n { font-size:1.6rem; font-weight:700; font-family:var(--mono); }
    .stat .l { font-size:.72rem; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
    .mono { font-family:var(--mono); font-size:.82rem; white-space:pre-wrap; color:var(--muted); }
    table { width:100%; border-collapse:collapse; font-size:.86rem; }
    th, td { text-align:left; padding:.5rem .4rem; border-bottom:1px solid var(--line); vertical-align:top; }
    th { color:var(--muted); font-weight:600; font-size:.74rem; text-transform:uppercase; letter-spacing:.05em; }
    .bar { height:8px; border-radius:6px; background:var(--panel2); overflow:hidden; }
    .bar > span { display:block; height:100%; background:linear-gradient(90deg,var(--accent),var(--accent2)); }
    .sev { font-weight:700; font-size:.72rem; padding:.15rem .45rem; border-radius:6px; }
    .sev.critical{ background:#3a0e14; color:#ff8a94;} .sev.high{ background:#3a2410; color:#ffbb66;}
    .sev.medium{ background:#33300f; color:#e8d264;} .sev.low{ background:#12253a; color:#7db8f0;} .sev.info{ background:#1c2430; color:var(--muted);}
    .tag { display:inline-block; font-size:.68rem; padding:.1rem .4rem; margin:.1rem .15rem 0 0; border:1px solid var(--line); border-radius:5px; color:var(--muted); }
    details { border:1px solid var(--line); border-radius:10px; padding:.5rem .8rem; margin-bottom:.55rem; background:var(--panel2); }
    details > summary { cursor:pointer; font-weight:600; }
    .think { border-left:3px solid var(--accent2); padding:.4rem .7rem; margin-top:.5rem; background:#0e131c;
      border-radius:0 8px 8px 0; font-family:var(--mono); font-size:.8rem; color:#c6d3e2; white-space:pre-wrap; }
    .muted { color:var(--muted); }
    .pill { display:inline-flex; align-items:center; gap:.4rem; border-radius:999px; padding:.3rem .7rem; font-size:.8rem; border:1px solid var(--line); }
    .pill.ok{ color:var(--ok);} .pill.bad{ color:var(--bad);} .pill.warn{ color:var(--warn);}
    #toast { min-height:1.2rem; color:var(--ok); margin-top:.5rem; font-size:.85rem; }
    .empty { color:var(--muted); padding:1rem 0; }
    .flex { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; }
    .kv { display:grid; grid-template-columns:auto 1fr; gap:.2rem .8rem; font-size:.85rem; }
    .kv .k { color:var(--muted); }
    .step { display:flex; align-items:center; gap:.7rem; padding:.55rem .7rem; border:1px solid var(--line);
      border-radius:10px; margin-bottom:.45rem; background:var(--panel2); }
    .step .idx { width:26px; height:26px; border-radius:50%; display:grid; place-items:center; font-size:.8rem;
      font-weight:700; background:#0d131b; border:1px solid var(--line); color:var(--muted); flex:none; }
    .step.running .idx{ background:var(--accent); color:#041018; border-color:var(--accent); animation:pulse 1.2s infinite; }
    .step.done .idx{ background:var(--ok); color:#041018; border-color:var(--ok); }
    .step.failed .idx{ background:var(--bad); color:#fff; border-color:var(--bad); }
    .step .t { font-weight:600; font-size:.9rem; }
    .step .d { color:var(--muted); font-size:.76rem; }
    .step .ai { color:var(--accent2); font-size:.74rem; }
    .step .el { margin-left:auto; color:var(--muted); font-family:var(--mono); font-size:.76rem; flex:none; }
    @keyframes pulse { 0%,100%{ box-shadow:0 0 0 0 rgba(61,156,253,.5);} 50%{ box-shadow:0 0 0 6px rgba(61,156,253,0);} }
    .chip.run b{ color:var(--warn);} .chip.done b{ color:var(--ok);} .chip.err b{ color:var(--bad);}
  </style>
</head>
<body>
  <nav>
    <div class="brand"><span id="healthDot" class="dot"></span> HunterEngine</div>
    <div class="usage" id="usage">
      <span class="chip model">model <b id="uModel">—</b></span>
      <span class="chip">prompt <b id="uPrompt">0</b></span>
      <span class="chip">completion <b id="uCompletion">0</b></span>
      <span class="chip">total <b id="uTotal">0</b></span>
      <span class="chip">reqs <b id="uReq">0</b></span>
      <span class="chip">think <b id="uThink">0</b></span>
      <span class="chip">latency <b id="uLatency">—</b></span>
      <span class="chip" id="scanChip">scan <b id="uScan">idle</b></span>
    </div>
  </nav>
  <div class="tabs" id="tabs">
    <div class="tab active" data-tab="scan">Scan Control</div>
    <div class="tab" data-tab="overview">Overview</div>
    <div class="tab" data-tab="reasoning">Reasoning &amp; Thinking</div>
    <div class="tab" data-tab="behavior">Behaviour Analysis</div>
    <div class="tab" data-tab="findings">Findings</div>
    <div class="tab" data-tab="learning">Domain Learning</div>
    <div class="tab" data-tab="settings">Settings</div>
    <div class="tab" data-tab="scope">Scope</div>
  </div>

  <main>
    <!-- SCAN CONTROL -->
    <div class="panel active" id="p-scan">
      <section>
        <h2>Run a scan</h2>
        <div class="row">
          <div><label>Target (optional — overrides scope)</label><input id="scanTarget" placeholder="https://app.example.com" /></div>
          <div><label>Profile</label>
            <select id="scanProfile"><option value="blackbox">blackbox</option><option value="greybox">greybox (authorized)</option></select></div>
        </div>
        <label>Phases (optional, comma-separated — blank = full 8-step pipeline)</label>
        <input id="scanPhases" placeholder="recon, scanning, threat_model, vuln_analysis, exploitation, post_exploit, correlation, reporting" />
        <div class="actions">
          <button id="startScanBtn" type="button">▶ Start scan</button>
          <button id="stopScanBtn" class="secondary" type="button" disabled>■ Stop (save)</button>
          <button id="abortScanBtn" class="secondary" type="button" disabled>✕ Abort</button>
          <span id="scanState" class="pill">idle</span>
        </div>
        <div id="scanErr" class="mono" style="color:var(--bad); margin-top:.5rem"></div>
      </section>
      <section>
        <h2>8-step methodology progress</h2>
        <div id="stepper"><div class="empty">Loading methodology…</div></div>
      </section>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <section><h2>Live counts</h2><div class="grid" id="liveCounts"><div class="empty">—</div></div></section>
        <section><h2>Live AI reasoning</h2><div id="liveReason" class="mono">Idle. Start a scan to stream per-phase reasoning.</div></section>
      </div>
    </div>

    <!-- OVERVIEW -->
    <div class="panel" id="p-overview">
      <section>
        <div class="flex" style="justify-content:space-between">
          <h2 style="margin:0">Latest scan</h2>
          <span id="runMeta" class="muted" style="font-size:.8rem"></span>
        </div>
        <div class="grid" id="statGrid" style="margin-top:.8rem"></div>
      </section>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <section>
          <h2>Severity breakdown</h2>
          <div id="sevBreakdown"><div class="empty">No scan data yet — run a scan to populate.</div></div>
        </section>
        <section>
          <h2>AI health</h2>
          <div id="healthSummary" class="mono">Running health check…</div>
          <div class="actions"><button id="healthBtn" class="secondary" type="button">Re-check</button></div>
        </section>
      </div>
      <section>
        <h2>Pipeline phase health</h2>
        <div id="phaseHealth"><div class="empty">No phase telemetry yet.</div></div>
      </section>
    </div>

    <!-- REASONING -->
    <div class="panel" id="p-reasoning">
      <section>
        <h2>Triage reasoning summary</h2>
        <div id="reasonSummary"><div class="empty">No reasoning captured yet. Enable ai.mode=both and run a scan.</div></div>
      </section>
      <section>
        <h2>Autonomous planning decisions</h2>
        <div id="decisions"><div class="empty">No planner decisions recorded.</div></div>
      </section>
      <section>
        <h2>Model thinking traces <span class="muted" id="traceCount"></span></h2>
        <div id="traces"><div class="empty">Thinking traces from Qwen3 appear here after an AI scan phase.</div></div>
      </section>
    </div>

    <!-- BEHAVIOR -->
    <div class="panel" id="p-behavior">
      <section>
        <h2>Attack surface &amp; posture</h2>
        <div id="behaviorTop"><div class="empty">Run a scan through the ai_test phase to build a behaviour model.</div></div>
      </section>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <section><h2>Prioritized focus areas</h2><div id="focusAreas" class="empty">—</div></section>
        <section><h2>Hypotheses</h2><div id="hypotheses" class="empty">—</div></section>
      </div>
      <section><h2>Top parameters &amp; methods</h2><div id="behaviorStructure" class="empty">—</div></section>
    </div>

    <!-- FINDINGS -->
    <div class="panel" id="p-findings">
      <section>
        <div class="flex" style="justify-content:space-between">
          <h2 style="margin:0">Findings</h2>
          <div class="flex">
            <select id="sevFilter" style="width:auto"><option value="">all severities</option>
              <option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
          </div>
        </div>
        <div id="findingsList" style="margin-top:.7rem"><div class="empty">No findings loaded.</div></div>
      </section>
    </div>

    <!-- LEARNING -->
    <div class="panel" id="p-learning">
      <section><h2>Learning analytics</h2><div class="grid" id="learnStats"><div class="empty">No profiles yet.</div></div></section>
      <div class="grid" style="grid-template-columns:1fr 1fr">
        <section><h2>Most effective vuln classes</h2><div id="topClasses" class="empty">—</div></section>
        <section><h2>Preferred hunters (global)</h2><div id="topHunters" class="empty">—</div></section>
      </div>
      <section><h2>Per-domain profiles</h2><div id="domains"><div class="empty">Loading…</div></div></section>
    </div>

    <!-- SETTINGS -->
    <div class="panel" id="p-settings">
      <section>
        <h2>AI settings</h2>
        <div class="row">
          <div><label>AI enabled</label>
            <select id="aiEnabled"><option value="true">true</option><option value="false">false</option></select></div>
          <div><label>Mode</label>
            <select id="aiMode"><option value="testing">testing</option><option value="triage">triage</option><option value="both">both</option></select></div>
        </div>
        <div class="row">
          <div><label>Provider</label>
            <select id="provider"><option value="ollama">ollama</option><option value="openai-compatible">openai-compatible</option><option value="lmstudio">lmstudio</option></select></div>
          <div><label>Testing model</label><input id="model" placeholder="qwen3:4b" /></div>
        </div>
        <label>Ollama / OpenAI base URL (external)</label>
        <input id="baseUrl" placeholder="http://127.0.0.1:11434" />
        <div class="row">
          <div><label>Think / reasoning</label>
            <select id="think"><option value="true">true</option><option value="false">false</option></select></div>
          <div><label>Planner deadline (seconds)</label><input id="plannerDeadline" type="number" min="3" step="1" /></div>
        </div>
        <label>Subagents (comma-separated)</label>
        <input id="subagents" />
        <div class="actions">
          <button id="saveBtn" type="button">Save settings</button>
          <button id="healthBtn2" class="secondary" type="button">Health check</button>
        </div>
        <div id="toast"></div>
      </section>
    </div>

    <!-- SCOPE -->
    <div class="panel" id="p-scope">
      <section>
        <h2>Scope (JSON view of scope.yaml)</h2>
        <textarea id="scopeYaml" spellcheck="false"></textarea>
        <div class="actions">
          <button id="saveScopeBtn" type="button">Save scope</button>
          <button id="reloadScopeBtn" class="secondary" type="button">Reload</button>
        </div>
        <div id="toastScope" class="mono" style="margin-top:.5rem"></div>
      </section>
    </div>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    const esc = (s) => String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    const fmt = (n) => (n ?? 0).toLocaleString();
    const toast = (m) => { $("toast").textContent = m; };

    // ── Tabs ──
    document.querySelectorAll(".tab").forEach(t => t.onclick = () => {
      document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(x => x.classList.remove("active"));
      t.classList.add("active");
      $("p-" + t.dataset.tab).classList.add("active");
    });

    // ── Navbar usage (polled) ──
    let lastLatency = "—";
    async function refreshUsage() {
      try {
        const u = await fetch("/api/usage").then(r => r.json());
        $("uModel").textContent = u.model || "—";
        const g = u.usage || {};
        $("uPrompt").textContent = fmt(g.prompt_tokens || g.prompt_tokens_estimated || 0);
        $("uCompletion").textContent = fmt(g.completion_tokens || 0);
        $("uTotal").textContent = fmt(g.total_tokens || 0);
        $("uReq").textContent = fmt(g.requests || 0) + "/" + fmt(g.requests_started || 0);
        $("uThink").textContent = fmt(g.thinking_chars || 0);
        $("uLatency").textContent = lastLatency;
      } catch (e) { /* ignore */ }
    }

    // ── Health ──
    async function healthCheck() {
      [$("healthBtn"), $("healthBtn2")].forEach(b => b && (b.disabled = true));
      $("healthSummary").textContent = "Probing…";
      $("healthDot").className = "dot warn";
      try {
        const h = await fetch("/api/health/ai").then(r => r.json());
        const ok = !!h.ok;
        $("healthDot").className = "dot " + (ok ? "ok" : "bad");
        lastLatency = (h.testing?.latency_ms ?? "—") + " ms";
        $("uLatency").textContent = lastLatency;
        $("healthSummary").textContent = [
          `overall: ${ok ? "OK" : "FAIL"}`,
          `provider: ${h.config?.provider}   model: ${h.config?.testing_model}`,
          `base_url: ${h.config?.testing_base_url}`,
          `daemon: ${h.testing?.ok ? "ok" : "fail"}   latency: ${h.testing?.latency_ms ?? "?"} ms`,
          `models: ${(h.testing?.models || []).slice(0,8).join(", ") || "(none)"}`,
          `chat_probe: ${h.chat_probe?.ok ? "ok" : "fail"}   reply: ${JSON.stringify(h.chat_probe?.reply || "")}`,
          `error: ${h.testing?.error || h.chat_probe?.error || "(none)"}`,
          `hints: ${(h.hints || []).join(" | ")}`,
        ].join("\n");
      } catch (e) {
        $("healthDot").className = "dot bad";
        $("healthSummary").textContent = String(e);
      } finally {
        [$("healthBtn"), $("healthBtn2")].forEach(b => b && (b.disabled = false));
      }
    }

    // ── Overview ──
    function statCard(n, l) { return `<div class="stat"><div class="n">${fmt(n)}</div><div class="l">${l}</div></div>`; }
    async function loadOverview() {
      const r = await fetch("/api/run").then(x => x.json());
      if (!r.available) { $("statGrid").innerHTML = `<div class="empty">No checkpoint found. Run: <code>python main.py scan</code></div>`; return; }
      const c = r.counts || {};
      $("runMeta").textContent = `phase: ${r.phase || "?"} · saved ${r.saved_at ? new Date(r.saved_at).toLocaleString() : "?"} · reason ${r.reason || "?"}`;
      $("statGrid").innerHTML = [
        statCard(c.live_hosts, "Live hosts"), statCard(c.endpoints, "Endpoints"),
        statCard(c.findings, "Findings"), statCard(c.weak_signals, "Weak signals"),
        statCard(r.ai_test_probes, "AI probes"), statCard(c.errors, "Errors"),
      ].join("");
      // severity
      const sev = r.severity_counts || {};
      const order = ["critical","high","medium","low","info"];
      const total = Object.values(sev).reduce((a,b)=>a+b,0);
      $("sevBreakdown").innerHTML = total ? order.filter(s=>sev[s]).map(s => `
        <div style="margin:.5rem 0"><div class="flex" style="justify-content:space-between">
          <span class="sev ${s}">${s.toUpperCase()}</span><b>${sev[s]}</b></div>
          <div class="bar" style="margin-top:.3rem"><span style="width:${Math.round(100*sev[s]/total)}%"></span></div></div>`).join("")
        : `<div class="empty">No findings.</div>`;
      // phase health
      const ph = r.phase_health || {};
      const keys = Object.keys(ph);
      $("phaseHealth").innerHTML = keys.length ? `<table><tr><th>Phase</th><th>Status</th><th>Elapsed</th><th>Error</th></tr>` +
        keys.map(k => `<tr><td>${esc(k)}</td><td>${ph[k].status==="ok"?'<span class="pill ok">ok</span>':'<span class="pill bad">'+esc(ph[k].status)+'</span>'}</td>
          <td>${ph[k].elapsed ?? "—"}s</td><td class="muted">${esc((ph[k].error||"").slice(0,80))}</td></tr>`).join("") + `</table>`
        : `<div class="empty">No phase telemetry yet.</div>`;
    }

    // ── Reasoning ──
    async function loadReasoning() {
      const r = await fetch("/api/reasoning").then(x => x.json());
      if (!r.available) return;
      const s = r.summary || {};
      $("reasonSummary").innerHTML = (s.reviewed !== undefined) ? `
        <div class="kv">
          <span class="k">mode</span><span>${esc(s.mode||"—")}</span>
          <span class="k">findings reviewed</span><span>${s.reviewed||0}</span>
          <span class="k">traces captured</span><span>${s.traces_captured||0}</span>
        </div>
        ${(s.top_risks||[]).length ? `<h3 style="margin-top:.8rem">Top risks</h3><table><tr><th>Title</th><th>Sev</th><th>Conf</th><th>Prio</th></tr>` +
          s.top_risks.map(t => `<tr><td>${esc(t.title)}</td><td><span class="sev ${esc(t.severity)}">${esc(t.severity)}</span></td>
            <td>${Math.round((t.confidence||0)*100)}%</td><td>${esc(t.priority||"—")}</td></tr>`).join("") + `</table>` : ""}
        ${(s.needs_review||[]).length ? `<h3 style="margin-top:.8rem">Needs manual review</h3>` + s.needs_review.map(x=>`<span class="tag">${esc(x)}</span>`).join("") : ""}
        ` : `<div class="empty">No triage summary in the latest run.</div>`;

      const d = r.decisions || [];
      $("decisions").innerHTML = d.length ? `<table><tr><th>Action</th><th>Priority</th><th>Rationale</th></tr>` +
        d.map(x => `<tr><td><b>${esc(x.action)}</b></td><td>${(x.priority??0).toFixed ? x.priority.toFixed(2) : x.priority}</td>
          <td class="muted">${esc(x.rationale)}${(x.evidence||[]).length?'<br><span class="tag">'+x.evidence.map(esc).join('</span> <span class="tag">')+'</span>':''}</td></tr>`).join("") + `</table>`
        : `<div class="empty">No planner decisions recorded.</div>`;

      const t = r.traces || [];
      $("traceCount").textContent = t.length ? `(${t.length})` : "";
      $("traces").innerHTML = t.length ? t.slice().reverse().map(tr => `
        <details><summary>${esc(tr.agent||tr.model||"model")} <span class="muted">· ${esc(tr.phase||"")} ${tr.finding?("· "+esc(tr.finding)):""}</span></summary>
          <div class="think">${esc(tr.text||"")}</div></details>`).join("")
        : `<div class="empty">No thinking traces captured. Ensure the model runs with think=true.</div>`;
    }

    // ── Behavior ──
    async function loadBehavior() {
      const r = await fetch("/api/behavior").then(x => x.json());
      const b = r.behavior || {};
      if (!b || !Object.keys(b).length) return;
      const ap = b.auth_posture || {};
      $("behaviorTop").innerHTML = `
        <div class="grid">
          ${statCard(b.endpoint_total, "Endpoints")}
          ${statCard(b.parameterized_endpoints, "Parameterized")}
          ${statCard(b.object_reference_endpoints, "Object refs (IDOR)")}
          ${statCard(b.state_changing_endpoints, "State-changing")}
          <div class="stat"><div class="n">${b.risk_score ?? 0}</div><div class="l">Risk score</div></div>
          <div class="stat"><div class="n" style="font-size:1rem">${esc(ap.posture||"?")}</div><div class="l">Auth posture</div></div>
        </div>
        ${(b.mechanisms||[]).length?'<div style="margin-top:.6rem">Auth: '+b.mechanisms.map(m=>`<span class="tag">${esc(m)}</span>`).join("")+'</div>':''}
        ${(b.waf_signals||[]).length?'<div style="margin-top:.4rem">WAF: '+b.waf_signals.map(m=>`<span class="tag">${esc(m)}</span>`).join("")+'</div>':''}`;

      const fa = b.focus_areas || [];
      $("focusAreas").className = fa.length ? "" : "empty";
      $("focusAreas").innerHTML = fa.length ? `<table><tr><th>Area</th><th>Score</th><th>Hunters</th><th>Why</th></tr>` +
        fa.map(a => `<tr><td><b>${esc(a.area)}</b></td><td>${a.score}</td><td>${(a.suggest_hunters||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join("")}</td>
          <td class="muted">${esc(a.why)}</td></tr>`).join("") + `</table>` : "No scored surface.";

      const hy = b.behavior_hypotheses || [];
      $("hypotheses").className = hy.length ? "" : "empty";
      $("hypotheses").innerHTML = hy.length ? "<ul style='margin:.2rem 0 0 .9rem; padding:0'>" + hy.map(h=>`<li style="margin:.3rem 0">${esc(h)}</li>`).join("") + "</ul>" : "No hypotheses.";

      const tp = b.top_parameters || {};
      const md = b.method_distribution || {};
      $("behaviorStructure").className = "";
      $("behaviorStructure").innerHTML = `
        <div class="grid" style="grid-template-columns:1fr 1fr">
          <div><h3>Top parameters</h3>${Object.keys(tp).length? Object.entries(tp).map(([k,v])=>`<div class="flex" style="justify-content:space-between"><span class="mono">${esc(k)}</span><b>${v}</b></div>`).join("") : '<span class="muted">none</span>'}</div>
          <div><h3>HTTP methods</h3>${Object.keys(md).length? Object.entries(md).map(([k,v])=>`<div class="flex" style="justify-content:space-between"><span class="mono">${esc(k)}</span><b>${v}</b></div>`).join("") : '<span class="muted">none</span>'}</div>
        </div>`;
    }

    // ── Findings ──
    let allFindings = [];
    function renderFindings() {
      const filt = $("sevFilter").value;
      const rows = allFindings.filter(f => !filt || String(f.severity||"info").toLowerCase() === filt);
      if (!rows.length) { $("findingsList").innerHTML = `<div class="empty">No findings${filt?" for "+filt:""}.</div>`; return; }
      $("findingsList").innerHTML = rows.map(f => {
        const ai = (f.metadata && f.metadata.ai_analysis) || {};
        const sev = String(f.severity||"info").toLowerCase();
        return `<details>
          <summary><span class="sev ${sev}">${sev.toUpperCase()}</span> ${esc(f.title||"Untitled")}
            <span class="muted">· ${Math.round((f.confidence||0)*100)}% · ${esc(f.detector||"")}</span></summary>
          <div style="margin-top:.5rem" class="kv">
            ${f.url?`<span class="k">url</span><span class="mono">${esc(f.url)}</span>`:""}
            ${f.parameter?`<span class="k">param</span><span class="mono">${esc(f.parameter)}</span>`:""}
            ${ai.exploitability?`<span class="k">exploitability</span><span>${esc(ai.exploitability)}</span>`:""}
            ${ai.impact_area?`<span class="k">impact</span><span>${esc(ai.impact_area)}</span>`:""}
            ${ai.false_positive_risk?`<span class="k">FP risk</span><span>${esc(ai.false_positive_risk)}</span>`:""}
            ${f.ai_priority?`<span class="k">priority</span><span>${esc(f.ai_priority)}</span>`:""}
          </div>
          ${f.description?`<p class="muted" style="margin:.5rem 0 0">${esc(String(f.description).slice(0,400))}</p>`:""}
          ${(ai.reasoning_steps||[]).length?`<div class="think">${ai.reasoning_steps.map((s,i)=>`${i+1}. ${esc(s)}`).join("\n")}</div>`:""}
          ${ai.rationale?`<p style="margin:.5rem 0 0"><b>Verdict:</b> <span class="muted">${esc(ai.rationale)}</span></p>`:""}
          ${(f.ai_validation_steps||ai.recommended_validation||[]).length?`<p style="margin:.5rem 0 0"><b>Validate:</b></p><ul style="margin:.2rem 0 0 .9rem">${(f.ai_validation_steps||ai.recommended_validation).map(s=>`<li class="muted">${esc(s)}</li>`).join("")}</ul>`:""}
          ${f.remediation?`<p style="margin:.5rem 0 0"><b>Fix:</b> <span class="muted">${esc(String(f.remediation).slice(0,400))}</span></p>`:""}
          ${(f.tags||[]).length?`<div style="margin-top:.5rem">${f.tags.map(t=>`<span class="tag">${esc(t)}</span>`).join("")}</div>`:""}
        </details>`;
      }).join("");
    }
    async function loadFindings() {
      const r = await fetch("/api/findings").then(x => x.json());
      allFindings = (r.findings || []).filter(f => f && typeof f === "object");
      renderFindings();
    }
    $("sevFilter").onchange = renderFindings;

    // ── Learning ──
    async function loadLearning() {
      const r = await fetch("/api/domains").then(x => x.json());
      const a = r.analytics || {};
      $("learnStats").innerHTML = [
        statCard(a.domains, "Domains learned"), statCard(a.total_scans, "Total scans"),
        statCard(a.total_findings, "Total findings"),
        `<div class="stat"><div class="n">${a.avg_success_rate ?? 0}</div><div class="l">Avg findings/scan</div></div>`,
      ].join("");
      $("topClasses").className = (a.top_classes||[]).length ? "" : "empty";
      $("topClasses").innerHTML = (a.top_classes||[]).length ? (a.top_classes).map(c=>`<div class="flex" style="justify-content:space-between; margin:.25rem 0"><span>${esc(c.class)}</span><b>${c.count}</b></div>`).join("") : "No data.";
      $("topHunters").className = (a.top_hunters||[]).length ? "" : "empty";
      $("topHunters").innerHTML = (a.top_hunters||[]).length ? (a.top_hunters).map(c=>`<div class="flex" style="justify-content:space-between; margin:.25rem 0"><span>${esc(c.hunter)}</span><b>${c.score}</b></div>`).join("") : "No data.";

      const rows = r.profiles || [];
      $("domains").innerHTML = rows.length ? `<table><tr><th>Domain</th><th>Scans</th><th>Findings</th><th>Rate</th><th>Risk</th><th>Preferred hunters</th><th>Focus</th></tr>` +
        rows.map(p => `<tr><td class="mono">${esc(p.domain)}</td><td>${p.scan_count||0}</td><td>${p.total_findings||0}</td>
          <td>${p.success_rate||0}</td><td>${p.risk_score||0}</td>
          <td>${(p.preferred_subagents||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join("")||"—"}</td>
          <td>${(p.focus_areas||[]).map(h=>`<span class="tag">${esc(h)}</span>`).join("")||"—"}</td></tr>`).join("") + `</table>`
        : `<div class="empty">No domain profiles yet. Run a scan to start learning.</div>`;
    }

    // ── Settings & scope ──
    async function loadSettings() {
      const s = await fetch("/api/settings").then(r => r.json());
      const ai = s.ai || {}; const tm = ai.testing_model || ai.local_model || {}; const testing = ai.testing || {};
      $("aiEnabled").value = String(!!ai.enabled);
      $("aiMode").value = ai.mode || "testing";
      $("provider").value = ai.provider || "ollama";
      $("model").value = tm.model || "qwen3:4b";
      $("baseUrl").value = tm.base_url || "http://127.0.0.1:11434";
      $("think").value = String(tm.think !== false);
      $("plannerDeadline").value = testing.planner_deadline ?? 25;
      $("subagents").value = (testing.subagents || []).join(", ");
    }
    async function saveSettings() {
      const body = { ai: {
        enabled: $("aiEnabled").value === "true", mode: $("aiMode").value, provider: $("provider").value,
        testing_model: { base_url: $("baseUrl").value.trim(), model: $("model").value.trim(), think: $("think").value === "true" },
        local_model: { base_url: $("baseUrl").value.trim(), model: $("model").value.trim() },
        testing: { enabled: true, planner_deadline: Number($("plannerDeadline").value || 25),
          subagents: $("subagents").value.split(",").map(s => s.trim()).filter(Boolean) } } };
      const res = await fetch("/api/settings", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body) }).then(r => r.json());
      toast(res.ok ? "Settings saved to config/settings.yaml" : "Save failed");
      refreshUsage();
    }
    async function loadScope() {
      const scope = await fetch("/api/scope").then(r => r.json());
      $("scopeYaml").value = JSON.stringify(scope, null, 2);
    }
    async function saveScope() {
      let parsed;
      try { parsed = JSON.parse($("scopeYaml").value); }
      catch (e) { $("toastScope").textContent = "Scope editor expects JSON. Fix and retry."; return; }
      const res = await fetch("/api/scope", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(parsed) }).then(r => r.json());
      $("toastScope").textContent = res.ok ? "Scope saved to scope.yaml" : "Scope save failed";
    }

    $("saveBtn").onclick = saveSettings;
    $("saveScopeBtn").onclick = saveScope;
    $("reloadScopeBtn").onclick = loadScope;
    $("healthBtn").onclick = healthCheck;
    $("healthBtn2").onclick = healthCheck;

    // ── Scan control ──
    let methodology = [];
    let scanPoll = null;
    async function loadMethodology() {
      const r = await fetch("/api/methodology").then(x => x.json());
      methodology = r.steps || [];
      renderStepper({});
    }
    function renderStepper(byPhase) {
      if (!methodology.length) { $("stepper").innerHTML = `<div class="empty">No methodology.</div>`; return; }
      $("stepper").innerHTML = methodology.map((s, i) => {
        // a step is running/done/failed if any of its runner phases is
        const statuses = (s.runners || []).map(r => (byPhase[r] || {}).status).filter(Boolean);
        let cls = "pending";
        if (statuses.includes("running")) cls = "running";
        else if (statuses.includes("failed")) cls = "failed";
        else if (statuses.length && statuses.every(x => x === "done")) cls = "done";
        const el = (s.runners || []).map(r => (byPhase[r] || {}).elapsed).filter(x => x != null).reduce((a,b)=>a+b,0);
        return `<div class="step ${cls}"><div class="idx">${cls==="done"?"✓":cls==="failed"?"!":i+1}</div>
          <div><div class="t">${esc(s.title)}</div><div class="d">${esc(s.summary)}</div><div class="ai">🧠 ${esc(s.ai_role)}</div></div>
          ${el?`<div class="el">${el.toFixed(1)}s</div>`:""}</div>`;
      }).join("");
    }
    function setScanButtons(running) {
      $("startScanBtn").disabled = running;
      $("stopScanBtn").disabled = !running;
      $("abortScanBtn").disabled = !running;
    }
    async function startScan() {
      $("scanErr").textContent = "";
      const body = { target: $("scanTarget").value.trim(), profile: $("scanProfile").value,
        phases: $("scanPhases").value.trim() };
      const res = await fetch("/api/scan/start", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body) });
      if (!res.ok) { const e = await res.json().catch(()=>({detail:"failed"})); $("scanErr").textContent = "Start failed: " + (e.detail || res.status); return; }
      setScanButtons(true);
      startPolling();
    }
    async function stopScan(save) {
      await fetch("/api/scan/stop", { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({save}) });
    }
    function startPolling() { if (!scanPoll) scanPoll = setInterval(pollScan, 2000); pollScan(); }
    async function pollScan() {
      let s;
      try { s = await fetch("/api/scan/status").then(x => x.json()); } catch(e) { return; }
      const running = !!s.running;
      const outcome = s.outcome || "idle";
      $("uScan").textContent = running ? (s.phase || "running") : outcome;
      $("scanChip").className = "chip " + (running ? "run" : outcome === "completed" ? "done" : (outcome==="error"||outcome==="stopped") ? "err" : "");
      $("scanState").textContent = running ? `running · ${s.phase || "?"} · ${Math.round(s.elapsed||0)}s` : outcome;
      $("scanState").className = "pill " + (running ? "warn" : outcome==="completed" ? "ok" : (outcome==="error"||outcome==="stopped")?"bad":"");
      if (s.error) $("scanErr").textContent = s.error;
      setScanButtons(running);

      const byPhase = {};
      (s.progress || []).forEach(p => byPhase[p.phase] = p);
      renderStepper(byPhase);

      const c = s.counts || {};
      $("liveCounts").innerHTML = [statCard(c.live_hosts,"Live hosts"), statCard(c.endpoints,"Endpoints"),
        statCard(c.findings,"Findings"), statCard(c.weak_signals,"Weak signals")].join("");

      const dec = s.recent_decisions || [];
      const tr = s.recent_traces || [];
      $("liveReason").textContent = [
        ...dec.map(d => `▸ [${(d.action||"").replace("phase:","")}] ${d.rationale||""}`),
        ...tr.map(t => `🧠 (${t.agent||t.phase}) ${(t.text||"").slice(0,200)}`),
      ].join("\n") || "…";

      if (!running) {
        clearInterval(scanPoll); scanPoll = null;
        // Refresh the read-only views from the freshly written checkpoint.
        loadOverview(); loadReasoning(); loadBehavior(); loadFindings(); loadLearning(); refreshUsage();
      }
    }
    $("startScanBtn").onclick = startScan;
    $("stopScanBtn").onclick = () => stopScan(true);
    $("abortScanBtn").onclick = () => stopScan(false);

    // ── Boot ──
    async function boot() {
      await Promise.all([loadMethodology(), loadSettings(), loadScope(), loadOverview(), loadReasoning(),
        loadBehavior(), loadFindings(), loadLearning(), refreshUsage()]);
      healthCheck();
      setInterval(refreshUsage, 8000);
      // Reattach to an in-progress scan (e.g. after a page reload).
      try { const s = await fetch("/api/scan/status").then(x=>x.json()); if (s.running) startPolling(); } catch(e){}
    }
    boot();
  </script>
</body>
</html>
"""
