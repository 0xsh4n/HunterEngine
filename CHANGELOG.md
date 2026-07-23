# Changelog

All notable changes to HunterEngine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.2.0] — 2026-07-23

### Added
- **MCP server** (`python main.py mcp`, `integrations/mcp_server.py`) — expose HunterEngine to **Claude Desktop / Claude Code** as MCP tools so Claude drives the engine (start/stop/status scans, then read findings, reasoning, behaviour, and domain learning back). Tools: `methodology`, `get_scope`, `ai_health`, `start_scan`, `scan_status`, `stop_scan`, `run_summary`, `list_findings`, `get_reasoning`, `get_behavior`, `list_domains`. Optional `mcp` extra (`pip install -e ".[mcp]"`); tool logic is transport-independent and unit-tested without the SDK
- **Classic 8-step methodology** — pipeline reorganized into Recon → Scanning/Enumeration → Threat Modeling → Vulnerability Analysis → Exploitation → Post-Exploitation → Correlation → Reporting (`core/methodology.py` as the single source of truth; classic step names available as `--phase` aliases)
- **AI in every phase** — `ai/phase_reasoner.py` emits an explainable decision + rationale before each phase (deterministic by default; optional local LLM via `ai.phase_reasoning: true`), recorded to scan state for the dashboard/report
- **Dashboard scan control** — start / stop / abort scans from the web console (`dashboard/scan_manager.py` runs the orchestrator in a background thread; cooperative stop via the ScanController) with a live 8-step progress stepper, live counts, and streaming per-phase reasoning; new API: `/api/scan/start`, `/api/scan/stop`, `/api/scan/status`, `/api/methodology`
- **Faster, behaviour-driven detection** — detectors are ranked by the threat model's focus areas + auth mechanisms and run **concurrently** (bounded) instead of sequentially; opt-in `detection.behaviour_driven` prunes low-relevance detectors (cheap passive baseline always runs)
- **Non-destructive post-exploitation** (`ai/impact.py`) — ranks blast radius, attacker gain, and same-host chain/escalation paths without sending traffic; annotates findings and records a reasoning trace
- **Explainable reasoning** — the AI client captures the model's thinking traces (Ollama `thinking`, OpenAI-compat `reasoning_content`, and leaked `<think>` blocks) instead of discarding them; retained on scan state and persisted in checkpoints
- **Step-by-step triage** in `LocalAIReasoner` (evidence → vuln class → exploitability → impact → FP risk → verdict); findings gain `reasoning_steps`, `exploitability`, `impact_area`, `attack_prerequisites`, plus a per-run reasoning summary
- **Operational web dashboard** — 7 tabs (Overview, Reasoning & Thinking, Behaviour Analysis, Findings, Domain Learning, Settings, Scope) reading the latest checkpoint, with a **live AI-usage navbar** (model, tokens, requests, thinking chars, latency, health)
- New dashboard API: `/api/run`, `/api/usage`, `/api/reasoning`, `/api/behavior`, `/api/findings`, enriched `/api/domains`
- **Scored behaviour analysis** — attack-surface scoring across sensitive categories, object-reference (IDOR) and state-changing detection, auth posture, top parameters, and a ranked focus-area plan
- **Learning analytics** — domain profiles track success rate, hit rate, risk score, per-class effectiveness, and finding-history trends; new `DomainLearner.analytics()` aggregate
- CLI `print_results` now shows reasoning-trace/thinking counts and an AI reasoning summary
- Tests: `tests/test_reasoning_traces.py` (thinking extraction, trace capture, deeper triage, behaviour scoring, dashboard run-loader)

### Fixed
- Test suite: `pytest-asyncio` config consolidated into `pyproject.toml`; removed the duplicate `[tool:pytest]` block in `setup.cfg` that triggered an "ignoring pytest config" warning and left async health-check tests unrun

### Changed
- Checkpoint save/restore carry `ai_reasoning_traces`, `ai_reasoning_summary`, and `impact_assessments`
- Threat modeling (behaviour analysis + agentic planning) is now its own phase, ahead of detection and exploitation, so detectors can be behaviour-driven
- README documents the 8-step methodology, dashboard scan control, AI-in-every-phase, faster detection, and scored behaviour/learning analytics

## [3.1.0] — 2026-07-22

### Added
- **Web dashboard** (`python main.py dashboard`) for settings/scope + AI Health check button
- **`ai-health` CLI** — daemon reachability, model install check, optional chat probe
- **Docker / Compose** — HunterEngine containerized; **Ollama stays external** via `OLLAMA_BASE_URL`
- **Per-domain learning** (`memory/domain_learner.py`) — behaviour profiles improve hunter order and path ranking
- **`domains` CLI** — list learned domain profiles
- Richer `ai.behavior` signals (API surface, WAF hints, method/status distribution)

### Fixed
- Ollama `available()` / health check: model-install probe was dead code after `return False`, so healthy endpoints were treated as down
- Default Ollama URL no longer points at a private LAN IP; `OLLAMA_BASE_URL` overrides YAML for Docker

### Changed
- README documents dashboard, Docker (external Ollama), health checks, and domain learning
- `main.py` exposes dashboard / ai-health / domains / knowledge / checkpoints alongside scan pipeline

## [3.0.0] — 2026-07-18

### Added
- **Hierarchical agents** — `ReconAgent`, `ActiveReconAgent`, `EnumerationAgent`, `VulnHuntAgent`
- **Nested vuln hunters** — SSTI, request smuggling, CORS, JWT (plus existing XSS/IDOR/SSRF/auth/open redirect)
- **`active_recon` phase** — live probing + tech fingerprint as its own pipeline stage
- Phase aliases: `enumeration`/`enum` → crawl, `vuln`/`vuln_hunt` → ai_test
- **httpx resolution table** in `check-tools` (pip library vs ProjectDiscovery binary)
- Scope/live-host **seeding** so `--phase ai_test` does not exit empty when crawl was skipped

### Changed
- Version bump to **3.0.0**
- Orchestrator runs recon/crawl/ai_test through agents instead of inline module calls
- Hardened `tool_resolver` to ignore pip `httpx` CLIs (venv + Windows Scripts)
- README rewritten for v3 agent architecture, flags, and AI testing

### Fixed
- `--phase ai_test` finishing immediately with no endpoints
- ProjectDiscovery httpx colliding with the pip `httpx` console script on PATH

## [2.0.0] — 2025-07-08

### Added
- **Auto-Crawl Browser Navigator** — Playwright-based autonomous crawler
- GitHub-ready project structure: README, LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
- `pyproject.toml` for modern Python packaging
- GitHub Actions CI pipeline
- Issue and PR templates

### Changed
- Crawl phase integrates auto-navigator alongside external tools
- Updated banner to v2.0.0

## [1.0.0] — 2025-07-08

### Added
- Initial release with full scan pipeline: Scope → Recon → Crawl → Detect → Correlate → AI → Report
- 15 detection modules (XSS, CORS, SSRF, IDOR, JWT, Prototype Pollution, etc.)
- Local AI triage via Ollama / OpenAI-compatible providers
- Adaptive rate limiter with WAF bypass
- Embedded mitmproxy for request interception
- Playwright browser engine for SPA rendering
- Vulnerability chaining engine
- Multi-format reporting (Markdown, HTML, HackerOne, Bugcrowd)
- Pattern memory database across scan sessions
