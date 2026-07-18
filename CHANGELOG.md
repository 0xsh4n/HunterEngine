# Changelog

All notable changes to HunterEngine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
