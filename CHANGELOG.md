# Changelog

All notable changes to HunterEngine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2025-07-08

### Added
- **GUI Web Dashboard** — Real-time scan monitoring, findings browser, crawl map, and settings editor via Flask + WebSocket
- **Auto-Crawl Browser Navigator** — Playwright-based autonomous crawler that self-navigates targets: clicks links, fills forms, intercepts XHR/fetch, and explores SPAs
- `python main.py gui` command to launch the web dashboard
- GitHub-ready project structure: README, LICENSE, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
- `pyproject.toml` for modern Python packaging
- GitHub Actions CI pipeline
- Issue and PR templates

### Changed
- Orchestrator now emits real-time events for GUI consumption
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
