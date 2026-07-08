<p align="center">
  <pre align="center">
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  ███████╗███╗   ██╗ ██████╗ ██╗███╗   ██╗███████╗
  ██╔════╝████╗  ██║██╔════╝ ██║████╗  ██║██╔════╝
  █████╗  ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║█████╗
  ██╔══╝  ██║╚██╗██║██║   ██║██║██║╚██╗██║██╔══╝
  ███████╗██║ ╚████║╚██████╔╝██║██║ ╚████║███████╗
  ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚══════╝
  </pre>
</p>

<p align="center">
  <strong>Automated Bug Bounty Reconnaissance & Vulnerability Detection Engine</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-2.0.0-orange?style=flat-square" alt="Version 2.0.0">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

## ⚠️ Legal Disclaimer

> **HunterEngine is designed exclusively for authorized security testing.**
> Only use this tool against targets you have **explicit written permission** to test.
> Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## 🔍 What is HunterEngine?

HunterEngine is an **all-in-one automated bug bounty engine** that performs full-pipeline reconnaissance, vulnerability detection, and AI-powered triage — from subdomain enumeration to report generation.

### ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🕷️ **Integrated Browser Auto-Crawl** | OWASP ZAP–style visible browser that auto-navigates targets: clicks links, fills forms, intercepts XHR/fetch/WebSocket traffic, discovers SPA routes |
| 🔎 **Full Recon Pipeline** | Subdomain enumeration → DNS resolution → live probing → tech fingerprinting → historical URL collection |
| 🛡️ **15 Detection Modules** | XSS, CORS, SSRF, IDOR, JWT, Prototype Pollution, GraphQL, Auth flaws, Open Redirect, CSP, Subdomain Takeover, Race Conditions, Secrets, Dependencies, Crypto |
| 🤖 **Local AI Triage** | Ollama / OpenAI-compatible LLM reviews findings, adjusts confidence scores, writes report summaries, and suggests safe validation steps |
| 🔗 **Vulnerability Chaining** | Automatically chains weak signals into higher-severity composite findings (e.g., Open Redirect + XSS → P1) |
| 🌐 **Embedded Proxy** | mitmproxy-based intercepting proxy with request history, replay, and passive analysis |
| ⚡ **Adaptive Rate Limiting** | Token-bucket rate limiter with automatic WAF/429 backoff |
| 🛡️ **WAF Bypass** | User-agent rotation, referrer spoofing, TLS fingerprint impersonation |
| 📊 **Multi-Format Reports** | Markdown, HTML, HackerOne, and Bugcrowd formatted reports |
| 💾 **Pattern Memory** | SQLite-backed cross-session pattern storage for trend detection |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      HunterEngine v2.0.0                     │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐ │
│  │  Scope   │──▶│   Recon   │──▶│  Crawl   │──▶│  Detect  │ │
│  │ Loader   │   │           │   │          │   │          │ │
│  └─────────┘   │• Subdomains│   │• Katana  │   │• XSS     │ │
│                │• DNS       │   │• GoSpider│   │• CORS    │ │
│                │• Live Probe│   │• JS Crawl│   │• SSRF    │ │
│                │• Historical│   │• Auto-   │   │• JWT     │ │
│                │• Tech FP   │   │  Navigator   │• IDOR    │ │
│                └───────────┘   │  (ZAP-   │   │• 10 more │ │
│                                │   style)  │   └──────────┘ │
│                                └──────────┘         │       │
│                                      │              ▼       │
│                                      │       ┌──────────┐   │
│  ┌─────────┐   ┌───────────┐         │       │Correlate │   │
│  │  Report  │◀──│  AI Triage│◀────────┴───────│& Chain   │   │
│  │          │   │  (Ollama) │                 └──────────┘   │
│  │• Markdown│   └───────────┘                               │
│  │• HTML    │                                               │
│  │• H1 / BC│   ┌──────────────────────────────────────────┐ │
│  └─────────┘   │  Core: Rate Limiter · WAF Bypass · Proxy │ │
│                │  Browser Engine · Session Manager         │ │
│                └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.11+**
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hunterengine.git
cd hunterengine

# Create virtual environment
python -m venv env

# Activate it
# Windows:
env\Scripts\activate
# Linux/macOS:
source env/bin/activate

# Install dependencies
pip install -e .

# Install Playwright browser
playwright install chromium
```

### Configure Your Target

Edit `config/scope.yaml` with your authorized target:

```yaml
program:
  name: "my-target"
  platform: "hackerone"

in_scope:
  domains:
    - "*.target.com"

out_of_scope:
  domains:
    - "admin.target.com"
  keywords:
    - "delete"
    - "password_reset"
```

### Run

```bash
# 🕷️ Standalone auto-crawl (opens visible browser)
python main.py crawl https://target.com

# 🕷️ Auto-crawl in headless mode
python main.py crawl https://target.com --headless

# 🔍 Full scan pipeline
python main.py scan

# 🔍 Full scan + integrated browser auto-crawl
python main.py scan --auto-crawl --headed

# 📋 Show current scope
python main.py scope

# 🔧 Check installed tools
python main.py check-tools
```

---

## 🕷️ Integrated Browser Auto-Crawl

HunterEngine v2.0.0 introduces **OWASP ZAP–style integrated browser crawling**. A visible Chromium window opens and autonomously explores the target while you watch:

### What It Does

- **🔗 Clicks every link** — `<a>` tags, navigation menus, breadcrumbs, sidebar links
- **🖱️ Clicks interactive elements** — buttons, tabs, accordions, dropdowns, modals
- **📝 Auto-fills forms** — intelligently fills email, name, search, password fields and submits
- **🌐 Intercepts network traffic** — captures every XHR, fetch, and WebSocket request as discovered endpoints
- **⚡ Detects SPA routes** — tracks `pushState`/`replaceState`, extracts React Router / Vue Router paths
- **👁️ Watches DOM mutations** — detects dynamically injected content
- **📸 Screenshots** — captures evidence on each new page
- **🛡️ Scope-enforced** — never navigates outside your defined boundaries

### Usage

```bash
# Basic auto-crawl (visible browser)
python main.py crawl https://target.com

# With options
python main.py crawl https://target.com \
  --max-pages 300 \
  --max-depth 8 \
  --no-forms

# Headless mode (no visible window)
python main.py crawl https://target.com --headless

# As part of the full scan pipeline
python main.py scan --auto-crawl --headed
```

### Live Terminal Dashboard

While the browser navigates, a Rich terminal dashboard shows real-time stats:

```
╭──── 🕷️  HunterEngine Auto-Crawler ────╮
│  ⏱  Elapsed           42s             │
│  📄 Pages visited      23             │
│  📋 Queue remaining    156            │
│  🔗 Endpoints found    89             │
│  🌐 Network requests   234           │
│  📜 JS files           12             │
│  📝 Forms submitted    4              │
│  📸 Screenshots        23             │
│  ⚡ Rate               0.5 pages/s    │
│  🎯 Current            https://...    │
╰── max 500 pages · depth 10 ───────────╯
```

---

## 📁 Project Structure

```
hunterengine/
├── main.py                     # CLI entry point (Typer)
├── config/
│   ├── scope.yaml              # Target scope definition
│   ├── settings.yaml           # Global settings
│   └── wordlists/              # Subdomain, directory, param wordlists
├── core/
│   ├── orchestrator.py         # Pipeline coordinator
│   ├── browser_engine.py       # Playwright browser manager
│   ├── proxy_engine.py         # Embedded mitmproxy
│   ├── rate_limiter.py         # Adaptive token-bucket rate limiter
│   ├── scope_loader.py         # Scope validation & enforcement
│   ├── session_manager.py      # Auth session handling
│   ├── waf_bypass.py           # WAF evasion techniques
│   └── tool_resolver.py        # External tool path resolution
├── crawl/
│   ├── auto_navigator.py       # 🆕 ZAP-style browser auto-crawler
│   ├── active_crawler.py       # katana/gospider/hakrawler wrapper
│   ├── js_crawler.py           # Playwright SPA crawler
│   ├── js_analyzer.py          # JS file analysis (secrets, endpoints)
│   ├── graphql_mapper.py       # GraphQL introspection
│   └── param_miner.py          # Hidden parameter discovery
├── detection/
│   ├── base_detector.py        # Abstract base for all detectors
│   ├── xss_detector.py         # Cross-site scripting
│   ├── cors_detector.py        # CORS misconfiguration
│   ├── ssrf_detector.py        # Server-side request forgery
│   ├── jwt_detector.py         # JWT vulnerabilities
│   ├── idor_detector.py        # Insecure direct object reference
│   ├── secrets_detector.py     # Exposed secrets/credentials
│   ├── auth_detector.py        # Authentication flaws
│   ├── open_redirect.py        # Open redirect
│   ├── csp_analyzer.py         # Content Security Policy
│   ├── prototype_pollution.py  # Prototype pollution
│   ├── graphql_detector.py     # GraphQL vulnerabilities
│   ├── subdomain_takeover.py   # Subdomain takeover
│   ├── dependency_scanner.py   # Vulnerable dependencies
│   ├── race_condition.py       # Race conditions (TOCTOU)
│   ├── crypto_specific.py      # Cryptographic weaknesses
│   └── memory_vulns.py         # Memory safety issues
├── recon/
│   ├── subdomain_enum.py       # Subdomain enumeration
│   ├── dns_resolver.py         # Bulk DNS resolution
│   ├── live_prober.py          # HTTP(S) live host probing
│   ├── historical_urls.py      # Wayback/GAU URL collection
│   └── tech_fingerprint.py     # Technology stack detection
├── ai/
│   └── local_reasoner.py       # Local LLM triage (Ollama/OpenAI)
├── confidence/
│   ├── scorer.py               # Multi-signal confidence scoring
│   └── correlation_engine.py   # Weak signal aggregation
├── memory/
│   ├── pattern_store.py        # Cross-session pattern DB
│   ├── endpoint_memory.py      # Endpoint deduplication
│   ├── param_correlator.py     # Parameter correlation
│   └── vuln_chaining.py        # Vulnerability chaining rules
├── proxy/
│   ├── mitm_core.py            # mitmproxy integration
│   ├── request_interceptor.py  # Request modification
│   ├── response_analyzer.py    # Passive response scanning
│   └── replay_engine.py        # Request replay (Burp Repeater)
├── reporting/
│   ├── triage_report.py        # Report generation engine
│   ├── h1_formatter.py         # HackerOne format
│   ├── bugcrowd_formatter.py   # Bugcrowd format
│   └── templates/              # Jinja2 report templates
├── data/                       # Runtime data (gitignored)
│   ├── reports/
│   ├── screenshots/
│   └── sessions/
├── pyproject.toml              # Python project config
├── requirements.txt            # Pip dependencies
├── Makefile                    # Dev task runner
├── LICENSE                     # MIT License
├── CONTRIBUTING.md             # Contribution guidelines
├── SECURITY.md                 # Security policy
├── CODE_OF_CONDUCT.md          # Contributor Covenant
└── CHANGELOG.md                # Release history
```

---

## 🔧 External Tools (Optional)

HunterEngine works standalone, but performance improves with these Go-based tools:

| Category | Tool | Install |
|----------|------|---------|
| Subdomain Recon | [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| DNS | [dnsx](https://github.com/projectdiscovery/dnsx) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| HTTP Probing | [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| Crawling | [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| Crawling | [gospider](https://github.com/jaeles-project/gospider) | `go install github.com/jaeles-project/gospider@latest` |
| JS Analysis | [jsluice](https://github.com/BishopFox/jsluice) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| Detection | [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| XSS | [dalfox](https://github.com/hahwul/dalfox) | `go install github.com/hahwul/dalfox/v2@latest` |
| Local AI | [Ollama](https://ollama.ai) | [ollama.ai/download](https://ollama.ai/download) |

Check what's installed:
```bash
python main.py check-tools
```

---

## ⚙️ Configuration

### `config/scope.yaml` — Target Scope

```yaml
program:
  name: "target-program"
  platform: "hackerone"         # hackerone | bugcrowd | yeswehack | private

in_scope:
  domains:
    - "*.target.com"
  cidrs: []                     # e.g., "10.0.0.0/8"

out_of_scope:
  domains:
    - "admin.target.com"
  keywords:
    - "delete"
    - "password_reset"

auth:
  type: "none"                  # none | bearer | cookie | basic
  token: ""
  cookie: ""
```

### `config/settings.yaml` — Engine Settings

Key settings (see full file for all options):

```yaml
rate_limiting:
  requests_per_second: 10
  adaptive: true                # Auto-backoff on WAF/429

crawl:
  max_depth: 5
  max_pages: 500
  js_rendering: true

detection:
  modules:
    xss: true
    cors: true
    ssrf: true
    jwt: true
    # ... 11 more modules

ai:
  enabled: true
  provider: "ollama"
  local_model:
    base_url: "http://127.0.0.1:11434"
    model: "qwen2.5:7b-instruct"
```

---

## 📊 CLI Reference

| Command | Description |
|---------|-------------|
| `python main.py scan` | Full scan pipeline (Recon → Crawl → Detect → Correlate → AI → Report) |
| `python main.py scan --auto-crawl --headed` | Full scan with visible browser auto-crawl |
| `python main.py scan --phase recon` | Run only a specific phase |
| `python main.py scan --dry-run` | Validate config without scanning |
| `python main.py crawl <URL>` | Standalone browser auto-crawl |
| `python main.py crawl <URL> --headless` | Headless auto-crawl |
| `python main.py scope` | Display current scope configuration |
| `python main.py history` | Show scan history |
| `python main.py check-tools` | Check installed external tools |

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m "Add amazing feature"`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🔒 Security

For responsible disclosure of security vulnerabilities in HunterEngine itself, see [SECURITY.md](SECURITY.md).

---

<p align="center">
  <strong>Built for the bug bounty community.</strong><br>
  <em>Hunt responsibly. Report ethically. Secure the web.</em>
</p>
