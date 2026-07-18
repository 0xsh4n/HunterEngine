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
  <strong>Automated Bug Bounty Engine — Hierarchical Agents + Local AI Vuln Hunting</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License: MIT">
  <img src="https://img.shields.io/badge/version-3.0.0-orange?style=flat-square" alt="Version 3.0.0">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform">
</p>

---

## ⚠️ Legal Disclaimer

> **HunterEngine is designed exclusively for authorized security testing.**
> Only use this tool against targets you have **explicit written permission** to test.
> Unauthorized access to computer systems is illegal. The authors are not responsible for misuse.

---

## What is HunterEngine?

HunterEngine **v3** is an automated bug bounty engine built around **hierarchical agents**:

1. **ReconAgent** — passive recon (subdomains, DNS, historical URLs)
2. **ActiveReconAgent** — live probing + tech fingerprinting
3. **EnumerationAgent** — crawl / JS / GraphQL / params
4. **VulnHuntAgent** — nests specialist hunters (IDOR, SSTI, request smuggling, XSS, …)

Classic detectors, correlation, local AI triage, and multi-format reports still run after the agent pipeline.

### Key Features

| Feature | Description |
|---------|-------------|
| **Hierarchical agents** | Recon → active recon → enumeration → nested vuln hunters |
| **Local AI bug hunt** | Ollama / Qwen3 reasoning plans scoped probes (not report fluff) |
| **Nested hunters** | XSS, IDOR, SSTI, SSRF, auth, open redirect, request smuggling, CORS, JWT |
| **Browser auto-crawl** | Playwright navigator: clicks, forms, XHR/fetch, SPA routes |
| **15 classic detectors** | Rule-based modules run after AI testing |
| **httpx dual-use** | pip `httpx` library in the venv; ProjectDiscovery httpx for live probing |
| **Vulnerability chaining** | Weak signals → higher-severity composites |
| **Embedded proxy** | mitmproxy intercept / replay |
| **Adaptive rate limiting** | Token bucket + WAF/429 backoff |
| **Multi-format reports** | Markdown, HTML, HackerOne, Bugcrowd |

---

## Architecture (v3)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HunterEngine v3.0.0                          │
├─────────────────────────────────────────────────────────────────────┤
│  ScopeLoader                                                        │
│       │                                                             │
│       ▼                                                             │
│  ┌──────────────┐   ┌─────────────────┐   ┌────────────────────┐  │
│  │ ReconAgent   │──▶│ ActiveReconAgent│──▶│ EnumerationAgent   │  │
│  │ • subdomains │   │ • PD httpx probe│   │ • katana/gospider  │  │
│  │ • DNS        │   │ • tech FP       │   │ • auto-navigator   │  │
│  │ • historical │   │                 │   │ • JS / GraphQL     │  │
│  └──────────────┘   └─────────────────┘   └─────────┬──────────┘  │
│                                                      │             │
│                                                      ▼             │
│                                           ┌────────────────────┐   │
│                                           │   VulnHuntAgent    │   │
│                                           │  (ai_test phase)   │   │
│                                           │  ┌─────┐ ┌─────┐   │   │
│                                           │  │IDOR │ │SSTI │ … │   │
│                                           │  │XSS  │ │Smug │   │   │
│                                           │  └─────┘ └─────┘   │   │
│                                           └─────────┬──────────┘   │
│                                                     ▼              │
│  Detect → Correlate → AI Triage (reporting) → Report               │
│  Core: Rate Limiter · WAF Bypass · Proxy · Browser · Sessions      │
└─────────────────────────────────────────────────────────────────────┘
```

**Pipeline phases:** `recon` → `active_recon` → `crawl`/`enumeration` → `ai_test` → `detect` → `correlate` → `ai` → `report`

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Git**
- **Ollama** (for AI testing) — [ollama.ai/download](https://ollama.ai/download)
- Optional: Go toolchain for ProjectDiscovery binaries

### Installation

```bash
git clone https://github.com/yourusername/hunterengine.git
cd hunterengine

python -m venv env
# Windows:
env\Scripts\activate
# Linux/macOS:
source env/bin/activate

pip install -e .
playwright install chromium

# AI testing model (recommended)
ollama pull qwen3:4b
```

### Configure scope

Edit `config/scope.yaml`:

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
# Full agent pipeline
python main.py scan

# Full scan + visible browser enumeration
python main.py scan --auto-crawl --headed

# Phase-only (agents)
python main.py scan --phase recon
python main.py scan --phase active_recon
python main.py scan --phase enumeration
python main.py scan --phase ai_test

# Classic detectors / report triage
python main.py scan --phase detect
python main.py scan --phase ai

# Standalone browser crawl
python main.py crawl https://target.com
python main.py crawl https://target.com --headless

python main.py scope
python main.py check-tools
```

---

## httpx: pip library vs ProjectDiscovery

Both install a command named `httpx`. HunterEngine keeps them separate:

| Context | Which httpx |
|---------|-------------|
| Inside the venv (`import httpx`) | **pip library** — detectors, AI probes, crawl clients |
| Live host probing (`ActiveReconAgent`) | **ProjectDiscovery Go binary** if found on PATH / `$GOPATH/bin` |
| If PD binary missing | Live probe **falls back** to the pip library |

`python main.py check-tools` prints a dedicated **httpx Resolution** table.

Install the Go tool **outside** the venv Scripts folder:

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# Ensure %USERPROFILE%\go\bin (or $GOPATH/bin) is on PATH, ahead of Python Scripts if needed
```

---

## AI Testing (`--phase ai_test`)

Controlled by `config/settings.yaml`:

```yaml
ai:
  enabled: true
  mode: "testing"          # triage | testing | both
  testing_model:
    base_url: "http://127.0.0.1:11434"
    model: "qwen3:4b"
    think: true
  testing:
    enabled: true
    concurrency: 3
    max_endpoints: 40
    max_probes_per_agent: 8
    max_total_probes: 60
    subagents:
      - xss
      - idor
      - ssti
      - ssrf
      - auth
      - open_redirect
      - request_smuggling
      - cors
      - jwt
```

### Why `ai_test` used to finish instantly

| Cause | What happens now |
|-------|------------------|
| Empty endpoints when run alone | Seeds from scope domains / live hosts / historical URLs |
| Ollama down | Clear warning: start Ollama + `ollama pull qwen3:4b` |
| `ai.enabled: false` or `mode: triage` | Logs that testing is disabled |
| No interesting targets after seeding | Warning with remediation hints |

Best quality: run enumeration first (or a full `scan`), then `ai_test`:

```bash
python main.py scan --phase enumeration
python main.py scan --phase ai_test
# or simply:
python main.py scan
```

---

## CLI Reference

| Command / flag | Description |
|----------------|-------------|
| `scan` | Full pipeline (all agents + detect + report) |
| `scan --phase recon` | Passive recon agent only |
| `scan --phase active_recon` | Live probe + tech FP agent |
| `scan --phase crawl` / `enumeration` / `enum` | Enumeration agent |
| `scan --phase ai_test` / `vuln` | Nested AI vuln hunters |
| `scan --phase detect` | Classic detectors |
| `scan --phase correlate` | Weak-signal chaining |
| `scan --phase ai` | Report triage enrichment (not hunting) |
| `scan --phase report` | Generate reports |
| `scan --auto-crawl` | Enable browser auto-navigator in enumeration |
| `scan --headed` | Show browser window |
| `scan --no-enum` | Skip subdomain enum; use scope domains only |
| `scan --dry-run` | Validate config only |
| `scan -v` / `--verbose` | Debug logging |
| `crawl <URL>` | Standalone auto-crawl |
| `crawl --headless` | Headless browser |
| `crawl --max-pages N` | Page cap |
| `crawl --max-depth N` | Click depth |
| `crawl --no-forms` | Disable form submit |
| `scope` | Print scope summary |
| `history` | Scan history from memory DB |
| `check-tools` | External tools + httpx resolution |

---

## Browser Auto-Crawl

```bash
python main.py crawl https://target.com
python main.py crawl https://target.com --max-pages 300 --max-depth 8 --no-forms
python main.py scan --auto-crawl --headed
```

Clicks links/buttons, fills forms, intercepts XHR/fetch/WebSocket, tracks SPA routes, screenshots, enforces scope.

---

## Project Structure

```
hunterengine/
├── main.py                     # CLI (Typer)
├── config/
│   ├── scope.yaml
│   ├── settings.yaml
│   └── wordlists/
├── core/
│   ├── orchestrator.py         # Phase coordinator (agents)
│   ├── tool_resolver.py        # PD httpx vs pip httpx
│   ├── browser_engine.py
│   ├── proxy_engine.py
│   ├── rate_limiter.py
│   ├── scope_loader.py
│   ├── session_manager.py
│   └── waf_bypass.py
├── ai/
│   ├── agents/                 # Hierarchical phase agents
│   │   ├── recon_agent.py
│   │   ├── active_recon_agent.py
│   │   ├── enum_agent.py
│   │   └── vuln_agent.py
│   ├── subagents/              # Nested vuln hunters
│   │   ├── xss_hunter.py
│   │   ├── idor_hunter.py
│   │   ├── ssti_hunter.py
│   │   ├── smuggling_hunter.py
│   │   └── …
│   ├── testing_agent.py        # Probe planner / executor
│   ├── ollama_client.py
│   └── local_reasoner.py       # Report triage only
├── crawl/  recon/  detection/  confidence/  memory/  proxy/  reporting/
├── pyproject.toml
└── requirements.txt
```

---

## External Tools (Optional)

| Category | Tool | Install |
|----------|------|---------|
| Subdomain | [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| DNS | [dnsx](https://github.com/projectdiscovery/dnsx) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| HTTP probe | [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| Crawl | [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| Crawl | [gospider](https://github.com/jaeles-project/gospider) | `go install github.com/jaeles-project/gospider@latest` |
| JS | [jsluice](https://github.com/BishopFox/jsluice) | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| Templates | [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| XSS | [dalfox](https://github.com/hahwul/dalfox) | `go install github.com/hahwul/dalfox/v2@latest` |
| Local AI | [Ollama](https://ollama.ai) | [ollama.ai/download](https://ollama.ai/download) |

---

## Configuration highlights

```yaml
# config/settings.yaml
rate_limiting:
  requests_per_second: 10
  adaptive: true

crawl:
  max_depth: 5
  max_pages: 500
  js_rendering: true

detection:
  confidence_threshold: 0.6
  modules:
    xss: true
    cors: true
    # …

ai:
  enabled: true
  mode: "testing"   # testing = hunt; triage = report only; both = both
```

Copy `.env.example` → `.env` for optional `OLLAMA_BASE_URL` / proxy overrides.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

## Security

Report issues in HunterEngine itself via [SECURITY.md](SECURITY.md).

---

<p align="center">
  <strong>Built for the bug bounty community.</strong><br>
  <em>Hunt responsibly. Report ethically. Secure the web.</em>
</p>
