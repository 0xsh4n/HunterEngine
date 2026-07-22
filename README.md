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
  <img src="https://img.shields.io/badge/version-3.1.0-orange?style=flat-square" alt="Version 3.1.0">
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
| **Black-box / grey-box profiles** | Explicit testing posture with request budgets and circuit breakers |
| **Local security RAG** | Ingest PDFs, blogs, Markdown, text, and HTML for assessment context |
| **Evidence-aware reports** | Per-scope folders, per-finding HTML pages, and Eyewitness/Gowitness images |

---

## Architecture (v3.1)

```
┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   HUNTERENGINE v3.1                                             │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│  INPUT / SAFETY                                                                                 │
│  scope.yaml + --target ──▶ ScopeLoader ──▶ URL/host normalization ──▶ out-of-scope filters    │
│                                  │                                                               │
│                                  ├── black-box / grey-box policy                                │
│                                  ├── method, response, request and host budgets                 │
│                                  └── rate limiter · proxy · session manager · circuit breakers  │
│                                                                                                 │
│  DISCOVERY                                                                                      │
│  ┌────────────────────┐   ┌─────────────────────┐   ┌──────────────────────────────────────┐  │
│  │ ReconAgent         │──▶│ ActiveReconAgent    │──▶│ EnumerationAgent                     │  │
│  │ • subdomains       │   │ • HTTP probing      │   │ • browser/auto-crawl                 │  │
│  │ • DNS resolution   │   │ • redirects/status  │   │ • JS and API routes                  │  │
│  │ • historical URLs  │   │ • tech fingerprint   │   │ • GraphQL mapping and params         │  │
│  └────────────────────┘   └─────────────────────┘   └───────────────────┬──────────────────┘  │
│                                                                         │                     │
│  APPLICATION UNDERSTANDING                                              ▼                     │
│  ┌─────────────────────────────┐   ┌──────────────────────────────┐   ┌───────────────────┐ │
│  │ Behavior model              │   │ Local RAG data pool           │   │ Endpoint memory   │ │
│  │ • auth/session/JWT/OAuth    │──▶│ • PDFs, blogs, HTML, text     │──▶│ • params/routes   │ │
│  │ • signup candidates         │   │ • lexical retrieval           │   │ • prior signals   │ │
│  │ • app flow hypotheses       │   │ • evidence-backed context    │   │ • learning events │ │
│  └─────────────────────────────┘   └──────────────────────────────┘   └─────────┬─────────┘ │
│                                                                                   │           │
│  AI REASONING / VALIDATION                                                       ▼           │
│  ┌─────────────────────────────────────────────────────────────────────────────────────────┐ │
│  │ AgenticPlanner ranks targets and explains decisions                                      │ │
│  │        │                                                                                 │ │
│  │        ▼                                                                                 │ │
│  │ VulnHuntAgent ──▶ XSS · IDOR · SSTI · SSRF · Auth · CORS · JWT · Redirect · Smuggling   │ │
│  │        │             │                                                                   │ │
│  │        │             └── optional ephemeral AI planner (structured plans only)           │ │
│  │        ▼                                                                                 │ │
│  │ Probe merge ──▶ scope gate ──▶ method gate ──▶ rate/budget gate ──▶ safe HTTP probe     │ │
│  │        ▲                                      │                                           │ │
│  │        └──── model timeout/malformed output ──┴── deterministic fallback canaries         │ │
│  └─────────────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                                 │
│  DETECTION / FEEDBACK / OUTPUT                                                                  │
│  Classic detectors ──▶ weak signals ──▶ correlation/chaining ──▶ AI triage ──▶ reports        │
│          │                    │                  │                     │                        │
│          └──────────────▶ learning events + token usage + phase health ◀─────────────────────┘
│                                                                                                 │
│  REPORT ARTIFACTS: reports/<scope>/summary + one HTML page per finding + evidence/ screenshots  │
│  CHECKPOINTS: resumable state, behavior model, decisions, errors, learning events, AI tokens   │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
``` 

**Pipeline phases:** `recon` → `active_recon` → `crawl`/`enumeration` → `ai_test` → `detect` → `correlate` → `ai` → `report`

The model is deliberately not the authority for traffic: it proposes and
explains hypotheses, while deterministic scope and safety gates decide whether
anything can be sent. If the model is unavailable, the same pipeline continues
with bounded non-destructive fallback probes and records the degraded mode in
phase health and checkpoints.

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

For a single subdomain or URL, use URL scope entries; URL-only scopes do not
trigger whole-domain enumeration:

```yaml
in_scope:
  domains: []
  urls:
    - "https://app.target.com/account/profile"
```

For large scopes, keep wildcard domains and tune `recon.concurrency` and
`recon.max_root_domains`. Enumeration and probing are isolated per target so a
failed host does not abort the remaining assessment.

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

# Explicit testing posture (grey-box requires written authorization)
python main.py scan --profile blackbox
python main.py scan --profile greybox

# Classic detectors / report triage
python main.py scan --phase detect
python main.py scan --phase ai

# Standalone browser crawl
python main.py crawl https://target.com
python main.py crawl https://target.com --headless

python main.py scope
python main.py check-tools

# Build and query the separate local pentest knowledge pool
python main.py knowledge-ingest ./research/
python main.py knowledge-ingest ./owasp-testing-guide.pdf
python main.py knowledge-search "SSRF metadata endpoint validation"
```

### Knowledge pool / RAG

The knowledge pool is an optional, local-only retrieval system. It accepts PDF,
Markdown, plain text, HTML, and blog exports, chunks them, and stores a small
searchable index at `data/knowledge/index.json`. During `ai_test`, relevant
chunks are retrieved using the discovered endpoints, parameters, and technology
fingerprints and supplied to the specialist agents as advisory context. The
retrieved material never overrides scope, safety, or authorization controls.

```yaml
# config/settings.yaml
knowledge:
  enabled: true
  index_path: "data/knowledge/index.json"
  chunk_size: 1200
  chunk_overlap: 180
```

Re-ingesting a source replaces its previous chunks, so the index is safe to
refresh as research changes. PDF extraction uses `pypdf`; unsupported or
unreadable files are skipped without stopping a scan.

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

Active testing is policy-gated in `config/settings.yaml`. Black-box is the
default and permits only safe read-oriented methods. Grey-box authentication
must be explicitly authorized before enabling authenticated requests:

```yaml
testing:
  profile: "blackbox"              # blackbox | greybox
safety:
  active_testing:
    allowed_methods: ["GET", "HEAD", "OPTIONS"]
    max_total_requests: 500
    max_requests_per_host: 100
    max_consecutive_timeouts: 3
    greybox_authorized: false       # change only for an authorized assessment
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
| `scan --profile blackbox|greybox` | Select the authorized testing posture |
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
| `knowledge-ingest <path>` | Index a PDF, blog export, text file, or directory |
| `knowledge-search <query>` | Search the local knowledge index |

---

## Browser Auto-Crawl

## Reports and proof-of-concept evidence

Reports are grouped by the configured program/scope name. Every finding gets a
standalone HTML page, making it easy to share or triage one issue at a time.
When an image is available, the reporter copies it into the scope folder and
embeds it in the finding page. It searches browser screenshots plus common
Eyewitness and Gowitness output directories.

```text
data/reports/<scope-name>/
├── report_<timestamp>.html
├── report_<timestamp>.md
├── 001_reflected-xss.html
├── 002_idor.html
└── evidence/
    ├── 001_gowitness.png
    └── 002_eyewitness.jpg
```

Configure additional image locations if your tooling writes elsewhere:

```yaml
reporting:
  evidence_dirs:
    - "data/screenshots"
    - "data/eyewitness"
    - "data/gowitness"
```

Missing screenshots never prevent HTML report generation; the finding page
records that no proof image was found.

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

## Operational guide (current)

### Scope modes

`config/scope.yaml` is the persistent source of truth. Use exactly one of these
patterns for a focused assessment:

```yaml
# Entire authorized domain and subdomains
in_scope:
  domains: ["*.example.com"]
  urls: []

# One subdomain or one application URL (survives a reboot)
in_scope:
  domains: []
  urls:
    - "https://app.example.com/login"
```

URL entries match HTTP/HTTPS redirect variants, query-string variants, and
descendant paths. They do not trigger whole-parent-domain enumeration. A
one-off target can be supplied without editing the file:

```bash
python main.py scan --target https://app.example.com/login
python main.py scan --target app.example.com
```

`--target` is runtime-only; edit `config/scope.yaml` when the target must be
retained after restarting the process. The current checked-in scope is a
single URL scope for `https://testphp.vulnweb.com`; its `domains: []` and URL
entry are intentional. Only use it where you have authorization.

### Recommended workflows

```bash
# Full large-scope assessment
python main.py scan --profile blackbox --auto-crawl

# Focused single application assessment
python main.py scan --target https://app.example.com --profile blackbox

# Resume after interruption/reboot
python main.py scan --resume

# Run phases independently
python main.py scan --phase recon
python main.py scan --phase active_recon
python main.py scan --phase crawl
python main.py scan --phase ai_test
python main.py scan --phase detect
python main.py scan --phase report
```

For grey-box work, use only written authorization and configure the permitted
authentication material explicitly. State-changing methods and account
creation remain disabled by default. Synthetic credential generation exists
for authorized lab workflows, but HunterEngine does not silently register
accounts or submit signup forms.

### AI, behavior analysis, and learning

The AI testing phase combines specialist planning with deterministic safeguards.
Before probing, it ranks endpoints, identifies likely authentication mechanisms
(session, token/JWT, OAuth/SSO), finds signup candidates, and retrieves relevant
RAG chunks. Each phase records success/failure telemetry and carries recent
learning events into later AI prompts. Model failures are isolated per agent;
scope, rate limits, request budgets, and circuit breakers remain authoritative.
Scan output includes prompt, completion, total-token, and request counts for the
testing model; usage is persisted in checkpoints. For unusual applications,
`ai.testing.generated_agent: true` enables an ephemeral planner that returns
the same structured probe format as built-in agents. Generated code is treated
as text only and is never imported or executed; every probe still passes the
deterministic safety gate.

### Local RAG data pool

```bash
python main.py knowledge-ingest ./research
python main.py knowledge-ingest ./security-guide.pdf
python main.py knowledge-search "authentication session fixation"
```

The index is stored at `data/knowledge/index.json` and can be rebuilt at any
time. PDF, Markdown, text, HTML, and blog exports are supported. RAG content
is advisory context, never permission to test a target.

### Reports and evidence

Reports are written under a sanitized scope/program folder. Every finding gets
its own HTML page. Existing screenshots from browser crawling, Eyewitness, or
Gowitness are copied into the scope's `evidence/` folder and embedded in the
finding page. Missing images do not fail report generation.

```text
data/reports/<scope>/
├── report_<timestamp>.html
├── report_<timestamp>.md
├── 001_finding-title.html
└── evidence/
```

Configure external evidence directories under `reporting.evidence_dirs` in
`config/settings.yaml`.

### Troubleshooting a target that appears to disappear

1. Confirm `config/scope.yaml` contains a quoted URL under `in_scope.urls`.
2. Run `python main.py scope` and verify the displayed scope.
3. Use `python main.py scan --target <url>` to isolate the target.
4. Run `python main.py scan --phase active_recon` and inspect live-host output.
5. If a prior scan stopped, use `python main.py scan --resume` or remove only
   the intended checkpoint after reviewing it.

The loader accepts URL-only scopes after a reboot; no in-memory CLI state is
required for persisted `scope.yaml` targets.

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
