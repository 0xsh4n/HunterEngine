#!/usr/bin/env python3
"""
HunterEngine v3 — Automated Bug Bounty Reconnaissance & Detection

Usage:
    python main.py scan                           # Full pipeline scan
    python main.py scan --auto-crawl --headed     # Full scan with visible browser auto-crawl
    python main.py scan --phase recon             # 1 Recon (passive)
    python main.py scan --phase scanning          # 2 Scanning & enumeration (active recon)
    python main.py scan --phase threat_model      # 3 Threat modeling (scored surface + AI plan)
    python main.py scan --phase vuln_analysis     # 4 Vulnerability analysis (behaviour-driven detectors)
    python main.py scan --phase exploitation      # 5 Exploitation (safe AI validation probes)
    python main.py scan --phase post_exploit      # 6 Post-exploitation (non-destructive impact)
    python main.py scan --phase correlation       # 7 Correlation & chaining
    python main.py scan --phase reporting         # 8 Reporting (AI triage + reports)
    python main.py scan --resume                  # Resume from latest checkpoint
    python main.py checkpoints                    # List saved checkpoints
    python main.py crawl https://target.com       # Standalone browser auto-crawl (ZAP-style)
    python main.py crawl https://target.com --headless  # Headless auto-crawl
    python main.py scope                          # Show current scope
    python main.py history                        # Show scan history
    python main.py check-tools                    # Check installed tools (resolves PD vs pip httpx)
    python main.py ai-health                      # Probe Ollama / configured model
    python main.py dashboard                      # Web console: start/stop scans, reasoning, findings
    python main.py domains                        # Show per-domain learning profiles
    python main.py knowledge-ingest ./research    # Index local pentest docs into RAG
    python main.py knowledge-search "SSRF"        # Search the local knowledge index

Controls during scan:
    Ctrl+C  → pause at next phase boundary → [r]esume / [q]uit+save / [a]bort
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
app = typer.Typer(
    name="hunterengine",
    help="Automated bug bounty recon & vulnerability detection engine.",
    add_completion=False,
)


@app.command(name="knowledge-ingest")
def knowledge_ingest(
    source: str = typer.Argument(..., help="PDF, text/blog file, or directory"),
    index: str = typer.Option("data/knowledge/index.json", help="RAG index path"),
) -> None:
    """Ingest security research into the separate local RAG index."""
    from knowledge.rag import KnowledgeBase
    kb = KnowledgeBase(index)
    kb.load()
    count = kb.ingest(source)
    console.print(f"Indexed {count} chunks → {index}")


@app.command(name="knowledge-search")
def knowledge_search(
    query: str = typer.Argument(...),
    index: str = typer.Option("data/knowledge/index.json", help="RAG index path"),
    top_k: int = typer.Option(5, "--top-k"),
) -> None:
    """Search the local pentest knowledge index."""
    from knowledge.rag import KnowledgeBase
    kb = KnowledgeBase(index)
    hits = kb.search(query, top_k=top_k)
    for hit in hits:
        console.print(f"[{hit.score:.3f}] {hit.chunk.source}\n{hit.chunk.text[:800]}\n")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )
    # Quiet noisy libraries
    for lib in ("httpx", "httpcore", "asyncio", "urllib3", "hpack", "mitmproxy"):
        logging.getLogger(lib).setLevel(logging.WARNING)


def print_banner() -> None:
    """Print the startup banner."""
    banner = """
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
    """
    console.print(Panel(banner, title="v3.2.0", border_style="blue"))


# ── Commands ──────────────────────────────────────────────────────────────


@app.command()
def scan(
    target: str = typer.Option("", "--target", help="Single authorized URL or subdomain (overrides scope targets)"),
    scope: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    phase: str = typer.Option(
        "",
        help=(
            "Run one of the 8 classic steps: recon, scanning, threat_model, "
            "vuln_analysis, exploitation, post_exploit, correlation, reporting "
            "(internal aliases: active_recon, crawl, detect, ai_test, correlate, ai, report)"
        ),
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate config without scanning"),
    auto_crawl: bool = typer.Option(False, "--auto-crawl", help="Enable integrated browser auto-crawl (ZAP-style)"),
    headed: bool = typer.Option(False, "--headed", help="Show the browser window during auto-crawl"),
    no_enum: bool = typer.Option(False, "--no-enum", help="Skip subdomain enumeration and only scan explicitly provided domains"),
    profile: str = typer.Option("blackbox", "--profile", help="Testing profile: blackbox or greybox (greybox requires explicit authorization)"),
    resume: bool = typer.Option(False, "--resume", "-R", help="Resume from the latest checkpoint"),
    checkpoint: str = typer.Option(
        "",
        "--checkpoint",
        help="Resume from a specific checkpoint JSON path",
    ),
) -> None:
    """Run the full scan pipeline or a specific phase.

    Press Ctrl+C during a scan to pause, then choose resume / quit+save / abort.
    Use --resume to continue from data/checkpoints/latest.json.
    """
    setup_logging(verbose)
    print_banner()

    from core.orchestrator import Orchestrator, ScanStopped
    from core.scan_control import ScanController

    controller = ScanController(interactive=True)
    orchestrator = Orchestrator(
        scope_path=scope,
        settings_path=settings,
        auto_crawl=auto_crawl,
        headed=headed,
        skip_enum=no_enum,
        controller=controller,
        profile=profile,
    )

    async def run_scan():
        console.print("\n[bold cyan]═══ Initializing HunterEngine ═══[/bold cyan]\n")
        console.print(
            "[dim]Controls: Ctrl+C → pause → [r]esume / [q]uit+save / [a]bort[/dim]\n"
        )

        await orchestrator.setup()

        if target:
            # Keep single-target runs isolated without rewriting scope.yaml.
            value = target.strip()
            if not value.startswith(("http://", "https://")):
                value = "https://" + value
            loader = orchestrator.scope_loader
            if loader:
                loader.scope.in_scope_domains = []
                loader.scope.in_scope_urls = [value]
                loader._compile_patterns()
                console.print(f"[yellow]Single-target mode:[/yellow] {value}")

        if resume or checkpoint:
            cp_path = checkpoint or None
            console.print(
                f"[bold yellow]Resuming from checkpoint"
                f"{f': {cp_path}' if cp_path else ' (latest)'}…[/bold yellow]\n"
            )
            if not orchestrator.load_checkpoint(cp_path):
                console.print("[red]No checkpoint found — start a new scan or check data/checkpoints/[/red]")
                raise typer.Exit(1)
            stats = orchestrator.get_stats()
            console.print(Panel(
                f"Phase: {stats['phase']}\n"
                f"Subdomains: {stats['subdomains']} · Live hosts: {stats['live_hosts']}\n"
                f"Endpoints: {stats['endpoints']} · Findings: {stats['findings']}",
                title="Restored State",
                border_style="yellow",
            ))

        scope_summary = orchestrator.scope_loader.summary()
        console.print(Panel(scope_summary, title="Scope", border_style="green"))

        if dry_run:
            console.print("\n[yellow]Dry run — config validated, no scan performed.[/yellow]")
            return

        if auto_crawl:
            mode = "[bold green]HEADED[/bold green]" if headed else "[bold yellow]HEADLESS[/bold yellow]"
            console.print(f"\n[bold cyan]🕷️  Auto-crawl enabled ({mode} browser)[/bold cyan]\n")

        phases = [phase] if phase else None
        start = time.time()

        console.print("\n[bold cyan]═══ Starting Scan ═══[/bold cyan]\n")
        try:
            state = await orchestrator.run(phases=phases)
        except ScanStopped as stop:
            elapsed = time.time() - start
            if stop.action == "quit":
                console.print(
                    f"\n[yellow]Scan quit after {elapsed:.0f}s — checkpoint saved.[/yellow]\n"
                    f"[dim]Resume with: python main.py scan --resume[/dim]\n"
                )
                if orchestrator.last_checkpoint_path:
                    console.print(f"[dim]{orchestrator.last_checkpoint_path}[/dim]\n")
            else:
                console.print(f"\n[red]Scan aborted after {elapsed:.0f}s (not saved).[/red]\n")
            print_results(orchestrator.state, elapsed)
            raise typer.Exit(0 if stop.action == "quit" else 130)
        except Exception as exc:
            elapsed = time.time() - start
            console.print(f"\n[red]Scan failed unexpectedly: {exc}[/red]\n")
            if verbose:
                logger = logging.getLogger("hunterengine")
                logger.exception("Scan pipeline crashed")
            print_results(getattr(orchestrator, "state", None), elapsed)
            raise typer.Exit(1) from exc

        elapsed = time.time() - start
        print_results(state, elapsed)

    asyncio.run(run_scan())


@app.command(name="checkpoints")
def checkpoints_cmd(
    directory: str = typer.Option("data/checkpoints", help="Checkpoint directory"),
) -> None:
    """List saved scan checkpoints (for --resume)."""
    setup_logging(False)
    from core.checkpoint import CheckpointStore

    store = CheckpointStore(directory)
    rows = store.list_checkpoints()
    latest = store.latest_path()

    if not rows and not latest:
        console.print("[yellow]No checkpoints found.[/yellow]")
        console.print(f"[dim]Directory: {directory}[/dim]")
        return

    table = Table(title="Scan Checkpoints")
    table.add_column("Saved (UTC)", style="cyan")
    table.add_column("Reason")
    table.add_column("Next phase", style="green")
    table.add_column("Hosts", justify="right")
    table.add_column("Endpoints", justify="right")
    table.add_column("Findings", justify="right")
    table.add_column("Path", style="dim", max_width=40)

    for row in rows[:20]:
        table.add_row(
            str(row.get("saved_at", ""))[:19],
            str(row.get("reason", "")),
            str(row.get("next_phase") or "—"),
            str(row.get("live_hosts", 0)),
            str(row.get("endpoints", 0)),
            str(row.get("findings", 0)),
            str(row.get("path", "")),
        )
    console.print(table)
    if latest:
        console.print(f"\n[bold]Latest pointer:[/bold] {latest}")
        console.print("[dim]Resume: python main.py scan --resume[/dim]")

@app.command()
def crawl(
    target: str = typer.Argument(..., help="Target URL to auto-crawl (e.g. https://example.com)"),
    scope: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    max_pages: int = typer.Option(200, "--max-pages", help="Maximum pages to visit"),
    max_depth: int = typer.Option(10, "--max-depth", help="Maximum click-depth"),
    headless: bool = typer.Option(False, "--headless", help="Run browser in headless mode (no visible window)"),
    no_forms: bool = typer.Option(False, "--no-forms", help="Disable automatic form filling and submission"),
    keep_open: float = typer.Option(5.0, "--keep-open", help="Seconds to keep browser open after crawl finishes"),
    slow_mo: int = typer.Option(150, "--slow-mo", help="Slow down browser actions by this many milliseconds (headed mode only)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """
    Standalone integrated browser auto-crawl (ZAP-style).

    Opens a visible Chromium browser and autonomously navigates the target:
    clicking links, filling forms, intercepting network requests, and
    discovering API endpoints — all within scope.
    """
    setup_logging(verbose)
    print_banner()

    from crawl.auto_navigator import AutoNavigator, NavigatorConfig

    # Load scope if available
    scope_loader = None
    try:
        from core.scope_loader import ScopeLoader
        sl = ScopeLoader(scope)
        sl.load()
        scope_loader = sl
        console.print(Panel(sl.summary(), title="Scope", border_style="green"))
    except FileNotFoundError:
        console.print("[yellow]No scope file found — crawling without scope enforcement.[/yellow]")

    nav_config = NavigatorConfig(
        headless=headless,
        max_pages=max_pages,
        max_depth=max_depth,
        form_submit=not no_forms,
        keep_open=keep_open,
        slow_mo=slow_mo,
    )

    async def run_crawl():
        console.print(f"\n[bold cyan]🕷️  Auto-crawling: {target}[/bold cyan]")
        mode = "[dim]headless[/dim]" if headless else "[bold green]HEADED (visible browser)[/bold green]"
        console.print(f"    Mode: {mode}")
        console.print(f"    Max pages: {max_pages} · Max depth: {max_depth}")
        console.print(f"    Form submission: {'[green]enabled[/green]' if not no_forms else '[red]disabled[/red]'}")
        console.print()

        navigator = AutoNavigator(config=nav_config, scope_loader=scope_loader)
        start = time.time()
        results = await navigator.crawl([target])
        elapsed = time.time() - start

        # Print summary
        console.print(f"\n[bold cyan]═══ Crawl Complete ({elapsed:.0f}s) ═══[/bold cyan]\n")

        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="dim")
        stats_table.add_column("Value", style="bold")
        stats_table.add_row("Pages visited", str(results["pages_visited"]))
        stats_table.add_row("Endpoints discovered", str(len(results["endpoints"])))
        stats_table.add_row("Network requests captured", str(len(results["network_requests"])))
        stats_table.add_row("JS files found", str(len(results["js_files"])))
        stats_table.add_row("Forms submitted", str(results["forms_submitted"]))
        stats_table.add_row("Screenshots taken", str(results["screenshots"]))
        console.print(Panel(stats_table, title="Crawl Results", border_style="green"))

        # Show discovered endpoints
        if results["endpoints"]:
            ep_table = Table(title=f"Discovered Endpoints ({len(results['endpoints'])} total)")
            ep_table.add_column("#", style="dim", width=5)
            ep_table.add_column("Method", style="cyan", width=7)
            ep_table.add_column("URL", style="white")
            ep_table.add_column("Source", style="dim")

            for i, ep in enumerate(results["endpoints"][:100], 1):
                ep_table.add_row(
                    str(i),
                    ep.get("method", "GET"),
                    ep.get("url", "")[:100],
                    ep.get("source", ""),
                )
            console.print(ep_table)

            if len(results["endpoints"]) > 100:
                console.print(f"[dim]  ... and {len(results['endpoints']) - 100} more[/dim]")

    asyncio.run(run_crawl())


@app.command()
def scope(
    scope_path: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
) -> None:
    """Display the current scope configuration."""
    setup_logging(False)

    from core.scope_loader import ScopeLoader

    loader = ScopeLoader(scope_path)
    try:
        loader.load()
        console.print(Panel(loader.summary(), title="Current Scope", border_style="green"))

        roots = loader.get_root_domains()
        if roots:
            console.print(f"\nRoot domains: {', '.join(roots)}")

        auth = loader.scope.auth
        if auth.auth_type != "none":
            console.print(f"Auth type: {auth.auth_type}")

    except FileNotFoundError:
        console.print(f"[red]Scope file not found: {scope_path}[/red]")
        console.print("Create one with: cp config/scope.yaml.example config/scope.yaml")
        raise typer.Exit(1)


@app.command()
def history(
    db_path: str = typer.Option("data/memory.db", help="Path to memory database"),
) -> None:
    """Show scan history from the memory database."""
    setup_logging(False)

    async def show_history():
        from memory.pattern_store import PatternStore
        store = PatternStore(db_path)
        scans = await store.get_scan_history()

        if not scans:
            console.print("[yellow]No scan history found.[/yellow]")
            return

        table = Table(title="Scan History")
        table.add_column("Date", style="cyan")
        table.add_column("Target", style="green")
        table.add_column("Findings", justify="right")
        table.add_column("By Severity")

        import json
        for scan in scans:
            scan_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(scan["scan_time"]))
            sev_data = json.loads(scan.get("findings_by_severity", "{}"))
            sev_str = " | ".join(f"{k}: {v}" for k, v in sev_data.items())
            table.add_row(scan_time, scan["target"], str(scan["total_findings"]), sev_str)

        console.print(table)

    asyncio.run(show_history())


@app.command(name="check-tools")
def check_tools() -> None:
    """Check which external tools are installed."""
    setup_logging(False)
    import shutil
    import urllib.request

    import yaml

    from core.tool_resolver import find_projectdiscovery_httpx

    tools = {
        "Subdomain Recon": ["subfinder", "amass", "assetfinder"],
        "DNS": ["dnsx", "dig"],
        "HTTP Probing": ["httpx", "naabu"],
        "Historical": ["gau", "waybackurls"],
        "Crawling": ["katana", "gospider", "hakrawler"],
        "JS Analysis": ["jsluice"],
        "Fuzzing": ["ffuf", "arjun"],
        "Detection": ["dalfox", "nuclei", "interactsh-client"],
        "Screenshots": ["gowitness"],
        "Local AI": ["ollama"],
        "Other": ["git", "curl", "chromium", "chromium-browser"],
    }

    table = Table(title="Tool Availability")
    table.add_column("Category", style="cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status", justify="center")

    def ollama_available() -> bool:
        if shutil.which("ollama") is not None:
            return True
        try:
            settings_path = Path("config/settings.yaml")
            settings = yaml.safe_load(settings_path.read_text()) if settings_path.exists() else {}
            base_url = (
                settings.get("ai", {})
                .get("local_model", {})
                .get("base_url", "http://127.0.0.1:11434")
                .rstrip("/")
            )
            with urllib.request.urlopen(f"{base_url}/api/tags", timeout=3) as response:
                return response.status < 500
        except Exception:
            return False

    tool_aliases = {
        "chromium-browser": ["chromium-browser", "chromium", "google-chrome", "google-chrome-stable"],
        "ollama": ["ollama"],
    }

    def tool_found(tool: str) -> bool:
        if tool == "httpx":
            return pd_httpx is not None
        if tool == "ollama":
            return ollama_available()
        return any(shutil.which(alias) is not None for alias in tool_aliases.get(tool, [tool]))

    pd_httpx = find_projectdiscovery_httpx()
    for category, tool_list in tools.items():
        for tool in tool_list:
            found = tool_found(tool)
            if tool == "httpx" and found:
                status = f"[green]✓ PD binary[/green]\n[dim]{pd_httpx}[/dim]"
            elif tool == "httpx":
                status = "[yellow]✗ PD missing[/yellow]\n[dim]probe falls back to pip httpx[/dim]"
            else:
                status = "[green]✓ installed[/green]" if found else "[red]✗ missing[/red]"
            table.add_row(category, tool, status)

    console.print(table)

    # httpx dual-use resolution
    from core.tool_resolver import describe_httpx_resolution

    hx = describe_httpx_resolution()
    hx_table = Table(title="httpx Resolution (pip vs ProjectDiscovery)")
    hx_table.add_column("Role", style="cyan")
    hx_table.add_column("Value", style="white")
    hx_table.add_row("ProjectDiscovery httpx", hx["projectdiscovery_httpx"])
    hx_table.add_row("pip httpx library (venv)", hx["pip_httpx_library"])
    hx_table.add_row("pip httpx CLI (ignored)", hx["pip_httpx_cli"])
    hx_table.add_row("Note", hx["note"])
    console.print("\n")
    console.print(hx_table)

    # Python packages
    console.print("\n")
    pkg_table = Table(title="Python Package Availability")
    pkg_table.add_column("Package", style="white")
    pkg_table.add_column("Status", justify="center")

    packages = [
        "playwright", "mitmproxy", "httpx", "fake_useragent",
        "PyJWT", "jose", "jinja2", "rich", "typer",
        "aiosqlite", "aiofiles", "tldextract", "bs4",
        "yaml", "jsbeautifier",
    ]

    for pkg in packages:
        import_name = {"PyJWT": "jwt"}.get(pkg, pkg)
        try:
            __import__(import_name)
            pkg_table.add_row(pkg, "[green]✓ installed[/green]")
        except ImportError:
            pkg_table.add_row(pkg, "[red]✗ missing[/red]")

    console.print(pkg_table)


@app.command(name="ai-health")
def ai_health(
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    probe: bool = typer.Option(True, "--probe/--no-probe", help="Also send a short chat probe"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """Check whether the configured local AI (Ollama) is reachable and usable."""
    setup_logging(verbose)

    async def _run() -> int:
        import yaml
        from ai.ollama_client import OllamaClient
        from ai.testing_agent import TestingAIConfig

        path = Path(settings)
        conf = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        cfg = TestingAIConfig.from_settings(conf or {})
        client = OllamaClient(cfg.to_client_config())
        report = await client.health_check()

        table = Table(title="AI Health Check")
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        table.add_row("Provider", str(report.get("provider")))
        table.add_row("Base URL", str(report.get("base_url")))
        table.add_row("Model", str(report.get("model")))
        table.add_row("Endpoint", str(report.get("endpoint")))
        table.add_row("Latency", f"{report.get('latency_ms')} ms")
        table.add_row("Daemon OK", "[green]yes[/green]" if report.get("ok") else "[red]no[/red]")
        models = report.get("models") or []
        table.add_row("Installed models", ", ".join(models[:12]) or "(none)")
        if report.get("error"):
            table.add_row("Error", f"[red]{report['error']}[/red]")
        if report.get("hint"):
            table.add_row("Hint", str(report["hint"]))
        console.print(table)

        chat_ok = False
        if probe and report.get("ok"):
            console.print("\n[dim]Sending chat probe…[/dim]")
            try:
                reply = await client.chat(
                    system="Reply with exactly: pong",
                    user="ping",
                    json_mode=False,
                    think=False,
                )
                chat_ok = bool((reply or "").strip())
                console.print(Panel((reply or "")[:400] or "(empty)", title="Chat probe reply", border_style="green" if chat_ok else "red"))
            except Exception as exc:
                console.print(f"[red]Chat probe failed: {exc}[/red]")
        elif not report.get("ok"):
            console.print(
                "\n[yellow]Fix the daemon/model issue first.[/yellow]\n"
                "[dim]Local: ollama serve && ollama pull qwen3:4b[/dim]\n"
                "[dim]Docker: set OLLAMA_BASE_URL=http://host.docker.internal:11434[/dim]\n"
                "[dim]Or open the dashboard: python main.py dashboard[/dim]"
            )

        ok = bool(report.get("ok") and (chat_ok if probe else True))
        if ok:
            console.print("\n[bold green]AI is working.[/bold green]")
            return 0
        console.print("\n[bold red]AI health check failed.[/bold red]")
        return 1

    raise typer.Exit(asyncio.run(_run()))


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (0.0.0.0 for Docker)"),
    port: int = typer.Option(8787, "--port", help="Dashboard port"),
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    scope: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
) -> None:
    """Launch the web console: start/stop scans, watch the 8-step pipeline, AI
    reasoning/thinking, behaviour analysis, findings, learning, config & scope."""
    setup_logging(False)
    print_banner()
    console.print(
        Panel(
            f"Open http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}\n"
            "Use the Health check button to verify Ollama.\n"
            "Ollama is not started by HunterEngine — run it on the host.",
            title="Dashboard",
            border_style="cyan",
        )
    )
    from dashboard.app import run_dashboard

    run_dashboard(host=host, port=port, settings_path=settings, scope_path=scope)


@app.command()
def mcp(
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    scope: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
) -> None:
    """Run the HunterEngine MCP server (stdio) for Claude Desktop / Claude Code.

    Claude becomes the reasoning brain that drives the engine: it starts scans,
    watches the 8-step pipeline, and reads findings/reasoning/behaviour back.

    Claude Code:   claude mcp add hunterengine -- python main.py mcp
    Claude Desktop: add to claude_desktop_config.json (see README → MCP server).
    Logs go to stderr so they never corrupt the stdio JSON-RPC stream.
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    from integrations.mcp_server import run_stdio

    try:
        run_stdio(settings_path=settings, scope_path=scope)
    except ImportError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


@app.command()
def domains(
    data_dir: str = typer.Option("data", help="Data directory containing domain_profiles/"),
) -> None:
    """List per-domain learning profiles built from prior scans."""
    setup_logging(False)
    from memory.domain_learner import DomainLearner

    learner = DomainLearner(f"{data_dir.rstrip('/').rstrip(chr(92))}/domain_profiles")
    rows = learner.list_profiles()
    if not rows:
        console.print("[yellow]No domain profiles yet. Run a scan to start learning.[/yellow]")
        return

    table = Table(title="Domain Learning Profiles")
    table.add_column("Domain", style="cyan")
    table.add_column("Scans", justify="right")
    table.add_column("Preferred hunters")
    table.add_column("Auth")
    table.add_column("Updated")
    for row in rows:
        updated = row.get("updated_at")
        updated_s = time.strftime("%Y-%m-%d %H:%M", time.localtime(updated)) if updated else "—"
        table.add_row(
            str(row.get("domain", "")),
            str(row.get("scan_count", 0)),
            ", ".join(row.get("preferred_subagents") or []) or "—",
            ", ".join(row.get("auth_mechanisms") or []) or "—",
            updated_s,
        )
    console.print(table)


# ── Output helpers ────────────────────────────────────────────────────────


def _safe_len(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 1 if value else 0


def _safe_text(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _print_reasoning_summary(summary: object) -> None:
    """Show the AI triage reasoning summary (top risks + what needs review)."""
    if not isinstance(summary, dict) or not summary:
        return
    top = summary.get("top_risks") or []
    needs = summary.get("needs_review") or []
    if not top and not needs:
        return
    table = Table(title="AI Reasoning Summary", show_header=True)
    table.add_column("Top risk", style="white")
    table.add_column("Sev", width=9)
    table.add_column("Conf", width=6)
    table.add_column("Prio", width=5)
    for risk in top[:5]:
        if not isinstance(risk, dict):
            continue
        try:
            conf = f"{float(risk.get('confidence', 0)):.0%}"
        except (TypeError, ValueError):
            conf = "0%"
        table.add_row(
            _safe_text(risk.get("title"))[:60],
            _safe_text(risk.get("severity", "info")).upper(),
            conf,
            _safe_text(risk.get("priority", "—")),
        )
    if top:
        console.print(table)
    if needs:
        console.print(f"[yellow]Needs manual review:[/yellow] {', '.join(_safe_text(n) for n in needs[:8])}")


def print_results(state, elapsed: float) -> None:
    """Print a rich dashboard of scan results."""
    try:
        state_obj = state or SimpleNamespace()
        findings = state_obj.findings if isinstance(getattr(state_obj, "findings", None), list) else []
        errors = getattr(state_obj, "errors", None) or []
        if not isinstance(errors, list):
            errors = [errors]

        console.print(f"\n[bold cyan]═══ Scan Complete ({elapsed:.0f}s) ═══[/bold cyan]\n")

        stats_table = Table(show_header=False, box=None)
        stats_table.add_column("Metric", style="dim")
        stats_table.add_column("Value", style="bold")
        stats_table.add_row("Subdomains discovered", str(_safe_len(getattr(state_obj, "subdomains", None))))
        stats_table.add_row("Live hosts", str(_safe_len(getattr(state_obj, "live_hosts", None))))
        stats_table.add_row("Endpoints crawled", str(_safe_len(getattr(state_obj, "endpoints", None))))
        stats_table.add_row("JS files analyzed", str(_safe_len(getattr(state_obj, "js_files", None))))
        stats_table.add_row("Total findings", str(len(findings)))
        stats_table.add_row("Weak signals", str(_safe_len(getattr(state_obj, "weak_signals", None))))
        stats_table.add_row("Chained findings", str(_safe_len(getattr(state_obj, "chained_findings", None))))
        stats_table.add_row("AI enriched findings", str(getattr(state_obj, "ai_enriched_findings", 0)))
        stats_table.add_row("AI test probes", str(getattr(state_obj, "ai_test_probes", 0)))
        stats_table.add_row("AI test findings", str(getattr(state_obj, "ai_test_findings", 0)))
        token_usage = getattr(state_obj, "ai_token_usage", {}) or {}
        stats_table.add_row("AI prompt tokens", str(token_usage.get("prompt_tokens", 0)))
        stats_table.add_row("AI prompt tokens (estimated)", str(token_usage.get("prompt_tokens_estimated", 0)))
        stats_table.add_row("AI completion tokens", str(token_usage.get("completion_tokens", 0)))
        stats_table.add_row("AI total tokens", str(token_usage.get("total_tokens", 0)))
        stats_table.add_row("AI model requests", str(token_usage.get("requests", 0)))
        stats_table.add_row("AI requests started", str(token_usage.get("requests_started", 0)))
        stats_table.add_row("AI failed requests", str(token_usage.get("failed_requests", 0)))
        stats_table.add_row("AI reasoning traces", str(_safe_len(getattr(state_obj, "ai_reasoning_traces", None))))
        stats_table.add_row("AI thinking chars", str(token_usage.get("thinking_chars", 0)))
        stats_table.add_row("Errors", str(len(errors)))
        console.print(Panel(stats_table, title="Scan Statistics", border_style="green"))

        _print_reasoning_summary(getattr(state_obj, "ai_reasoning_summary", None))

        if findings:
            findings_table = Table(title=f"Findings ({len(findings)} total)")
            findings_table.add_column("#", style="dim", width=4)
            findings_table.add_column("Sev", width=8)
            findings_table.add_column("Conf", width=6)
            findings_table.add_column("Title", style="white")
            findings_table.add_column("Detector", style="dim")
            findings_table.add_column("URL", style="cyan", max_width=50)

            sev_colors = {
                "critical": "bold red",
                "high": "bold yellow",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }

            for i, finding in enumerate(findings[:50], 1):
                if not isinstance(finding, dict):
                    continue
                sev = _safe_text(finding.get("severity", "info")).lower() or "info"
                sev_style = sev_colors.get(sev, "dim")
                conf_value = finding.get("confidence", 0)
                try:
                    conf = f"{float(conf_value):.0%}"
                except (TypeError, ValueError):
                    conf = "0%"
                url = _safe_text(finding.get("url", ""))[:50]
                findings_table.add_row(
                    str(i),
                    f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                    conf,
                    _safe_text(finding.get("title", ""))[:60],
                    _safe_text(finding.get("detector", "")),
                    url,
                )

            console.print(findings_table)
        else:
            console.print("[yellow]No findings detected.[/yellow]")

        if errors:
            console.print(f"\n[red]Errors ({len(errors)}):[/red]")
            for err in errors:
                console.print(f"  [red]•[/red] {_safe_text(err, 'Unknown error')}")
    except Exception as exc:
        console.print(f"[yellow]Result summary could not be rendered: {exc}[/yellow]")


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
