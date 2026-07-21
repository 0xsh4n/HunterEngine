#!/usr/bin/env python3
"""
HunterEngine v3 — Automated Bug Bounty Reconnaissance & Detection

Usage:
    python main.py scan                           # Full pipeline scan
    python main.py scan --auto-crawl --headed     # Full scan with visible browser auto-crawl
    python main.py scan --phase recon             # Passive recon agent
    python main.py scan --phase active_recon      # Live probe + tech fingerprint agent
    python main.py scan --phase enumeration       # Crawl / endpoint enumeration agent
    python main.py scan --phase ai_test           # Nested AI vuln hunters (Ollama)
    python main.py scan --phase detect            # Classic detectors
    python main.py scan --phase ai                # Local AI report enrichment
    python main.py scan --resume                  # Resume from latest checkpoint
    python main.py checkpoints                    # List saved checkpoints
    python main.py crawl https://target.com       # Standalone browser auto-crawl (ZAP-style)
    python main.py crawl https://target.com --headless  # Headless auto-crawl
    python main.py scope                          # Show current scope
    python main.py history                        # Show scan history
    python main.py check-tools                    # Check installed tools (resolves PD vs pip httpx)

Controls during scan:
    Ctrl+C  → pause at next phase boundary → [r]esume / [q]uit+save / [a]bort
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from pathlib import Path

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
    console.print(Panel(banner, title="v3.0.0", border_style="blue"))


# ── Commands ──────────────────────────────────────────────────────────────


@app.command()
def scan(
    scope: str = typer.Option("config/scope.yaml", help="Path to scope.yaml"),
    settings: str = typer.Option("config/settings.yaml", help="Path to settings.yaml"),
    phase: str = typer.Option(
        "",
        help=(
            "Run specific phase: recon, active_recon, crawl|enumeration, "
            "ai_test|vuln, detect, correlate, ai, report"
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


# ── Output helpers ────────────────────────────────────────────────────────


def print_results(state, elapsed: float) -> None:
    """Print a rich dashboard of scan results."""
    console.print(f"\n[bold cyan]═══ Scan Complete ({elapsed:.0f}s) ═══[/bold cyan]\n")

    # Stats panel
    stats_table = Table(show_header=False, box=None)
    stats_table.add_column("Metric", style="dim")
    stats_table.add_column("Value", style="bold")
    stats_table.add_row("Subdomains discovered", str(len(state.subdomains)))
    stats_table.add_row("Live hosts", str(len(state.live_hosts)))
    stats_table.add_row("Endpoints crawled", str(len(state.endpoints)))
    stats_table.add_row("JS files analyzed", str(len(state.js_files)))
    stats_table.add_row("Total findings", str(len(state.findings)))
    stats_table.add_row("Weak signals", str(len(state.weak_signals)))
    stats_table.add_row("Chained findings", str(len(state.chained_findings)))
    stats_table.add_row("AI enriched findings", str(getattr(state, "ai_enriched_findings", 0)))
    stats_table.add_row("AI test probes", str(getattr(state, "ai_test_probes", 0)))
    stats_table.add_row("AI test findings", str(getattr(state, "ai_test_findings", 0)))
    stats_table.add_row("Errors", str(len(state.errors)))
    console.print(Panel(stats_table, title="Scan Statistics", border_style="green"))

    # Findings table
    if state.findings:
        findings_table = Table(title=f"Findings ({len(state.findings)} total)")
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

        for i, f in enumerate(state.findings[:50], 1):
            sev = f.get("severity", "info")
            sev_style = sev_colors.get(sev, "dim")
            conf = f"{f.get('confidence', 0):.0%}"
            url = f.get("url", "")[:50]
            findings_table.add_row(
                str(i),
                f"[{sev_style}]{sev.upper()}[/{sev_style}]",
                conf,
                f.get("title", "")[:60],
                f.get("detector", ""),
                url,
            )

        console.print(findings_table)
    else:
        console.print("[yellow]No findings detected.[/yellow]")

    # Errors
    if state.errors:
        console.print(f"\n[red]Errors ({len(state.errors)}):[/red]")
        for err in state.errors:
            console.print(f"  [red]•[/red] {err}")


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
