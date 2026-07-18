"""Helpers for resolving external security tools safely.

ProjectDiscovery ``httpx`` (Go binary) and the pip ``httpx`` Python package
both install a command named ``httpx``. HunterEngine uses:

- **pip httpx** — always via ``import httpx`` (Python library) inside the venv
- **ProjectDiscovery httpx** — only the Go binary, never the pip CLI wrapper
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def find_projectdiscovery_httpx() -> Optional[str]:
    """Return the ProjectDiscovery httpx Go binary, never the pip httpx CLI."""
    for candidate in _httpx_candidates():
        if _is_python_httpx_cli(candidate):
            continue
        if _looks_like_projectdiscovery_httpx(candidate):
            return candidate
    return None


def describe_httpx_resolution() -> dict[str, str]:
    """Human-readable httpx resolution summary for check-tools / docs."""
    pd = find_projectdiscovery_httpx()
    pip_cli = _find_python_httpx_cli()
    try:
        import httpx as pip_lib  # noqa: F401

        pip_lib_ver = getattr(pip_lib, "__version__", "installed")
    except ImportError:
        pip_lib_ver = "missing"

    return {
        "projectdiscovery_httpx": pd or "not found (live probe falls back to pip httpx)",
        "pip_httpx_library": f"available ({pip_lib_ver}) — used for HTTP client / detectors",
        "pip_httpx_cli": pip_cli or "not on PATH",
        "note": (
            "Inside the venv, `import httpx` is the Python library. "
            "Live probing prefers ProjectDiscovery httpx outside the venv/Scripts."
        ),
    }


def _httpx_candidates() -> list[str]:
    """Ordered search paths for httpx binaries (prefer Go install locations)."""
    seen: set[str] = set()
    results: list[str] = []

    def add(path: Path | str) -> None:
        p = Path(path)
        if not p.exists():
            return
        # Accept .exe on Windows even if X_OK is unreliable
        if sys.platform != "win32" and not os.access(p, os.X_OK):
            return
        resolved = str(p.resolve())
        if resolved in seen:
            return
        seen.add(resolved)
        results.append(str(p))

    # Prefer known Go / PD install locations first (outside venv)
    home = Path.home()
    go_paths = [
        home / "go" / "bin" / "httpx",
        home / "go" / "bin" / "httpx.exe",
        Path(os.environ.get("GOPATH", "")) / "bin" / "httpx" if os.environ.get("GOPATH") else None,
        Path(os.environ.get("GOPATH", "")) / "bin" / "httpx.exe" if os.environ.get("GOPATH") else None,
        Path(os.environ.get("GOBIN", "")) / "httpx" if os.environ.get("GOBIN") else None,
        Path(os.environ.get("GOBIN", "")) / "httpx.exe" if os.environ.get("GOBIN") else None,
        Path("/usr/local/bin/httpx"),
        Path("/usr/bin/httpx"),
        home / ".local" / "bin" / "httpx",
        home / "AppData" / "Local" / "Programs" / "httpx" / "httpx.exe",
    ]
    for gp in go_paths:
        if gp is not None:
            add(gp)

    # Then PATH entries (filtered later)
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        base = Path(directory)
        add(base / "httpx")
        add(base / "httpx.exe")
        add(base / "httpx.bat")
        add(base / "httpx.cmd")

    fallback = shutil.which("httpx")
    if fallback:
        add(fallback)

    return results


def _find_python_httpx_cli() -> Optional[str]:
    for candidate in _httpx_candidates():
        if _is_python_httpx_cli(candidate):
            return candidate
    return None


def _is_python_httpx_cli(path: str) -> bool:
    """
    True if this ``httpx`` is the pip package console script.

    Covers venv Scripts/bin, global Python Scripts, and shebang wrappers.
    """
    candidate = Path(path).resolve()
    name = candidate.name.lower()

    # Never treat a clearly named PD binary as pip
    if "projectdiscovery" in str(candidate).lower():
        return False

    # Inside active venv (Unix bin / Windows Scripts)
    prefixes = [
        Path(sys.prefix).resolve() / "bin",
        Path(sys.prefix).resolve() / "Scripts",
        Path(sys.exec_prefix).resolve() / "bin",
        Path(sys.exec_prefix).resolve() / "Scripts",
    ]
    for prefix in prefixes:
        try:
            if prefix in candidate.parents or candidate.parent == prefix:
                # Confirm it's the Python entry point, not a manually dropped PD binary
                return _file_looks_like_pip_httpx(candidate)
        except Exception:
            continue

    # Global Python Scripts dirs (e.g. .../Python314/Scripts/httpx.exe)
    parts_lower = [p.lower() for p in candidate.parts]
    if "scripts" in parts_lower and any("python" in p for p in parts_lower):
        return _file_looks_like_pip_httpx(candidate)

    if name in ("httpx", "httpx.exe", "httpx.bat", "httpx.cmd"):
        return _file_looks_like_pip_httpx(candidate) and not _looks_like_projectdiscovery_httpx(path)

    return False


def _file_looks_like_pip_httpx(candidate: Path) -> bool:
    """Inspect file content / metadata for pip console-script markers."""
    try:
        # .exe launchers from pip are binaries; check companion scripts or version
        if candidate.suffix.lower() in (".bat", ".cmd"):
            text = candidate.read_text(errors="ignore")[:800].lower()
            return "from httpx" in text or "httpx.__main__" in text or "python" in text

        if candidate.suffix.lower() == ".exe":
            # Try --help; pip httpx CLI mentions "HTTPX" / "AsyncClient" style usage,
            # but safest: run --version and see if ProjectDiscovery markers are absent
            # AND path is under a Python install.
            parent = str(candidate.parent).lower()
            if "python" in parent or "scripts" in parent or "venv" in parent or ".venv" in parent:
                # Confirm via version output (pip httpx has no "projectdiscovery")
                try:
                    proc = subprocess.run(
                        [str(candidate), "--version"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                    )
                    output = f"{proc.stdout}\n{proc.stderr}".lower()
                    if "projectdiscovery" in output or "current version" in output:
                        return False
                    # pip httpx --version often prints just a semver or usage
                    if "httpx" in output or proc.returncode == 0:
                        # Ambiguous — treat Scripts/*.exe without PD markers as pip
                        return "projectdiscovery" not in output
                except Exception:
                    return True
                return True
            return False

        # Shebang script
        text = candidate.read_text(errors="ignore")[:500].lower()
        if text.startswith("#!") and ("python" in text[:80]):
            return "projectdiscovery" not in text
        if "from httpx" in text or "httpx.__main__" in text:
            return True
    except Exception:
        pass
    return False


def _looks_like_projectdiscovery_httpx(path: str) -> bool:
    try:
        proc = subprocess.run(
            [path, "-version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = f"{proc.stdout}\n{proc.stderr}".lower()
        if "projectdiscovery" in output:
            return True
        # Older PD builds: "Current Version: v1.x.x"
        if "current version" in output and "httpx" in output:
            return True

        # Fallback: --version (some builds)
        proc2 = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output2 = f"{proc2.stdout}\n{proc2.stderr}".lower()
        if "projectdiscovery" in output2:
            return True
        if "current version" in output2:
            return True
    except Exception:
        return False
    return False


def _is_venv_python_httpx(path: str) -> bool:
    """Backward-compatible alias used by tests / callers."""
    return _is_python_httpx_cli(path)
