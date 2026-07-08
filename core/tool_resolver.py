"""Helpers for resolving external security tools safely."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional


def find_projectdiscovery_httpx() -> Optional[str]:
    """Return the ProjectDiscovery httpx binary, not Python's httpx package CLI."""
    candidates = _which_all("httpx")
    for candidate in candidates:
        if _is_venv_python_httpx(candidate):
            continue
        try:
            proc = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception:
            continue
        output = f"{proc.stdout}\n{proc.stderr}".lower()
        if "projectdiscovery" in output or "current version" in output:
            return candidate
    return None


def _which_all(command: str) -> list[str]:
    seen = set()
    results = []
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        path = Path(directory) / command
        if not path.exists() or not os.access(path, os.X_OK):
            continue
        resolved = str(path.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        results.append(str(path))

    fallback = shutil.which(command)
    if fallback and str(Path(fallback).resolve()) not in seen:
        results.append(fallback)
    return results


def _is_venv_python_httpx(path: str) -> bool:
    candidate = Path(path).resolve()
    venv_bin = Path(sys.prefix).resolve() / "bin"
    if venv_bin not in candidate.parents:
        return False
    try:
        text = candidate.read_text(errors="ignore")[:300]
    except Exception:
        return False
    return "httpx" in text.lower() and "projectdiscovery" not in text.lower()
