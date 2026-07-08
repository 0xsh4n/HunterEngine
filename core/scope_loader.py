"""
Scope validation & enforcement.

Every module calls ScopeLoader.is_in_scope(url) before making any request.
Ensures the engine never touches out-of-scope assets.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml
import tldextract


@dataclass
class AuthConfig:
    auth_type: str = "none"
    token: str = ""
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    credentials: dict[str, str] = field(default_factory=dict)


@dataclass
class Scope:
    program_name: str = ""
    platform: str = ""
    program_url: str = ""

    in_scope_domains: list[str] = field(default_factory=list)
    in_scope_cidrs: list[str] = field(default_factory=list)
    in_scope_urls: list[str] = field(default_factory=list)

    out_of_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_cidrs: list[str] = field(default_factory=list)
    out_of_scope_urls: list[str] = field(default_factory=list)
    out_of_scope_keywords: list[str] = field(default_factory=list)

    auth: AuthConfig = field(default_factory=AuthConfig)


class ScopeLoader:
    """Load, validate, and enforce target scope from scope.yaml."""

    def __init__(self, scope_path: str | Path = "config/scope.yaml") -> None:
        self.scope_path = Path(scope_path)
        self.scope = Scope()
        self._compiled_in: list[re.Pattern] = []
        self._compiled_out: list[re.Pattern] = []
        self._in_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._out_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    # ── Loading ────────────────────────────────────────────────────────────

    def load(self) -> Scope:
        """Parse scope.yaml and compile patterns."""
        if not self.scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {self.scope_path}")

        raw = yaml.safe_load(self.scope_path.read_text())

        program = raw.get("program", {})
        self.scope.program_name = program.get("name", "")
        self.scope.platform = program.get("platform", "")
        self.scope.program_url = program.get("url", "")

        in_s = raw.get("in_scope", {})
        self.scope.in_scope_domains = in_s.get("domains", [])
        self.scope.in_scope_cidrs = in_s.get("cidrs", [])
        self.scope.in_scope_urls = in_s.get("urls", [])

        out_s = raw.get("out_of_scope", {})
        self.scope.out_of_scope_domains = out_s.get("domains", [])
        self.scope.out_of_scope_cidrs = out_s.get("cidrs", [])
        self.scope.out_of_scope_urls = out_s.get("urls", [])
        self.scope.out_of_scope_keywords = out_s.get("keywords", [])

        auth_raw = raw.get("auth", {})
        self.scope.auth = AuthConfig(
            auth_type=auth_raw.get("type", "none"),
            token=auth_raw.get("token", ""),
            cookie=auth_raw.get("cookie", ""),
            headers=auth_raw.get("headers", {}),
            login_url=auth_raw.get("login_url", ""),
            credentials=auth_raw.get("credentials", {}),
        )

        self._compile_patterns()
        return self.scope

    def _compile_patterns(self) -> None:
        """Compile wildcard domain patterns to regex for fast matching."""
        self._compiled_in = [self._glob_to_regex(d) for d in self.scope.in_scope_domains]
        self._compiled_out = [self._glob_to_regex(d) for d in self.scope.out_of_scope_domains]
        self._in_networks = [ipaddress.ip_network(c, strict=False) for c in self.scope.in_scope_cidrs]
        self._out_networks = [ipaddress.ip_network(c, strict=False) for c in self.scope.out_of_scope_cidrs]

    @staticmethod
    def _glob_to_regex(pattern: str) -> re.Pattern:
        """Convert a wildcard domain pattern (e.g. *.example.com) to regex."""
        escaped = re.escape(pattern).replace(r"\*", r"[a-zA-Z0-9\-\.]*")
        return re.compile(f"^{escaped}$", re.IGNORECASE)

    # ── Scope checks ──────────────────────────────────────────────────────

    def is_in_scope(self, url_or_host: str) -> bool:
        """
        Check whether a URL or hostname falls within the defined scope.
        Returns True only if it matches in-scope AND does not match out-of-scope.
        """
        host = self._extract_host(url_or_host)
        path = self._extract_path(url_or_host)

        if self._is_out_of_scope_domain(host):
            return False
        if self._is_out_of_scope_url(url_or_host):
            return False
        if self._matches_blocked_keyword(path):
            return False
        if self._is_out_of_scope_cidr(host):
            return False

        return self._is_in_scope_domain(host) or self._is_in_scope_cidr(host)

    def filter_in_scope(self, urls: list[str]) -> list[str]:
        """Filter a list of URLs to only those in scope."""
        return [u for u in urls if self.is_in_scope(u)]

    def _is_in_scope_domain(self, host: str) -> bool:
        return any(p.match(host) for p in self._compiled_in)

    def _is_out_of_scope_domain(self, host: str) -> bool:
        return any(p.match(host) for p in self._compiled_out)

    def _is_in_scope_cidr(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._in_networks)
        except ValueError:
            return False

    def _is_out_of_scope_cidr(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
            return any(addr in net for net in self._out_networks)
        except ValueError:
            return False

    def _is_out_of_scope_url(self, url: str) -> bool:
        for pattern in self.scope.out_of_scope_urls:
            if fnmatch.fnmatch(url, pattern):
                return True
        return False

    def _matches_blocked_keyword(self, path: str) -> bool:
        path_lower = path.lower()
        return any(kw.lower() in path_lower for kw in self.scope.out_of_scope_keywords)

    # ── Extraction helpers ────────────────────────────────────────────────

    @staticmethod
    def _extract_host(url_or_host: str) -> str:
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            host = parsed.hostname or ""
        else:
            host = url_or_host.split("/")[0].split(":")[0]
        return host.lower()

    @staticmethod
    def _extract_path(url_or_host: str) -> str:
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            return parsed.path
        parts = url_or_host.split("/", 1)
        return f"/{parts[1]}" if len(parts) > 1 else "/"

    def get_root_domains(self) -> list[str]:
        """Return deduplicated root domains from in-scope patterns."""
        roots = set()
        for d in self.scope.in_scope_domains:
            clean = d.lstrip("*.")
            ext = tldextract.extract(clean)
            if ext.domain and ext.suffix:
                roots.add(f"{ext.domain}.{ext.suffix}")
        return sorted(roots)

    def get_auth_headers(self) -> dict[str, str]:
        """Build auth headers based on scope auth config."""
        headers: dict[str, str] = {}
        auth = self.scope.auth

        if auth.auth_type == "bearer" and auth.token:
            headers["Authorization"] = f"Bearer {auth.token}"
        elif auth.auth_type == "cookie" and auth.cookie:
            headers["Cookie"] = auth.cookie
        elif auth.auth_type == "basic":
            import base64
            creds = auth.credentials
            encoded = base64.b64encode(
                f"{creds.get('username', '')}:{creds.get('password', '')}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {encoded}"

        headers.update(auth.headers)
        return headers

    def summary(self) -> str:
        """Return a human-readable scope summary."""
        lines = [
            f"Program: {self.scope.program_name} ({self.scope.platform})",
            f"In-scope domains: {', '.join(self.scope.in_scope_domains) or 'none'}",
            f"In-scope CIDRs: {', '.join(self.scope.in_scope_cidrs) or 'none'}",
            f"Out-of-scope domains: {', '.join(self.scope.out_of_scope_domains) or 'none'}",
            f"Out-of-scope keywords: {', '.join(self.scope.out_of_scope_keywords) or 'none'}",
            f"Auth type: {self.scope.auth.auth_type}",
        ]
        return "\n".join(lines)
