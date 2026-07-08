"""
Auth session handling.

Manages authenticated sessions, cookie jars, token refresh,
and session persistence across engine runs.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx


@dataclass
class Session:
    name: str
    domain: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "domain": self.domain,
            "cookies": self.cookies,
            "headers": self.headers,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Session:
        return cls(**data)


class SessionManager:
    """
    Manage multiple auth sessions.

    Sessions can be created via:
      - Manual header/cookie injection
      - Login flow (POST credentials)
      - Browser-based login (Playwright)
    """

    def __init__(self, sessions_dir: str | Path = "data/sessions") -> None:
        self.sessions_dir = Path(sessions_dir)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, Session] = {}

    # ── Session CRUD ──────────────────────────────────────────────────────

    def create_session(
        self,
        name: str,
        domain: str,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        expires_at: Optional[float] = None,
    ) -> Session:
        """Create and register a new session."""
        session = Session(
            name=name,
            domain=domain,
            cookies=cookies or {},
            headers=headers or {},
            expires_at=expires_at,
        )
        self._sessions[name] = session
        self._persist(session)
        return session

    def get_session(self, name: str) -> Optional[Session]:
        """Retrieve a session by name, loading from disk if needed."""
        if name not in self._sessions:
            self._load(name)
        session = self._sessions.get(name)
        if session and session.is_expired:
            return None
        return session

    def get_session_for_domain(self, domain: str) -> Optional[Session]:
        """Find any valid session matching the given domain."""
        for sess in self._sessions.values():
            if domain.endswith(sess.domain) and not sess.is_expired:
                return sess
        # Try loading from disk
        for path in self.sessions_dir.glob("*.json"):
            name = path.stem
            if name not in self._sessions:
                self._load(name)
                sess = self._sessions.get(name)
                if sess and domain.endswith(sess.domain) and not sess.is_expired:
                    return sess
        return None

    def delete_session(self, name: str) -> None:
        self._sessions.pop(name, None)
        path = self.sessions_dir / f"{name}.json"
        path.unlink(missing_ok=True)

    def list_sessions(self) -> list[Session]:
        # Load all from disk
        for path in self.sessions_dir.glob("*.json"):
            name = path.stem
            if name not in self._sessions:
                self._load(name)
        return list(self._sessions.values())

    # ── Login flows ───────────────────────────────────────────────────────

    async def login_with_credentials(
        self,
        name: str,
        login_url: str,
        domain: str,
        credentials: dict[str, str],
        extra_headers: Optional[dict[str, str]] = None,
    ) -> Optional[Session]:
        """
        Perform a POST login and capture session cookies/tokens.
        """
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.post(
                login_url,
                data=credentials,
                headers=extra_headers or {},
            )
            if resp.status_code < 400:
                cookies = dict(resp.cookies)
                # Check for auth tokens in response
                auth_header = {}
                try:
                    body = resp.json()
                    for key in ("token", "access_token", "jwt", "session_token"):
                        if key in body:
                            auth_header["Authorization"] = f"Bearer {body[key]}"
                            break
                except Exception:
                    pass

                session = self.create_session(
                    name=name,
                    domain=domain,
                    cookies=cookies,
                    headers={**(extra_headers or {}), **auth_header},
                )
                return session
        return None

    def apply_to_request(self, headers: dict[str, str], domain: str) -> dict[str, str]:
        """Merge session auth into an outgoing request's headers."""
        session = self.get_session_for_domain(domain)
        if not session:
            return headers

        merged = {**headers}
        merged.update(session.headers)
        if session.cookies:
            existing = merged.get("Cookie", "")
            cookie_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            merged["Cookie"] = f"{existing}; {cookie_str}".strip("; ") if existing else cookie_str
        return merged

    # ── Persistence ───────────────────────────────────────────────────────

    def _persist(self, session: Session) -> None:
        path = self.sessions_dir / f"{session.name}.json"
        path.write_text(json.dumps(session.to_dict(), indent=2))

    def _load(self, name: str) -> None:
        path = self.sessions_dir / f"{name}.json"
        if path.exists():
            data = json.loads(path.read_text())
            self._sessions[name] = Session.from_dict(data)
