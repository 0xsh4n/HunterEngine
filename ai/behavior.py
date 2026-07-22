"""Deterministic behavior and authentication reconnaissance.

This produces hypotheses for the AI/reporting layers; it does not submit forms,
create accounts, or bypass authentication.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


AUTH_MARKERS = ("/login", "/signin", "/auth", "/oauth", "/sso", "/token", "/session", "/account")
SIGNUP_MARKERS = ("/signup", "/register", "/join", "/create-account")


def analyze_behavior(state: Any) -> dict[str, Any]:
    endpoints = list(getattr(state, "endpoints", []) or [])
    urls = [str(e.get("url", "")) for e in endpoints if e.get("url")]
    auth = [u for u in urls if any(m in u.lower() for m in AUTH_MARKERS)]
    signup = [u for u in urls if any(m in u.lower() for m in SIGNUP_MARKERS)]
    mechanisms = []
    for u in auth:
        low = u.lower()
        if "/oauth" in low or "/sso" in low: mechanisms.append("oauth_or_sso")
        elif "/token" in low or "/jwt" in low: mechanisms.append("token_or_jwt")
        elif "/session" in low or "/login" in low: mechanisms.append("session_cookie_candidate")
    result = {
        "authentication_endpoints": list(dict.fromkeys(auth))[:100],
        "signup_endpoints": list(dict.fromkeys(signup))[:50],
        "mechanisms": sorted(set(mechanisms)),
        "behavior_hypotheses": [
            "Compare anonymous and explicitly authorized sessions on read-only endpoints." if auth else "No obvious authentication route discovered.",
            "Review account creation flow manually before any state-changing test." if signup else "No account creation route discovered.",
        ],
    }
    setattr(state, "behavior_model", result)
    return result
