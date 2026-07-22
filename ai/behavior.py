"""Deterministic behavior and authentication reconnaissance.

This produces hypotheses for the AI/reporting layers; it does not submit forms,
create accounts, or bypass authentication.
"""
from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import urlparse


AUTH_MARKERS = ("/login", "/signin", "/auth", "/oauth", "/sso", "/token", "/session", "/account")
SIGNUP_MARKERS = ("/signup", "/register", "/join", "/create-account")
API_MARKERS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/json")
WAF_HINTS = ("cloudflare", "akamai", "imperva", "sucuri", "aws-waf", "mod_security")


def analyze_behavior(state: Any) -> dict[str, Any]:
    endpoints = list(getattr(state, "endpoints", []) or [])
    urls = [str(e.get("url", "")) for e in endpoints if e.get("url")]
    auth = [u for u in urls if any(m in u.lower() for m in AUTH_MARKERS)]
    signup = [u for u in urls if any(m in u.lower() for m in SIGNUP_MARKERS)]
    api_ish = [u for u in urls if any(m in u.lower() for m in API_MARKERS)]
    mechanisms = []
    for u in auth:
        low = u.lower()
        if "/oauth" in low or "/sso" in low:
            mechanisms.append("oauth_or_sso")
        elif "/token" in low or "/jwt" in low:
            mechanisms.append("token_or_jwt")
        elif "/session" in low or "/login" in low:
            mechanisms.append("session_cookie_candidate")

    methods = Counter(
        str(e.get("method", "GET")).upper()
        for e in endpoints
        if e.get("url")
    )
    status_codes = Counter(
        int(e.get("status") or 0)
        for e in endpoints
        if e.get("status")
    )

    waf_signals: list[str] = []
    tech = getattr(state, "tech_stack", {}) or {}
    for _url, profile in list(tech.items())[:40]:
        blob = ""
        if hasattr(profile, "frameworks"):
            blob = " ".join(str(x) for x in (getattr(profile, "frameworks", []) or []))
            blob += " " + " ".join(str(x) for x in (getattr(profile, "servers", []) or []))
        elif isinstance(profile, dict):
            blob = json_safe_blob(profile)
        low = blob.lower()
        for hint in WAF_HINTS:
            if hint in low:
                waf_signals.append(hint)

    hosts = sorted({
        (urlparse(u).hostname or "").lower()
        for u in urls
        if urlparse(u).hostname
    })

    result = {
        "hosts": hosts[:30],
        "authentication_endpoints": list(dict.fromkeys(auth))[:100],
        "signup_endpoints": list(dict.fromkeys(signup))[:50],
        "api_endpoints": list(dict.fromkeys(api_ish))[:80],
        "mechanisms": sorted(set(mechanisms)),
        "method_distribution": dict(methods.most_common(8)),
        "status_distribution": {str(k): v for k, v in status_codes.most_common(8)},
        "waf_signals": sorted(set(waf_signals)),
        "spa_likely": any(
            bool(getattr(p, "is_spa", False)) if hasattr(p, "is_spa")
            else bool((p or {}).get("is_spa")) if isinstance(p, dict) else False
            for p in tech.values()
        ),
        "behavior_hypotheses": [
            "Compare anonymous and explicitly authorized sessions on read-only endpoints."
            if auth else "No obvious authentication route discovered.",
            "Review account creation flow manually before any state-changing test."
            if signup else "No account creation route discovered.",
            "Prefer API/parameterized hunters; surface looks API-heavy."
            if len(api_ish) >= max(3, len(urls) // 5) else "Mixed or mostly HTML surface.",
            f"Possible edge protection: {', '.join(sorted(set(waf_signals)))}."
            if waf_signals else "No WAF fingerprint in tech stack yet.",
        ],
    }
    setattr(state, "behavior_model", result)
    return result


def json_safe_blob(profile: dict) -> str:
    parts: list[str] = []
    for key in ("frameworks", "servers", "languages", "cdn", "waf"):
        val = profile.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif val:
            parts.append(str(val))
    return " ".join(parts)
