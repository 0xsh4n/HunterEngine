"""Deterministic behavior and authentication reconnaissance.

This produces hypotheses and a scored attack-surface model for the AI /
reporting layers; it does not submit forms, create accounts, or bypass
authentication. Everything here is passive inference over already-discovered
endpoints and fingerprints.
"""
from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import parse_qs, urlparse


AUTH_MARKERS = ("/login", "/signin", "/auth", "/oauth", "/sso", "/token", "/session", "/account")
SIGNUP_MARKERS = ("/signup", "/register", "/join", "/create-account")
API_MARKERS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/json")
WAF_HINTS = ("cloudflare", "akamai", "imperva", "sucuri", "aws-waf", "mod_security")

# Sensitive surface categories → (path markers, base risk weight). These drive
# a prioritized "focus areas" list the hunters and the dashboard consume.
SURFACE_CATEGORIES: dict[str, tuple[tuple[str, ...], float]] = {
    "admin": (("/admin", "/manage", "/console", "/dashboard", "/internal", "/backoffice"), 3.0),
    "auth": (AUTH_MARKERS, 2.5),
    "account": (("/account", "/profile", "/settings", "/user", "/users", "/me"), 2.2),
    "payment": (("/pay", "/payment", "/billing", "/checkout", "/invoice", "/subscription", "/wallet"), 3.0),
    "file": (("/upload", "/file", "/files", "/import", "/export", "/attachment", "/media", "/download"), 2.4),
    "api": (API_MARKERS, 2.0),
    "graphql": (("/graphql", "/gql"), 2.6),
    "idor_prone": (("/api/", "/orders", "/order/", "/documents", "/records", "/items", "/id="), 2.3),
    "redirect": (("redirect", "return", "next=", "url=", "callback", "continue="), 1.8),
    "debug": (("/debug", "/actuator", "/.git", "/.env", "/phpinfo", "/swagger", "/api-docs", "/openapi"), 2.8),
}

# Object-reference-style path segments (numeric / uuid-ish) hint at IDOR surface.
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def analyze_behavior(state: Any) -> dict[str, Any]:
    endpoints = list(getattr(state, "endpoints", []) or [])
    urls = [str(e.get("url", "")) for e in endpoints if e.get("url")]
    low_urls = [u.lower() for u in urls]

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

    # ── Deeper structural analysis ────────────────────────────────────────
    parameterized = _parameterized_endpoints(endpoints)
    numeric_ref = [u for u in urls if _has_object_reference(u)]
    state_changing = [
        str(e.get("url", ""))
        for e in endpoints
        if str(e.get("method", "GET")).upper() in STATE_CHANGING
    ]
    surface = _score_surface(low_urls)
    focus_areas = _focus_areas(surface, parameterized, state_changing, waf_signals)
    auth_posture = _auth_posture(status_codes, auth, api_ish)

    result = {
        "hosts": hosts[:30],
        "endpoint_total": len(urls),
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
        # New structural signals
        "parameterized_endpoints": len(parameterized),
        "top_parameters": _top_parameters(parameterized),
        "object_reference_endpoints": len(numeric_ref),
        "state_changing_endpoints": len(state_changing),
        "attack_surface": surface,
        "focus_areas": focus_areas,
        "auth_posture": auth_posture,
        "risk_score": round(sum(f["score"] for f in focus_areas), 2),
        "behavior_hypotheses": _hypotheses(
            auth, signup, api_ish, urls, waf_signals, surface, numeric_ref, state_changing
        ),
    }
    setattr(state, "behavior_model", result)
    return result


def _parameterized_endpoints(endpoints: list[dict]) -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = []
    for e in endpoints:
        url = str(e.get("url", ""))
        if not url:
            continue
        params = list(e.get("params") or [])
        if not params:
            params = list(parse_qs(urlparse(url).query).keys())
        if params:
            out.append((url, [str(p) for p in params]))
    return out


def _top_parameters(parameterized: list[tuple[str, list[str]]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for _url, params in parameterized:
        for p in params:
            counter[p] += 1
    return dict(counter.most_common(12))


def _has_object_reference(url: str) -> bool:
    path = urlparse(url).path
    for seg in path.split("/"):
        if seg.isdigit():
            return True
        # uuid-ish / long hex id
        if len(seg) >= 16 and all(c in "0123456789abcdef-" for c in seg.lower()):
            return True
    query = urlparse(url).query.lower()
    return any(k in query for k in ("id=", "uid=", "user=", "account=", "order="))


def _score_surface(low_urls: list[str]) -> list[dict[str, Any]]:
    surface: list[dict[str, Any]] = []
    for name, (markers, weight) in SURFACE_CATEGORIES.items():
        hits = [u for u in low_urls if any(m in u for m in markers)]
        if not hits:
            continue
        # Diminishing returns: presence matters more than raw count.
        score = round(weight * (1 + min(len(hits), 20) / 20.0), 2)
        surface.append({
            "category": name,
            "weight": weight,
            "hits": len(hits),
            "score": score,
            "examples": hits[:3],
        })
    surface.sort(key=lambda s: s["score"], reverse=True)
    return surface


def _focus_areas(
    surface: list[dict[str, Any]],
    parameterized: list[tuple[str, list[str]]],
    state_changing: list[str],
    waf_signals: list[str],
) -> list[dict[str, Any]]:
    """Turn the surface + structure into a ranked, hunter-oriented plan."""
    hunter_map = {
        "admin": ["auth", "idor"],
        "auth": ["auth", "jwt"],
        "account": ["idor", "auth"],
        "payment": ["idor", "auth"],
        "file": ["ssrf", "xss"],
        "api": ["idor", "ssrf"],
        "graphql": ["idor", "ssrf"],
        "idor_prone": ["idor"],
        "redirect": ["open_redirect"],
        "debug": ["auth", "ssrf"],
    }
    areas: list[dict[str, Any]] = []
    for item in surface:
        score = item["score"]
        # Parameterized + state-changing surface amplifies injection/idor risk.
        if item["category"] in ("api", "idor_prone", "account") and parameterized:
            score += min(len(parameterized), 15) * 0.05
        if item["category"] in ("payment", "account", "admin") and state_changing:
            score += 0.5
        if waf_signals:
            score -= 0.3  # edge protection lowers naive exploitability
        areas.append({
            "area": item["category"],
            "score": round(max(score, 0.0), 2),
            "suggest_hunters": hunter_map.get(item["category"], []),
            "why": f"{item['hits']} endpoint(s) match {item['category']} surface",
            "examples": item["examples"],
        })
    areas.sort(key=lambda a: a["score"], reverse=True)
    return areas[:8]


def _auth_posture(status_codes: Counter, auth: list[str], api_ish: list[str]) -> dict[str, Any]:
    total = sum(status_codes.values()) or 1
    unauthorized = status_codes.get(401, 0) + status_codes.get(403, 0)
    return {
        "has_auth_routes": bool(auth),
        "api_heavy": len(api_ish) >= 3,
        "unauthorized_ratio": round(unauthorized / total, 3),
        "observed_401_403": unauthorized,
        "posture": (
            "enforced" if unauthorized and unauthorized / total > 0.2
            else "mixed" if unauthorized
            else "permissive_or_unknown"
        ),
    }


def _hypotheses(
    auth: list[str],
    signup: list[str],
    api_ish: list[str],
    urls: list[str],
    waf_signals: list[str],
    surface: list[dict[str, Any]],
    numeric_ref: list[str],
    state_changing: list[str],
) -> list[str]:
    out = [
        "Compare anonymous and explicitly authorized sessions on read-only endpoints."
        if auth else "No obvious authentication route discovered.",
        "Review account creation flow manually before any state-changing test."
        if signup else "No account creation route discovered.",
        "Prefer API/parameterized hunters; surface looks API-heavy."
        if len(api_ish) >= max(3, len(urls) // 5) else "Mixed or mostly HTML surface.",
        f"Possible edge protection: {', '.join(sorted(set(waf_signals)))}."
        if waf_signals else "No WAF fingerprint in tech stack yet.",
    ]
    if numeric_ref:
        out.append(
            f"{len(numeric_ref)} endpoint(s) expose object references — prioritize IDOR "
            "checks with a second authorized identity (read-only)."
        )
    if state_changing:
        out.append(
            f"{len(state_changing)} state-changing route(s) seen — do NOT auto-fire; "
            "these need explicit authorization before any active test."
        )
    if surface:
        top = ", ".join(f"{s['category']}({s['score']})" for s in surface[:3])
        out.append(f"Highest-value surface by score: {top}.")
    return out


def json_safe_blob(profile: dict) -> str:
    parts: list[str] = []
    for key in ("frameworks", "servers", "languages", "cdn", "waf"):
        val = profile.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif val:
            parts.append(str(val))
    return " ".join(parts)
