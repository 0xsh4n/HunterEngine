"""
Per-domain learning profiles.

After each scan, HunterEngine records how a site behaved (auth style, tech,
which hunters paid off, WAF / rate-limit signals) and reuses that profile on
later visits so ranking and AI prompts get smarter per domain — without
fine-tuning the LLM weights.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("hunterengine.memory.domain_learner")


def normalize_domain(value: str) -> str:
    """Extract a stable registrable-ish host key from a URL or hostname."""
    text = (value or "").strip().lower()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text
    host = urlparse(text).hostname or ""
    host = host.removeprefix("www.")
    return host


class DomainLearner:
    """JSON-backed store of per-domain behaviour profiles."""

    def __init__(self, store_dir: str = "data/domain_profiles") -> None:
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, domain: str) -> Path:
        safe = re.sub(r"[^a-z0-9._-]+", "_", domain)[:180] or "unknown"
        return self.store_dir / f"{safe}.json"

    def load(self, domain: str) -> dict[str, Any]:
        domain = normalize_domain(domain)
        if not domain:
            return self._empty(domain)
        path = self._path_for(domain)
        if not path.exists():
            return self._empty(domain)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("domain", domain)
                return data
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load domain profile %s: %s", path, exc)
        return self._empty(domain)

    def save(self, profile: dict[str, Any]) -> Path:
        domain = normalize_domain(str(profile.get("domain", "")))
        profile["domain"] = domain
        profile["updated_at"] = time.time()
        path = self._path_for(domain)
        path.write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")
        return path

    def list_profiles(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in sorted(self.store_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    rows.append({
                        "domain": data.get("domain", path.stem),
                        "scan_count": data.get("scan_count", 0),
                        "successful_classes": data.get("successful_classes", {}),
                        "preferred_subagents": data.get("preferred_subagents", []),
                        "auth_mechanisms": data.get("auth_mechanisms", []),
                        "total_findings": data.get("total_findings", 0),
                        "success_rate": data.get("success_rate", 0.0),
                        "hit_rate": data.get("hit_rate", 0.0),
                        "risk_score": data.get("risk_score", 0.0),
                        "focus_areas": data.get("focus_areas", []),
                        "class_effectiveness": data.get("class_effectiveness", {}),
                        "finding_history": data.get("finding_history", []),
                        "notes": data.get("notes", [])[-5:],
                        "updated_at": data.get("updated_at"),
                        "path": str(path),
                    })
            except (OSError, json.JSONDecodeError):
                continue
        rows.sort(key=lambda r: (r.get("risk_score") or 0, r.get("total_findings") or 0), reverse=True)
        return rows

    def analytics(self) -> dict[str, Any]:
        """Aggregate learning across all known domains (for the dashboard)."""
        rows = self.list_profiles()
        if not rows:
            return {
                "domains": 0, "total_scans": 0, "total_findings": 0,
                "avg_success_rate": 0.0, "top_classes": [], "top_hunters": [],
                "riskiest": [],
            }
        class_totals: dict[str, int] = {}
        hunter_totals: dict[str, int] = {}
        for r in rows:
            for cls, n in (r.get("successful_classes") or {}).items():
                class_totals[cls] = class_totals.get(cls, 0) + int(n or 0)
            for pos, name in enumerate(r.get("preferred_subagents") or []):
                hunter_totals[name] = hunter_totals.get(name, 0) + (6 - min(pos, 5))
        total_scans = sum(int(r.get("scan_count") or 0) for r in rows)
        total_findings = sum(int(r.get("total_findings") or 0) for r in rows)
        rates = [float(r.get("success_rate") or 0) for r in rows if r.get("scan_count")]
        return {
            "domains": len(rows),
            "total_scans": total_scans,
            "total_findings": total_findings,
            "avg_success_rate": round(sum(rates) / len(rates), 3) if rates else 0.0,
            "top_classes": [
                {"class": k, "count": v}
                for k, v in sorted(class_totals.items(), key=lambda kv: kv[1], reverse=True)[:8]
            ],
            "top_hunters": [
                {"hunter": k, "score": v}
                for k, v in sorted(hunter_totals.items(), key=lambda kv: kv[1], reverse=True)[:8]
            ],
            "riskiest": [
                {"domain": r["domain"], "risk_score": r.get("risk_score", 0),
                 "findings": r.get("total_findings", 0)}
                for r in rows[:6]
            ],
        }

    def context_for_targets(self, urls: list[str]) -> dict[str, Any]:
        """Aggregate profiles for hosts present in the current target set."""
        domains = sorted({normalize_domain(u) for u in urls if normalize_domain(u)})
        profiles = [self.load(d) for d in domains[:12]]
        profiles = [p for p in profiles if p.get("scan_count", 0) > 0]
        if not profiles:
            return {"domains": [], "hints": []}

        preferred: dict[str, int] = {}
        classes: dict[str, int] = {}
        auth: set[str] = set()
        hints: list[str] = []
        for p in profiles:
            for name in p.get("preferred_subagents", []) or []:
                preferred[str(name)] = preferred.get(str(name), 0) + 1
            for cls, count in (p.get("successful_classes", {}) or {}).items():
                classes[str(cls)] = classes.get(str(cls), 0) + int(count or 0)
            auth.update(str(a) for a in (p.get("auth_mechanisms", []) or []))
            for note in (p.get("notes", []) or [])[-3:]:
                hints.append(f"{p.get('domain')}: {note}")

        ranked_agents = [k for k, _ in sorted(preferred.items(), key=lambda kv: kv[1], reverse=True)]
        ranked_classes = [k for k, _ in sorted(classes.items(), key=lambda kv: kv[1], reverse=True)]
        return {
            "domains": [p.get("domain") for p in profiles],
            "preferred_subagents": ranked_agents[:8],
            "successful_classes": ranked_classes[:8],
            "auth_mechanisms": sorted(auth),
            "path_boosts": self._merge_path_boosts(profiles),
            "hints": hints[:12],
            "profiles": profiles,
        }

    def rank_subagents(self, default: list[str], domain_context: dict[str, Any]) -> list[str]:
        """Reorder hunters so historically useful ones run first."""
        preferred = list(domain_context.get("preferred_subagents") or [])
        if not preferred:
            return list(default)
        seen: set[str] = set()
        ordered: list[str] = []
        for name in preferred + list(default):
            if name in default and name not in seen:
                ordered.append(name)
                seen.add(name)
        return ordered

    def interest_boost(self, url: str, domain_context: dict[str, Any]) -> float:
        """Extra score for paths that previously yielded signal on this domain."""
        boosts = domain_context.get("path_boosts") or {}
        if not boosts:
            return 0.0
        path = urlparse(url).path.lower() or "/"
        score = 0.0
        for fragment, weight in boosts.items():
            if fragment and fragment in path:
                score += float(weight)
        return min(score, 3.0)

    def learn_from_scan(self, state: Any, scope_loader: Any = None) -> list[dict[str, Any]]:
        """
        Update profiles from scan behaviour + findings.

        Returns the list of updated profiles.
        """
        hosts = self._hosts_from_state(state, scope_loader)
        if not hosts:
            return []

        behavior = getattr(state, "behavior_model", {}) or {}
        findings = list(getattr(state, "findings", []) or [])
        weak = list(getattr(state, "weak_signals", []) or [])
        tech = getattr(state, "tech_stack", {}) or {}
        phase_health = getattr(state, "phase_health", {}) or {}
        updated: list[dict[str, Any]] = []

        for host in hosts:
            profile = self.load(host)
            profile["scan_count"] = int(profile.get("scan_count", 0)) + 1
            profile["auth_mechanisms"] = sorted(set(
                list(profile.get("auth_mechanisms", []) or [])
                + list(behavior.get("mechanisms", []) or [])
            ))
            profile["tech_signals"] = self._merge_tech(profile.get("tech_signals", {}), tech, host)
            profile["successful_classes"] = dict(profile.get("successful_classes", {}) or {})
            profile["path_hits"] = dict(profile.get("path_hits", {}) or {})
            profile["notes"] = list(profile.get("notes", []) or [])

            host_findings = [
                f for f in findings + weak
                if isinstance(f, dict) and host in normalize_domain(str(f.get("url", "")))
            ] or [
                f for f in findings + weak
                if isinstance(f, dict) and host in str(f.get("url", "")).lower()
            ]

            for finding in host_findings:
                cls = self._class_of(finding)
                if cls:
                    profile["successful_classes"][cls] = int(
                        profile["successful_classes"].get(cls, 0)
                    ) + 1
                path = urlparse(str(finding.get("url", ""))).path.lower() or "/"
                for fragment in self._path_fragments(path):
                    profile["path_hits"][fragment] = int(profile["path_hits"].get(fragment, 0)) + 1

            preferred = [
                cls for cls, _ in sorted(
                    profile["successful_classes"].items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )[:6]
            ]
            # Map finding classes to hunter names where they differ
            alias = {"open_redirect": "open_redirect", "request_smuggling": "request_smuggling"}
            profile["preferred_subagents"] = [alias.get(c, c) for c in preferred] or list(
                profile.get("preferred_subagents", []) or []
            )

            ai_health = phase_health.get("ai_test") or {}
            if ai_health.get("status") == "failed":
                note = f"ai_test failed: {ai_health.get('error', 'unknown')[:120]}"
                if note not in profile["notes"]:
                    profile["notes"].append(note)
            if behavior.get("mechanisms"):
                note = f"auth={','.join(behavior.get('mechanisms', [])[:4])}"
                if note not in profile["notes"][-5:]:
                    profile["notes"].append(note)
            profile["notes"] = profile["notes"][-30:]

            # ── Analytics: yield trend, risk surface, hunter effectiveness ──
            found = len(host_findings)
            ai_probes = int(getattr(state, "ai_test_probes", 0) or 0)
            profile["last_findings"] = found
            profile["last_ai_probes"] = ai_probes
            profile["total_findings"] = int(profile.get("total_findings", 0)) + found
            profile["success_rate"] = round(
                profile["total_findings"] / max(1, profile["scan_count"]), 3
            )
            profile["hit_rate"] = round(found / ai_probes, 3) if ai_probes else 0.0
            if behavior.get("risk_score") is not None:
                profile["risk_score"] = behavior.get("risk_score")
            if behavior.get("focus_areas"):
                profile["focus_areas"] = [
                    a.get("area") for a in behavior.get("focus_areas", [])[:6]
                ]
            history = list(profile.get("finding_history", []) or [])
            history.append({
                "ts": time.time(),
                "findings": found,
                "ai_probes": ai_probes,
                "risk_score": behavior.get("risk_score"),
            })
            profile["finding_history"] = history[-40:]
            # Track effectiveness per vuln class so ranking reflects real payoff.
            effectiveness = dict(profile.get("class_effectiveness", {}) or {})
            for cls, count in profile["successful_classes"].items():
                effectiveness[cls] = round(int(count) / max(1, profile["scan_count"]), 3)
            profile["class_effectiveness"] = effectiveness
            self.save(profile)
            updated.append(profile)
            logger.info(
                "Domain learning updated %s (scans=%d classes=%s)",
                host,
                profile["scan_count"],
                ",".join(profile.get("preferred_subagents", [])[:5]) or "none",
            )

        events = list(getattr(state, "learning_events", []) or [])
        for profile in updated:
            events.append({
                "type": "domain_learn",
                "domain": profile.get("domain"),
                "scan_count": profile.get("scan_count"),
                "preferred_subagents": profile.get("preferred_subagents", [])[:5],
                "result": "success",
            })
        setattr(state, "learning_events", events[-500:])
        setattr(state, "domain_profiles", {
            p["domain"]: {
                "scan_count": p.get("scan_count"),
                "preferred_subagents": p.get("preferred_subagents", []),
                "successful_classes": p.get("successful_classes", {}),
            }
            for p in updated
        })
        return updated

    @staticmethod
    def _empty(domain: str) -> dict[str, Any]:
        return {
            "domain": domain,
            "scan_count": 0,
            "auth_mechanisms": [],
            "tech_signals": {},
            "successful_classes": {},
            "preferred_subagents": [],
            "path_hits": {},
            "notes": [],
            "updated_at": None,
        }

    def _hosts_from_state(self, state: Any, scope_loader: Any) -> list[str]:
        hosts: set[str] = set()
        for ep in getattr(state, "endpoints", []) or []:
            host = normalize_domain(str(ep.get("url", "")))
            if host:
                hosts.add(host)
        for live in getattr(state, "live_hosts", []) or []:
            host = normalize_domain(str(live.get("url", live.get("host", ""))))
            if host:
                hosts.add(host)
        if scope_loader:
            for domain in scope_loader.get_root_domains() or []:
                host = normalize_domain(str(domain).removeprefix("*."))
                if host:
                    hosts.add(host)
            for url in getattr(getattr(scope_loader, "scope", None), "in_scope_urls", []) or []:
                host = normalize_domain(str(url))
                if host:
                    hosts.add(host)
        return sorted(hosts)[:20]

    @staticmethod
    def _class_of(finding: dict) -> str:
        detector = str(finding.get("detector", "")).lower()
        for name in (
            "xss", "idor", "ssti", "ssrf", "auth", "cors", "jwt",
            "open_redirect", "request_smuggling", "smuggling",
        ):
            if name in detector:
                return "request_smuggling" if name == "smuggling" else name
        return str(finding.get("vuln_class") or finding.get("type") or "").lower()

    @staticmethod
    def _path_fragments(path: str) -> list[str]:
        parts = [p for p in path.split("/") if p and not p.isdigit()]
        frags = []
        if parts:
            frags.append("/" + parts[0])
        if len(parts) >= 2:
            frags.append("/" + "/".join(parts[:2]))
        return frags

    @staticmethod
    def _merge_path_boosts(profiles: list[dict[str, Any]]) -> dict[str, float]:
        merged: dict[str, float] = {}
        for p in profiles:
            for path, hits in (p.get("path_hits", {}) or {}).items():
                merged[str(path)] = merged.get(str(path), 0.0) + min(float(hits), 5.0) * 0.35
        return dict(sorted(merged.items(), key=lambda kv: kv[1], reverse=True)[:40])

    @staticmethod
    def _merge_tech(existing: dict, tech_stack: dict, host: str) -> dict:
        out = dict(existing or {})
        for url, profile in (tech_stack or {}).items():
            if host not in str(url).lower():
                continue
            if hasattr(profile, "frameworks"):
                out["frameworks"] = list(dict.fromkeys(
                    list(out.get("frameworks", []) or [])
                    + list(getattr(profile, "frameworks", []) or [])
                ))[:12]
                out["is_spa"] = bool(getattr(profile, "is_spa", False) or out.get("is_spa"))
                out["has_graphql"] = bool(getattr(profile, "has_graphql", False) or out.get("has_graphql"))
            elif isinstance(profile, dict):
                for key in ("frameworks", "servers", "languages"):
                    if key in profile:
                        out[key] = list(dict.fromkeys(
                            list(out.get(key, []) or []) + list(profile.get(key) or [])
                        ))[:12]
        return out
