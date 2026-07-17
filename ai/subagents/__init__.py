"""AI pentest subagents for local bug hunting."""

from ai.subagents.base import HunterSubagent, ProbePlan, PlannedProbe
from ai.subagents.xss_hunter import XSSHunter
from ai.subagents.idor_hunter import IDORHunter
from ai.subagents.ssrf_hunter import SSRFHunter
from ai.subagents.auth_hunter import AuthHunter
from ai.subagents.redirect_hunter import RedirectHunter

SUBAGENT_REGISTRY: dict[str, type[HunterSubagent]] = {
    "xss": XSSHunter,
    "idor": IDORHunter,
    "ssrf": SSRFHunter,
    "auth": AuthHunter,
    "open_redirect": RedirectHunter,
}

__all__ = [
    "HunterSubagent",
    "ProbePlan",
    "PlannedProbe",
    "SUBAGENT_REGISTRY",
    "XSSHunter",
    "IDORHunter",
    "SSRFHunter",
    "AuthHunter",
    "RedirectHunter",
]
