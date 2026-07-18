"""AI pentest subagents for local bug hunting."""

from ai.subagents.base import HunterSubagent, ProbePlan, PlannedProbe
from ai.subagents.xss_hunter import XSSHunter
from ai.subagents.idor_hunter import IDORHunter
from ai.subagents.ssrf_hunter import SSRFHunter
from ai.subagents.auth_hunter import AuthHunter
from ai.subagents.redirect_hunter import RedirectHunter
from ai.subagents.ssti_hunter import SSTIHunter
from ai.subagents.smuggling_hunter import SmugglingHunter
from ai.subagents.cors_hunter import CORSHunter
from ai.subagents.jwt_hunter import JWTHunter

SUBAGENT_REGISTRY: dict[str, type[HunterSubagent]] = {
    "xss": XSSHunter,
    "idor": IDORHunter,
    "ssrf": SSRFHunter,
    "auth": AuthHunter,
    "open_redirect": RedirectHunter,
    "ssti": SSTIHunter,
    "request_smuggling": SmugglingHunter,
    "cors": CORSHunter,
    "jwt": JWTHunter,
}

# Alias for convenience
SUBAGENT_REGISTRY["smuggling"] = SmugglingHunter

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
    "SSTIHunter",
    "SmugglingHunter",
    "CORSHunter",
    "JWTHunter",
]
