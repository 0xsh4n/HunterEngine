"""Opt-in synthetic account data for authorized test environments.

Generation is separated from submission. HunterEngine never creates accounts
unless a caller explicitly implements and enables an authorized workflow.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class SyntheticCredentials:
    email: str
    password: str


def generate_credentials(domain: str = "example.invalid") -> SyntheticCredentials:
    token = secrets.token_hex(6)
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    password = "HeTest!" + "".join(secrets.choice(alphabet) for _ in range(18))
    return SyntheticCredentials(f"hunter-{token}@{domain.lstrip('@')}", password)
