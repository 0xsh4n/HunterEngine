"""
WAF bypass layer.

Provides request-level evasion via UA rotation, referrer spoofing,
random delays, and header randomization. Works with the rate limiter
to adapt when blocks are detected.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Optional

from fake_useragent import UserAgent


@dataclass
class BypassConfig:
    ua_rotation: bool = True
    referrer_spoof: bool = True
    delay_range: tuple[float, float] = (0.5, 2.0)
    tls_impersonation: bool = False
    tls_browser: str = "chrome"
    ip_rotation_enabled: bool = False
    ip_rotation_provider: str = "aws"
    ip_rotation_regions: list[str] = field(default_factory=lambda: ["us-east-1"])


class WAFBypass:
    """Applies evasion headers and techniques to outgoing requests."""

    COMMON_REFERRERS = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "https://www.google.co.uk/search?q=",
        "https://search.yahoo.com/search?p=",
    ]

    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,fr;q=0.8",
        "en;q=0.9",
        "en-US,en;q=0.5",
    ]

    def __init__(self, config: Optional[BypassConfig] = None) -> None:
        self.config = config or BypassConfig()
        self._ua = UserAgent(fallback="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")

    def get_headers(self, target_host: str = "") -> dict[str, str]:
        """
        Build a set of headers designed to look like a normal browser.
        Returns a dict of HTTP headers to merge into requests.
        """
        headers: dict[str, str] = {}

        # User-Agent
        if self.config.ua_rotation:
            headers["User-Agent"] = self._ua.random
        else:
            headers["User-Agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )

        # Accept headers (browser-like)
        headers["Accept"] = (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        )
        headers["Accept-Language"] = random.choice(self.ACCEPT_LANGUAGES)
        headers["Accept-Encoding"] = "gzip, deflate, br"

        # Referrer
        if self.config.referrer_spoof:
            headers["Referer"] = random.choice(self.COMMON_REFERRERS)

        # Connection & cache (browser norms)
        headers["Connection"] = "keep-alive"
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])

        # Sec-Fetch headers (modern browser fingerprint)
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"

        return headers

    def get_random_delay(self) -> float:
        """Return a random delay within the configured range."""
        lo, hi = self.config.delay_range
        return random.uniform(lo, hi)

    def randomize_param_case(self, value: str) -> str:
        """Randomly change the case of alphabetic chars — defeats naive keyword WAFs."""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in value
        )

    def add_junk_params(self, params: dict[str, str], count: int = 2) -> dict[str, str]:
        """Add random harmless query params to confuse pattern-matching WAFs."""
        junk = {}
        for _ in range(count):
            key = "".join(random.choices(string.ascii_lowercase, k=random.randint(3, 8)))
            val = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(3, 12)))
            junk[key] = val
        return {**params, **junk}

    def get_ip_rotation_config(self) -> dict:
        """Return config dict for the IP rotation layer (AWS API Gateway, etc.)."""
        if not self.config.ip_rotation_enabled:
            return {"enabled": False}
        return {
            "enabled": True,
            "provider": self.config.ip_rotation_provider,
            "regions": self.config.ip_rotation_regions,
        }
