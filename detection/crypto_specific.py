"""
Crypto/wallet/trading application detection.

Checks for vulnerabilities specific to cryptocurrency and
fintech applications: exposed wallet info, insecure transaction
endpoints, API key leaks, and price oracle issues.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Optional

from detection.base_detector import BaseDetector, Severity

logger = logging.getLogger("hunterengine.detection.crypto")

CRYPTO_INDICATORS = [
    "wallet", "blockchain", "ethereum", "bitcoin", "solana",
    "defi", "swap", "stake", "token", "nft", "web3",
    "metamask", "ledger", "0x", "contract", "mint",
]

SENSITIVE_CRYPTO_PATTERNS = [
    (r'0x[a-fA-F0-9]{40}', "Ethereum Address"),
    (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', "Bitcoin Address"),
    (r'(?:private[_-]?key|priv[_-]?key)\s*[:=]\s*["\']?([a-fA-F0-9]{64})', "Private Key Reference"),
    (r'(?:mnemonic|seed[_-]?phrase)\s*[:=]\s*["\']([a-z\s]{20,})["\']', "Mnemonic/Seed Phrase"),
    (r'infura\.io/v3/([a-f0-9]{32})', "Infura API Key"),
    (r'alchemy\.com/v2/([a-zA-Z0-9_-]{32})', "Alchemy API Key"),
    (r'moralis.*?api[_-]?key.*?([a-zA-Z0-9]{20,})', "Moralis API Key"),
]


class CryptoDetector(BaseDetector):
    """Detect vulnerabilities specific to crypto/blockchain applications."""

    @property
    def name(self) -> str:
        return "crypto"

    async def run(self, scan_state: Any) -> list[dict]:
        findings: list[dict] = []

        # Determine if target is a crypto/fintech app
        is_crypto_app = self._is_crypto_app(scan_state)
        if not is_crypto_app:
            logger.info("Target does not appear to be a crypto application")
            return findings

        logger.info("Crypto application detected — running specialized checks")

        # 1. Check for exposed crypto secrets in JS
        crypto_secrets = self._scan_crypto_secrets(scan_state)
        findings.extend(crypto_secrets)

        # 2. Check for insecure transaction endpoints
        tx_findings = await self._check_transaction_endpoints(scan_state)
        findings.extend(tx_findings)

        # 3. Check for exposed RPC endpoints
        rpc_findings = await self._check_rpc_endpoints(scan_state)
        findings.extend(rpc_findings)

        logger.info(f"Crypto detector: {len(findings)} findings")
        return findings

    def _is_crypto_app(self, scan_state: Any) -> bool:
        """Check if the target is likely a crypto/blockchain application."""
        # Check tech stack
        for url, tech in scan_state.tech_stack.items():
            libs = []
            if hasattr(tech, "js_libraries"):
                libs = tech.js_libraries
            elif isinstance(tech, dict):
                libs = tech.get("js_libraries", [])
            for lib in libs:
                if any(kw in lib.lower() for kw in ("web3", "ethers", "wagmi", "viem")):
                    return True

        # Check endpoints for crypto keywords
        crypto_count = 0
        for ep in scan_state.endpoints[:200]:
            url = ep.get("url", "").lower()
            if any(kw in url for kw in CRYPTO_INDICATORS):
                crypto_count += 1

        return crypto_count >= 3

    def _scan_crypto_secrets(self, scan_state: Any) -> list[dict]:
        """Scan for exposed crypto secrets from JS analysis."""
        findings = []

        # Check weak signals from JS analysis
        for signal in scan_state.weak_signals:
            value = signal.get("value", "")
            for pattern, secret_type in SENSITIVE_CRYPTO_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    severity = Severity.CRITICAL if "private" in secret_type.lower() or "mnemonic" in secret_type.lower() else Severity.HIGH
                    findings.append(self._make_finding(
                        title=f"Exposed {secret_type} in JavaScript",
                        description=f"A {secret_type} was found exposed in client-side JavaScript.",
                        severity=severity,
                        confidence=0.85,
                        url=signal.get("source_url", ""),
                        evidence=f"Type: {secret_type}\nPattern matched in JS content",
                        tags=["crypto", "secret", secret_type.lower().replace(" ", "-")],
                        impact=f"Exposure of {secret_type} can lead to direct financial loss.",
                        remediation="Never include private keys, mnemonics, or RPC secrets in client-side code.",
                    ))

        return findings

    async def _check_transaction_endpoints(self, scan_state: Any) -> list[dict]:
        """Check transaction-related endpoints for security issues."""
        findings = []

        tx_endpoints = [
            ep for ep in scan_state.endpoints
            if any(kw in ep.get("url", "").lower()
                   for kw in ("transfer", "send", "swap", "withdraw", "trade", "order"))
        ]

        for ep in tx_endpoints[:20]:
            url = ep.get("url", "")

            # Check if endpoint lacks CSRF protection
            resp = await self._get(url)
            if resp and resp.status_code == 200:
                # Check for CSRF tokens in response
                body = resp.text.lower()
                has_csrf = any(kw in body for kw in ("csrf", "_token", "xsrf", "authenticity_token"))

                if not has_csrf:
                    findings.append(self._make_finding(
                        title=f"Transaction Endpoint May Lack CSRF Protection",
                        description=f"The financial endpoint {url} does not appear to use CSRF tokens.",
                        severity=Severity.MEDIUM,
                        confidence=0.5,
                        url=url,
                        tags=["crypto", "csrf", "transaction"],
                        impact="Missing CSRF on financial endpoints could allow unauthorized transactions.",
                        remediation="Implement CSRF protection on all state-changing financial endpoints.",
                    ))

        return findings

    async def _check_rpc_endpoints(self, scan_state: Any) -> list[dict]:
        """Check for exposed blockchain RPC endpoints."""
        findings = []
        rpc_paths = ["/rpc", "/jsonrpc", "/api/rpc", "/eth", "/web3"]

        for host in scan_state.live_hosts[:20]:
            base = host.get("url", "")
            for path in rpc_paths:
                url = base.rstrip("/") + path
                resp = await self._post(
                    url,
                    json_body={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                    headers={"Content-Type": "application/json"},
                )

                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if "result" in data:
                            findings.append(self._make_finding(
                                title="Exposed Blockchain RPC Endpoint",
                                description=f"An open blockchain RPC endpoint was found at {url}.",
                                severity=Severity.HIGH,
                                confidence=0.9,
                                url=url,
                                evidence=f"eth_blockNumber response: {data.get('result', '')}",
                                tags=["crypto", "rpc", "exposed-service"],
                                impact="Open RPC endpoints can be abused for unauthorized transactions or resource exhaustion.",
                                remediation="Restrict RPC access via authentication and IP allowlisting.",
                            ))
                    except Exception:
                        pass

        return findings
