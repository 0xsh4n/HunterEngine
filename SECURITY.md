# Security Policy

## ⚠️ Legal Notice

HunterEngine is a **defensive security tool** intended for use by authorized security professionals conducting **bug bounty** and **penetration testing** with **explicit written permission** from the target organization.

**Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical.** The authors and contributors are not responsible for misuse.

## Reporting a Vulnerability

If you discover a security vulnerability **in HunterEngine itself** (not a vulnerability found by HunterEngine during a scan), please report it responsibly:

1. **Do NOT** open a public GitHub issue.
2. Email the maintainers at: `security@hunterengine.dev` (or open a private security advisory on GitHub).
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within **48 hours** and aim to release a fix within **7 days** for critical issues.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Active support   |
| 1.x     | ⚠️ Security fixes only |
| < 1.0   | ❌ Not supported    |

## Responsible Use Guidelines

When using HunterEngine:

- ✅ **DO** only test targets you are **authorized** to test.
- ✅ **DO** respect `scope.yaml` boundaries — the engine enforces them, and so should you.
- ✅ **DO** follow your bug bounty program's rules of engagement.
- ✅ **DO** report findings responsibly through the program's platform.
- ❌ **DO NOT** use this tool for unauthorized access, data exfiltration, or denial of service.
- ❌ **DO NOT** disable scope enforcement or modify the tool to bypass authorization checks.
- ❌ **DO NOT** share findings publicly before the program has addressed them.

## Data Handling

HunterEngine stores scan data locally in `data/`. This may contain sensitive information:

- Discovered endpoints and parameters
- HTTP request/response captures
- Authentication tokens (if configured)
- Vulnerability evidence

**Protect this data.** Do not commit the `data/` directory to version control (it is excluded by `.gitignore`).
