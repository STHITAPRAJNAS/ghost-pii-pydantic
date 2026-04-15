# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

GhostPII is a security-focused library. If you discover a vulnerability — especially one that could cause PII to leak in contexts where it should be redacted — please report it **privately** rather than opening a public issue.

**How to report:**

1. Open a [GitHub Security Advisory](https://github.com/STHITAPRAJNAS/ghost-pii-pydantic/security/advisories/new) (preferred — keeps details private until patched).
2. Alternatively, email **papu.sahoo@gmail.com** with subject line `[SECURITY] ghost-pii-pydantic`.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The version(s) affected

**Response SLA:** We aim to acknowledge reports within 48 hours and issue a patch within 7 days for confirmed vulnerabilities.

## Scope

Issues in scope include (but are not limited to):
- Bypass of PII redaction in logging or print contexts
- Tainted-memory propagation failures that allow PII to escape
- Strict-mode bypasses
- Dependency vulnerabilities with a direct exploit path

Out of scope: general Python security issues unrelated to PII redaction behaviour.
