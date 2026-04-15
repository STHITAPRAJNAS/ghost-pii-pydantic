# GhostPII 👻

**Automatic PII redaction for Pydantic v2 — zero-config, GDPR/HIPAA-friendly.**

[![PyPI version](https://img.shields.io/pypi/v/ghost-pii-pydantic.svg)](https://pypi.org/project/ghost-pii-pydantic/)
[![Python](https://img.shields.io/pypi/pyversions/ghost-pii-pydantic.svg)](https://pypi.org/project/ghost-pii-pydantic/)
[![CI](https://github.com/STHITAPRAJNAS/ghost-pii-pydantic/actions/workflows/ci.yml/badge.svg)](https://github.com/STHITAPRAJNAS/ghost-pii-pydantic/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Typed](https://img.shields.io/badge/typing-py.typed-informational)](src/ghost_pii/py.typed)

> **Note:** This project is published on PyPI as [`ghost-pii-pydantic`](https://pypi.org/project/ghost-pii-pydantic/).

GhostPII solves the **"Logged Secret"** problem: sensitive fields (emails, SSNs, credit card numbers, API keys) leaking into logs and tracebacks. It provides a smart string proxy that automatically redacts itself in unsafe contexts (`logging`, `print`, tracebacks) while remaining fully functional for business logic, databases, and APIs.

- Drop-in Pydantic v2 `Annotated` type — no middleware, no post-processing
- Tainted memory propagation — concatenated strings stay redacted
- Strict mode for FinTech / HealthTech / high-compliance environments
- Works with sync and async Python services


## Features

| Feature | Description |
|---------|-------------|
| **Auto-Magical Redaction** | Automatically detects `print()`, `logging`, `structlog`, `loguru`, and more. |
| **Partial Masking** | Show `jo***@ex***.com` instead of `[REDACTED]` — ideal for UIs and audit logs. |
| **Pydantic Native** | First-class support for Pydantic v2 `Annotated` types. |
| **Strict Mode** | Opt-in for 100% redaction everywhere unless explicitly unmasked. |
| **Tainted Memory** | Operations on PII (like concatenation) stay PII. No accidental leaks. |
| **Context Aware** | `unmask_pii()` context manager with optional audit callback. |
| **asyncio Safe** | Uses `contextvars.ContextVar` — isolated per thread and per async task. |
| **pytest Plugin** | Built-in `ghost_pii_strict` fixture and `--ghost-pii-strict` CLI flag. |
| **Extensible** | Register custom unsafe modules (OpenTelemetry, Datadog, etc.) at runtime. |

## Installation

```bash
pip install ghost-pii-pydantic
```

## Quick Start

```python
from pydantic import BaseModel, EmailStr
from ghost_pii import PII, unmask_pii

class User(BaseModel):
    name: PII[str]
    email: PII[EmailStr] # Validates as email (via Pydantic), redacts in logs

user = User(name="John Doe", email="john@example.com")

# 1. Safe by Default: Redacts in logs/prints
print(user)
# Output: name=GhostString('[REDACTED]') email=GhostString('[REDACTED]')

# 2. Functional: Works in business logic/DBs
# (String conversion or attribute access in non-unsafe contexts reveals the real string)
db.execute("INSERT INTO users VALUES (?)", [user.email])
# Successfully inserts "john@example.com"
```
# 3. Explicit: Use context manager for sensitive tasks
with unmask_pii():
    print(user) 
    # Output: name=GhostString('John Doe') email=GhostString('john@example.com')
```

## Advanced Scenarios

### Nested Models and Collections
GhostPII seamlessly handles nested Pydantic models and lists of PII.

```python
from typing import List
from ghost_pii import PII

class Address(BaseModel):
    street: PII[str]
    city: str

class Organization(BaseModel):
    name: str
    admin_emails: List[PII[EmailStr]]
    headquarters: Address

org = Organization(
    name="Acme Corp",
    admin_emails=["admin@acme.com", "sec@acme.com"],
    headquarters=Address(street="123 Secret Lane", city="New York")
)

print(org.model_dump())
# Output: {
#   'name': 'Acme Corp', 
#   'admin_emails': ['[REDACTED]', '[REDACTED]'], 
#   'headquarters': {'street': '[REDACTED]', 'city': 'New York'}
# }
```

### Tainted Memory (Concatenation)
PII "infects" any string it touches. If you combine a PII field with a normal string, the result is a new `GhostString` that is also redacted by default.

```python
labeled_name = "User: " + user.name
print(labeled_name) # Output: [REDACTED]

with unmask_pii():
    print(labeled_name) # Output: User: John Doe
```

## Partial Masking

Use `masked_pii()` when you need identifiable-but-safe values — customer service UIs, audit logs, support dashboards.

Supported strategies in `MaskStrategy`:
- `FULL`: Always shows `[REDACTED]`. (Default)
- `EMAIL`: Partially masks local-part and domain, e.g. `jo***@ex***.com`.
- `LAST4`: Keeps the last four digits, e.g. `****6789`.
- `PHONE`: Keeps country prefix and last three digits, e.g. `+44*****456`.
- `SSN`: Shows only the last four digits in SSN format, e.g. `***-**-6789`.

```python
from ghost_pii import masked_pii, MaskStrategy

class User(BaseModel):
    email: masked_pii(EmailStr, MaskStrategy.EMAIL)   # jo***@ex***.com
    ssn:   masked_pii(str,      MaskStrategy.SSN)     # ***-**-6789
    card:  masked_pii(str,      MaskStrategy.LAST4)   # ****1111
    phone: masked_pii(str,      MaskStrategy.PHONE)   # +44*****456

user = User(email="john@example.com", ssn="123-45-6789",
            card="4111111111111111", phone="+447911123456")

print(user.email)  # jo***@ex***.com
print(user.ssn)    # ***-**-6789

with unmask_pii():
    print(user.email)  # john@example.com
```

## Audit Hook

Pass `on_access` to `unmask_pii()` to emit a compliance trail whenever PII is deliberately exposed — required for SOC2 / GDPR audit logs.

```python
import logging
from ghost_pii import unmask_pii

audit = logging.getLogger("audit")

# The callback is triggered exactly once when entering the context manager
with unmask_pii(on_access=lambda: audit.info("PII accessed by service X")):
    send_email(to=str(user.email))
```

## Extending Unsafe Modules

GhostPII covers `logging`, `structlog`, `loguru`, `rich`, `print`, and test runners out of the box. Add your own:

```python
from ghost_pii import add_unsafe_module

add_unsafe_module("opentelemetry")
add_unsafe_module("datadog")
```

## Async Support

GhostPII works transparently in async services. The `unmask_pii()` context manager is sync-safe and can be used inside `async` functions:

```python
import asyncio
from ghost_pii import PII, unmask_pii

class UserEvent(BaseModel):
    user_id: str
    email: PII[str]

async def send_confirmation(event: UserEvent):
    # Logging is safe — email is auto-redacted
    logger.info("Sending confirmation to %s", event.email)

    with unmask_pii():
        await smtp_client.send(to=str(event.email), subject="Confirm your account")
```

## Enterprise Strategy

GhostPII is designed to adapt to different compliance levels:

| Mode | Recommended For | Mechanism |
|------|-----------------|-----------|
| **Auto-Magical** | General microservices, high developer velocity. | Uses stack inspection to detect `logging`, `print`, etc. |
| **Strict Mode** | FinTech, HealthTech, High-Compliance environments. | Redacts **everywhere**. Requires explicit `unmask_pii()` to access data. |

### Enabling Strict Mode
```python
from ghost_pii import set_strict_mode

set_strict_mode(True) # Best practice for production PII handling
```

## pytest Plugin

GhostPII ships a built-in pytest plugin (auto-registered via `pytest11` entry point).

**Per-test strict mode:**
```python
def test_no_pii_in_logs(ghost_pii_strict):
    user = User(name="John Doe", email="john@example.com")
    assert str(user.email) == "[REDACTED]"   # strict: always redacted
    with unmask_pii():
        assert str(user.email) == "john@example.com"
```

**Session-wide (CI enforcement):**
```bash
pytest --ghost-pii-strict
```

**Disable the plugin:**
```bash
pytest -p no:ghost-pii
```

## Why GhostPII vs Alternatives

| | GhostPII | [presidio](https://github.com/microsoft/presidio) | [scrubadub](https://github.com/LeapBeyond/scrubadub) | Manual field redaction |
|---|---|---|---|---|
| **Integration model** | Pydantic `Annotated` type | NLP pipeline / scrubber | String scrubber | Ad-hoc |
| **Auto-redacts in logs** | Yes — zero config | No | No | No |
| **Preserves value for DB/API** | Yes | No (destructive) | No (destructive) | Depends |
| **Tainted memory propagation** | Yes | No | No | No |
| **Strict / audit mode** | Yes | No | No | Manual |
| **Setup overhead** | `pip install` + type annotation | NER models, language packs | Pattern config | High |
| **Best for** | Pydantic services, FastAPI, microservices | Bulk text anonymisation | Legacy string scrubbing | Simple one-off cases |

**TL;DR:** presidio and scrubadub are great for scrubbing free-text blobs. GhostPII is purpose-built for Pydantic models where you need the real value to flow through your app but never appear in logs.

## Contributing

We follow strict engineering standards. Please ensure you run linters and tests before submitting PRs.

```bash
pip install -e ".[dev]"
pytest                        # run test suite
ruff check src/ghost_pii      # lint
mypy src/ghost_pii            # type-check
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Sthitaprajna Sahoo and contributors.
