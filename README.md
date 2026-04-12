# GhostPII 👻 (ghost-pii-pydantic)

Enterprise-Grade PII Redaction for Python. Type-Safe, Invisible by Default.

[![PyPI version](https://img.shields.io/pypi/v/ghost-pii-pydantic.svg)](https://pypi.org/project/ghost-pii-pydantic/)
[![Python](https://img.shields.io/pypi/pyversions/ghost-pii-pydantic.svg)](https://pypi.org/project/ghost-pii-pydantic/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Typed](https://img.shields.io/badge/typing-py.typed-informational)](src/ghost_pii/py.typed)

GhostPII (published as `ghost-pii-pydantic`) solves the "Logged Secret" problem once and for all. It provides a smart string proxy that automatically redacts itself when accessed by unsafe contexts (logging, printing, tracebacks) but remains fully functional for your business logic, databases, and APIs.

## Features

| Feature | Description |
|---------|-------------|
| **Auto-Magical Redaction** | Automatically detects `print()` and `logging` calls to mask PII. |
| **Pydantic Native** | First-class support for Pydantic v2 `Annotated` types. |
| **Strict Mode** | Opt-in for 100% redaction everywhere unless explicitly unmasked. |
| **Tainted Memory** | Operations on PII (like concatenation) stay PII. No accidental leaks. |
| **Context Aware** | Use `unmask_pii()` context manager for explicit, safe data access. |
| **Zero-Performance-Cost** | Optimized stack inspection with fast-fail logic. |

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
    email: PII[EmailStr]

user = User(name="John Doe", email="john@example.com")

# 1. Safe by Default: Redacts in logs/prints
print(user)
# Output: name=GhostString('[REDACTED]') email=GhostString('[REDACTED]')

# 2. Functional: Works in business logic/DBs
# (Internal calls to user.email return the real string)
db.execute("INSERT INTO users VALUES (?)", [user.email])
# Successfully inserts "john@example.com"

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
