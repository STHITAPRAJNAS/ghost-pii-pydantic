# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-04-15

### New Features
- **Partial masking** — `masked_pii()` helper with `MaskStrategy.EMAIL`, `LAST4`, `PHONE`, `SSN` strategies.
- **Audit hook** — `unmask_pii(on_access=callable)` parameter for compliance logging.
- **pytest plugin** — built-in `ghost_pii_strict` fixture and `--ghost-pii-strict` CLI flag (auto-registered via `pytest11` entry point).
- **Extensible unsafe modules** — `add_unsafe_module()` and `remove_unsafe_module()` exported at package level.
- **structlog / loguru** — added to default unsafe module set.

### Bug Fixes
- **asyncio safety** — replaced `threading.local` with `contextvars.ContextVar`; `unmask_pii()` is now isolated per thread *and* per asyncio task.
- **`__hash__` correctness** — `GhostString.__hash__` now hashes on `_secret_value` (consistent with `__eq__`); previously all instances hashed identically, breaking dict/set usage.
- **Taint propagation** — concatenation results now correctly inherit the left operand's `MaskStrategy`.

## [0.1.3] - 2026-04-15
- SEO: improved PyPI description, added keywords for GDPR/HIPAA/privacy/logging discoverability.
- docs: expanded README with async usage example, competitor comparison table (vs presidio, scrubadub), and clearer intro.
- added SECURITY.md with private vulnerability disclosure process.

## [0.1.2] - 2026-04-11
- Official release to PyPI as ghost-pii-pydantic.

## [0.1.1] - 2026-04-11
- Project renamed to ghost-pii-pydantic for PyPI compatibility.

## [0.1.0] - 2026-04-11
- Initial release of GhostPII.
- Enterprise-grade PII redaction with stack inspection.
- Pydantic v2 integration via Annotated types.
- Dual-mode security (Auto-Magical and Strict).
- Tainted memory support for string operations.
