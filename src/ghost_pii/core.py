from enum import Enum
from typing import Any

from .context import get_state
from .inspector import is_unsafe_caller

REDACTED_VALUE = "[REDACTED]"


class MaskStrategy(str, Enum):
    """
    Controls how PII is displayed in unsafe contexts (logging, print, tracebacks).

    - FULL:  Always shows ``[REDACTED]``. Default behaviour.
    - EMAIL: Partially masks local-part and domain, e.g. ``jo***@ex***.com``.
    - LAST4: Keeps the last four digits, e.g. ``****1234``.
    - PHONE: Keeps country prefix and last three digits, e.g. ``+44*****456``.
    - SSN:   Shows only the last four digits in SSN format, e.g. ``***-**-6789``.
    """

    FULL = "full"
    EMAIL = "email"
    LAST4 = "last4"
    PHONE = "phone"
    SSN = "ssn"


# ---------------------------------------------------------------------------
# Masking helpers
# ---------------------------------------------------------------------------

def _mask_email(value: str) -> str:
    if "@" not in value:
        return REDACTED_VALUE
    local, _, domain = value.partition("@")

    def _partial(s: str, keep: int = 2) -> str:
        return s[:keep] + "***" if len(s) > keep else "***"

    domain_name, _, tld = domain.rpartition(".")
    masked_domain = (_partial(domain_name) + "." + tld) if domain_name else _partial(domain)
    return f"{_partial(local)}@{masked_domain}"


def _mask_last4(value: str) -> str:
    digits = "".join(c for c in value if c.isdigit())
    if len(digits) < 4:
        return REDACTED_VALUE
    return "*" * (len(digits) - 4) + digits[-4:]


def _mask_phone(value: str) -> str:
    digits = "".join(c for c in value if c.isdigit())
    if len(digits) < 6:
        return REDACTED_VALUE
    prefix = value[:3] if value.startswith("+") else ""
    return prefix + "*" * (len(digits) - 3) + digits[-3:]


def _mask_ssn(value: str) -> str:
    digits = "".join(c for c in value if c.isdigit())
    if len(digits) != 9:
        return REDACTED_VALUE
    return f"***-**-{digits[-4:]}"


# ---------------------------------------------------------------------------
# GhostString
# ---------------------------------------------------------------------------

class GhostString(str):
    """
    A smart string proxy that redacts (or partially masks) its value when
    accessed by unsafe contexts (logging, printing, tracebacks) but remains
    fully functional for business logic, databases, and APIs.
    """

    _secret_value: str
    _mask_strategy: MaskStrategy

    def __new__(
        cls,
        value: str,
        mask_strategy: MaskStrategy = MaskStrategy.FULL,
    ) -> "GhostString":
        # The base str value is always the redacted sentinel to prevent
        # accidental leakage through str internals.
        instance = super().__new__(cls, REDACTED_VALUE)
        instance._secret_value = str(value)
        instance._mask_strategy = mask_strategy
        return instance

    # ------------------------------------------------------------------
    # Redaction logic
    # ------------------------------------------------------------------

    def _should_redact(self) -> bool:
        state = get_state()
        if state.unmasked:
            return False
        if state.strict_mode:
            return True
        return is_unsafe_caller()

    def _display_value(self) -> str:
        """Value shown in unsafe contexts, respecting the mask strategy."""
        strategy = self._mask_strategy
        if strategy == MaskStrategy.EMAIL:
            return _mask_email(self._secret_value)
        if strategy == MaskStrategy.LAST4:
            return _mask_last4(self._secret_value)
        if strategy == MaskStrategy.PHONE:
            return _mask_phone(self._secret_value)
        if strategy == MaskStrategy.SSN:
            return _mask_ssn(self._secret_value)
        return REDACTED_VALUE  # MaskStrategy.FULL

    # ------------------------------------------------------------------
    # str protocol
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        if self._should_redact():
            return self._display_value()
        return self._secret_value

    def __repr__(self) -> str:
        if self._should_redact():
            return f"GhostString({self._display_value()!r})"
        return f"GhostString({self._secret_value!r})"

    def __add__(self, other: Any) -> "GhostString":
        # Taint propagation: result inherits this string's mask strategy.
        other_val = other._secret_value if isinstance(other, GhostString) else str(other)
        return GhostString(self._secret_value + other_val, self._mask_strategy)

    def __radd__(self, other: Any) -> "GhostString":
        return GhostString(str(other) + self._secret_value, self._mask_strategy)

    def __len__(self) -> int:
        return len(self._secret_value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GhostString):
            return self._secret_value == other._secret_value
        return self._secret_value == str(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        # Must be consistent with __eq__, which compares _secret_value.
        return hash(self._secret_value)

    # ------------------------------------------------------------------
    # Explicit escape hatch
    # ------------------------------------------------------------------

    def reveal(self) -> str:
        """Explicitly return the plaintext value. Use with caution."""
        return self._secret_value
