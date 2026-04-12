from typing import Any
from .context import get_state
from .inspector import is_unsafe_caller

REDACTED_VALUE = "[REDACTED]"


class GhostString(str):
    """
    A smart string proxy that redacts its value when accessed by unsafe contexts
    (logging, printing, etc.) but remains plaintext for business logic.
    """

    _secret_value: str

    def __new__(cls, value: str):
        # We don't store the value in the base 'str' to prevent leakage.
        # Instead, we store it in a private attribute.
        instance = super().__new__(cls, REDACTED_VALUE)
        instance._secret_value = str(value)
        return instance

    def _should_redact(self) -> bool:
        state = get_state()

        # 1. Manual Override (with unmask_pii())
        if state.unmasked:
            return False

        # 2. Strict Mode (ALWAYS redacted unless unmasked)
        if state.strict_mode:
            return True

        # 3. Auto Mode (Stack Inspection)
        # We only inspect the stack if we're not in strict mode
        return is_unsafe_caller()

    def __str__(self) -> str:
        if self._should_redact():
            return REDACTED_VALUE
        return self._secret_value

    def __repr__(self) -> str:
        if self._should_redact():
            return f"GhostString({REDACTED_VALUE!r})"
        return f"GhostString({self._secret_value!r})"

    def __add__(self, other: Any) -> "GhostString":
        # Concatenation results in a new tainted GhostString
        other_val = str(other)
        if isinstance(other, GhostString):
            # If both are GhostStrings, we only reveal if allowed
            if self._should_redact() or other._should_redact():
                # We can't easily concatenate without revealing,
                # so we create a new one from the raw values.
                return GhostString(self._secret_value + other._secret_value)

        return GhostString(self._secret_value + other_val)

    def __radd__(self, other: Any) -> "GhostString":
        return GhostString(str(other) + self._secret_value)

    # To ensure it acts like a normal string for most operations
    def __len__(self) -> int:
        return len(self._secret_value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GhostString):
            return self._secret_value == other._secret_value
        return self._secret_value == str(other)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def reveal(self) -> str:
        """
        Explicitly reveal the plaintext value. Use with caution.
        """
        return self._secret_value
