from typing import Annotated, Any, TypeVar

from pydantic import AfterValidator, PlainSerializer

from .core import GhostString, MaskStrategy

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Serializer (shared)
# ---------------------------------------------------------------------------

def _serialize_pii(v: GhostString) -> str:
    """Pydantic serializer: follows the same redaction rules as __str__."""
    return str(v)


# ---------------------------------------------------------------------------
# PII — full redaction (default)
# ---------------------------------------------------------------------------

PII = Annotated[
    T,
    AfterValidator(lambda v: v if isinstance(v, GhostString) else GhostString(str(v))),
    PlainSerializer(_serialize_pii, when_used="always"),
]
"""
Full-redaction PII type for Pydantic v2 ``Annotated`` fields.

In unsafe contexts (logging, print, tracebacks) the value is replaced with
``[REDACTED]``. In business logic and database operations the real value is
preserved::

    class User(BaseModel):
        name: PII[str]
        email: PII[EmailStr]
"""


# ---------------------------------------------------------------------------
# masked_pii — partial masking
# ---------------------------------------------------------------------------

def masked_pii(inner_type: Any, strategy: MaskStrategy = MaskStrategy.EMAIL) -> Any:
    """
    Create a Pydantic ``Annotated`` PII type with partial masking.

    Unlike :data:`PII` (which shows ``[REDACTED]``), ``masked_pii`` reveals a
    sanitised representation that is still identifiable but not exploitable::

        class User(BaseModel):
            email: masked_pii(EmailStr, MaskStrategy.EMAIL)   # jo***@ex***.com
            ssn:   masked_pii(str,      MaskStrategy.SSN)     # ***-**-6789
            card:  masked_pii(str,      MaskStrategy.LAST4)   # ****1234
            phone: masked_pii(str,      MaskStrategy.PHONE)   # +44*****456

    Args:
        inner_type: The underlying Pydantic-compatible type (e.g. ``str``,
                    ``EmailStr``).  Pydantic validates this type first, then
                    wraps the result in a :class:`~ghost_pii.GhostString`.
        strategy:   A :class:`~ghost_pii.MaskStrategy` value that controls how
                    the field is displayed in unsafe contexts.
    """
    def _validate(v: Any) -> GhostString:
        if isinstance(v, GhostString):
            return v
        return GhostString(str(v), mask_strategy=strategy)

    return Annotated[
        inner_type,
        AfterValidator(_validate),
        PlainSerializer(_serialize_pii, when_used="always"),
    ]


# ---------------------------------------------------------------------------
# wrap_pii helper
# ---------------------------------------------------------------------------

def wrap_pii(v: T, strategy: MaskStrategy = MaskStrategy.FULL) -> T:
    """Manually wrap a value in a :class:`~ghost_pii.GhostString`."""
    return GhostString(str(v), mask_strategy=strategy)  # type: ignore[return-value]
