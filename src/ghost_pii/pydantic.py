from typing import Annotated, Any, TypeVar
from pydantic import AfterValidator, PlainSerializer
from .core import GhostString

T = TypeVar("T")


def validate_pii(v: Any, info: Any) -> Any:
    """
    Validation hook for Pydantic. It first validates the value against
     the target type (T), then wraps the result in a GhostString.
    """
    if isinstance(v, GhostString):
        return v
    return GhostString(str(v))


def serialize_pii(v: GhostString) -> str:
    """
    Serializer for Pydantic. By default, it follows the redaction rules.
    """
    return str(v)


# Improved PII Annotated type.
# It uses AfterValidator so that the inner type (e.g., EmailStr)
# is validated BEFORE we wrap it in a GhostString.
PII = Annotated[
    T,
    AfterValidator(lambda v: GhostString(str(v))),
    PlainSerializer(serialize_pii, when_used="always"),
]


def wrap_pii(v: T) -> T:
    """Helper to manually wrap a value in a GhostString."""
    return GhostString(str(v))  # type: ignore
