import asyncio
import logging
import threading
import pytest
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, ValidationError

from ghost_pii import (
    GhostString,
    MaskStrategy,
    PII,
    masked_pii,
    set_strict_mode,
    unmask_pii,
    wrap_pii,
    add_unsafe_module,
    remove_unsafe_module,
)

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Address(BaseModel):
    street: PII[str]
    city: str
    zip_code: PII[str]


class UserProfile(BaseModel):
    id: int
    username: str
    full_name: PII[str]
    email: PII[EmailStr]
    backup_emails: List[PII[EmailStr]] = Field(default_factory=list)
    address: Optional[Address] = None
    secret_note: PII[str] = wrap_pii("initial secret")


class UserWithMasking(BaseModel):
    email: masked_pii(EmailStr, MaskStrategy.EMAIL)
    ssn: masked_pii(str, MaskStrategy.SSN)
    card: masked_pii(str, MaskStrategy.LAST4)
    phone: masked_pii(str, MaskStrategy.PHONE)


# ---------------------------------------------------------------------------
# Basic redaction
# ---------------------------------------------------------------------------

def test_pydantic_validation_and_redaction():
    user = UserProfile(
        id=1,
        username="jdoe",
        full_name="John Doe",
        email="john@example.com",
        backup_emails=["work@example.com", "personal@example.com"],
        address=Address(street="123 Ghost St", city="London", zip_code="W1 1AA"),
        secret_note="Top secret",
    )
    assert str(user.full_name) == "[REDACTED]"
    assert str(user.email) == "[REDACTED]"
    assert str(user.address.street) == "[REDACTED]"
    assert str(user.backup_emails[0]) == "[REDACTED]"
    assert user.username == "jdoe"
    assert user.address.city == "London"


def test_unmask_pii_complex():
    user = UserProfile(
        id=1,
        username="jdoe",
        full_name="John Doe",
        email="john@example.com",
        backup_emails=["work@example.com"],
        address=Address(street="123 Ghost St", city="London", zip_code="W1 1AA"),
    )
    with unmask_pii():
        assert str(user.full_name) == "John Doe"
        assert str(user.email) == "john@example.com"
        assert str(user.backup_emails[0]) == "work@example.com"
        assert str(user.address.street) == "123 Ghost St"

    assert str(user.full_name) == "[REDACTED]"


def test_json_serialization_redacts():
    user = UserProfile(id=1, username="jdoe", full_name="John Doe", email="john@example.com")
    json_data = user.model_dump_json()
    assert "John Doe" not in json_data
    assert "[REDACTED]" in json_data


def test_validation_errors_still_raised():
    with pytest.raises(ValidationError):
        UserProfile(id=1, username="jdoe", full_name="John Doe", email="not-an-email")


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------

def test_strict_mode_isolation():
    pii = wrap_pii("secret")
    set_strict_mode(True)
    try:
        assert str(pii) == "[REDACTED]"
        with unmask_pii():
            assert str(pii) == "secret"
        assert str(pii) == "[REDACTED]"
    finally:
        set_strict_mode(False)


# ---------------------------------------------------------------------------
# Tainted concatenation
# ---------------------------------------------------------------------------

def test_tainted_concatenation():
    first = wrap_pii("John")
    full = first + " Doe"
    assert isinstance(full, GhostString)
    assert str(full) == "[REDACTED]"

    labeled = "User: " + first
    assert isinstance(labeled, GhostString)
    assert str(labeled) == "[REDACTED]"

    with unmask_pii():
        assert str(full) == "John Doe"
        assert str(labeled) == "User: John"


def test_taint_preserves_mask_strategy():
    """Concatenation result should inherit the left operand's mask strategy."""
    email_ghost = GhostString("john@example.com", MaskStrategy.EMAIL)
    combined = email_ghost + " (primary)"
    assert combined._mask_strategy == MaskStrategy.EMAIL
    assert combined._secret_value == "john@example.com (primary)"


# ---------------------------------------------------------------------------
# Hash correctness (bug fix)
# ---------------------------------------------------------------------------

def test_hash_consistency_with_eq():
    p1 = wrap_pii("secret")
    p2 = wrap_pii("secret")
    p3 = wrap_pii("other")

    assert p1 == p2
    assert hash(p1) == hash(p2)
    assert p1 != p3
    assert hash(p1) != hash(p3)


def test_ghost_strings_usable_as_dict_keys():
    d = {wrap_pii("key1"): "value1", wrap_pii("key2"): "value2"}
    assert d[wrap_pii("key1")] == "value1"
    assert d[wrap_pii("key2")] == "value2"


def test_ghost_strings_usable_in_sets():
    s = {wrap_pii("a"), wrap_pii("a"), wrap_pii("b")}
    assert len(s) == 2


# ---------------------------------------------------------------------------
# Equality
# ---------------------------------------------------------------------------

def test_equality_logic():
    p1 = wrap_pii("secret")
    p2 = wrap_pii("secret")
    p3 = wrap_pii("other")
    assert p1 == p2
    assert p1 == "secret"
    assert p1 != p3
    assert p1 != "other"


# ---------------------------------------------------------------------------
# reveal()
# ---------------------------------------------------------------------------

def test_reveal_method():
    pii = wrap_pii("sensitive")
    assert pii.reveal() == "sensitive"

    set_strict_mode(True)
    try:
        assert pii.reveal() == "sensitive"
    finally:
        set_strict_mode(False)


# ---------------------------------------------------------------------------
# Partial masking
# ---------------------------------------------------------------------------

class TestEmailMasking:
    def test_email_strategy_in_unsafe_context(self):
        user = UserWithMasking(
            email="john@example.com",
            ssn="123-45-6789",
            card="4111111111111111",
            phone="+447911123456",
        )
        assert str(user.email) == "jo***@ex***.com"

    def test_email_reveals_fully_in_unmask(self):
        user = UserWithMasking(
            email="john@example.com",
            ssn="123-45-6789",
            card="4111111111111111",
            phone="+447911123456",
        )
        with unmask_pii():
            assert str(user.email) == "john@example.com"


class TestSSNMasking:
    def test_ssn_strategy(self):
        g = GhostString("123456789", MaskStrategy.SSN)
        assert str(g) == "***-**-6789"

    def test_ssn_formatted_input(self):
        g = GhostString("123-45-6789", MaskStrategy.SSN)
        assert str(g) == "***-**-6789"

    def test_ssn_invalid_length_falls_back_to_redacted(self):
        g = GhostString("1234", MaskStrategy.SSN)
        assert str(g) == "[REDACTED]"


class TestLast4Masking:
    def test_last4_strategy(self):
        g = GhostString("4111111111111111", MaskStrategy.LAST4)
        assert str(g) == "************1111"

    def test_last4_too_short_falls_back(self):
        g = GhostString("123", MaskStrategy.LAST4)
        assert str(g) == "[REDACTED]"


class TestPhoneMasking:
    def test_phone_with_country_code(self):
        g = GhostString("+447911123456", MaskStrategy.PHONE)
        assert str(g) == "+44*********456"

    def test_phone_too_short_falls_back(self):
        g = GhostString("123", MaskStrategy.PHONE)
        assert str(g) == "[REDACTED]"


# ---------------------------------------------------------------------------
# asyncio safety (ContextVar)
# ---------------------------------------------------------------------------

def test_asyncio_unmask_does_not_leak_across_tasks():
    """
    unmask_pii() in one asyncio task must not affect a concurrent task.
    With threading.local this test would race; with ContextVar it is safe.
    """
    pii = wrap_pii("secret")
    results: dict = {}

    async def leaky_task():
        with unmask_pii():
            await asyncio.sleep(0)  # yield — lets the other task run
            results["leaky"] = str(pii)

    async def clean_task():
        await asyncio.sleep(0)  # run after leaky_task enters unmask_pii
        results["clean"] = str(pii)

    async def main():
        await asyncio.gather(leaky_task(), clean_task())

    asyncio.run(main())

    assert results["leaky"] == "secret"
    assert results["clean"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_thread_safety_unmask_isolation():
    from tests.logic_utils import process_pii

    pii = wrap_pii("global_secret")
    results: dict = {}

    def thread_task(name, should_unmask):
        if should_unmask:
            with unmask_pii():
                results[name] = process_pii(pii)
        else:
            results[name] = process_pii(pii)

    t1 = threading.Thread(target=thread_task, args=("T1_unmasked", True))
    t2 = threading.Thread(target=thread_task, args=("T2_masked", False))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert results["T1_unmasked"] == "global_secret"
    # T2 runs outside unmask_pii; process_pii lives outside unsafe modules
    assert results["T2_masked"] == "global_secret"


# ---------------------------------------------------------------------------
# Audit hook on unmask_pii
# ---------------------------------------------------------------------------

def test_audit_hook_called_on_entry():
    audit_log = []
    pii = wrap_pii("sensitive")

    with unmask_pii(on_access=lambda: audit_log.append("accessed")):
        _ = pii.reveal()

    assert audit_log == ["accessed"]


def test_audit_hook_not_called_without_argument():
    pii = wrap_pii("sensitive")
    with unmask_pii():
        _ = pii.reveal()


def test_audit_hook_called_even_on_exception():
    audit_log = []

    with pytest.raises(RuntimeError):
        with unmask_pii(on_access=lambda: audit_log.append("accessed")):
            raise RuntimeError("boom")

    assert audit_log == ["accessed"]


# ---------------------------------------------------------------------------
# add_unsafe_module / remove_unsafe_module
# ---------------------------------------------------------------------------

def test_add_and_remove_unsafe_module():
    from ghost_pii.inspector import inspector

    add_unsafe_module("mycompany_logger")
    assert "mycompany_logger" in inspector.unsafe_modules

    remove_unsafe_module("mycompany_logger")
    assert "mycompany_logger" not in inspector.unsafe_modules


# ---------------------------------------------------------------------------
# pytest plugin fixture
# ---------------------------------------------------------------------------

def test_ghost_pii_strict_fixture(ghost_pii_strict):
    pii = wrap_pii("fixture_secret")
    assert str(pii) == "[REDACTED]"
    with unmask_pii():
        assert str(pii) == "fixture_secret"
