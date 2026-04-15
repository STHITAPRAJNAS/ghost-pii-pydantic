"""
GhostPII pytest plugin.

Registered automatically via the ``pytest11`` entry point when
``ghost-pii-pydantic`` is installed.  Provides:

* ``ghost_pii_strict`` fixture — enables strict mode for one test.
* ``--ghost-pii-strict`` CLI flag — enables strict mode for the entire session.

Usage
-----
Per-test::

    def test_no_pii_leaks(ghost_pii_strict):
        user = User(email="john@example.com")
        assert str(user.email) == "[REDACTED]"   # strict: always redacted

Session-wide (e.g. in CI)::

    pytest --ghost-pii-strict

To disable the plugin entirely::

    pytest -p no:ghost-pii
"""

from __future__ import annotations

import pytest

from ghost_pii.context import get_state, set_strict_mode


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--ghost-pii-strict",
        action="store_true",
        default=False,
        help="Enable GhostPII strict mode for the entire test session.",
    )


def pytest_configure(config: pytest.Config) -> None:
    if config.getoption("--ghost-pii-strict", default=False):
        set_strict_mode(True)


@pytest.fixture
def ghost_pii_strict():
    """
    Enable GhostPII strict mode for the duration of a single test.

    Strict mode redacts PII everywhere — no stack inspection, no exceptions —
    until ``unmask_pii()`` is used explicitly.  Restores the previous mode
    after the test regardless of pass/fail.
    """
    previous = get_state().strict_mode
    set_strict_mode(True)
    yield
    set_strict_mode(previous)
