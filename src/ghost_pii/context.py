# Copyright 2026 Sthitaprajna Sahoo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from contextvars import ContextVar
from contextlib import contextmanager
from typing import Callable, Generator, Optional


class GhostState:
    def __init__(self, strict_mode: bool = False, unmasked: bool = False) -> None:
        self.strict_mode = strict_mode
        self.unmasked = unmasked


_state_var: ContextVar[GhostState] = ContextVar("ghost_pii_state")


def get_state() -> GhostState:
    try:
        return _state_var.get()
    except LookupError:
        state = GhostState()
        _state_var.set(state)
        return state


def set_strict_mode(enabled: bool = True) -> None:
    """
    In Strict Mode, PII is ALWAYS redacted unless wrapped in unmask_pii().
    No stack inspection is performed.

    Safe for both threading and asyncio — uses contextvars.ContextVar
    so each thread and each asyncio task has its own isolated state.
    """
    state = get_state()
    _state_var.set(GhostState(strict_mode=enabled, unmasked=state.unmasked))


@contextmanager
def unmask_pii(
    on_access: Optional[Callable[[], None]] = None,
) -> Generator[None, None, None]:
    """
    Temporarily allows PII to be revealed in the current context.

    Safe for both threading and asyncio — uses ContextVar.reset() to
    restore the previous state exactly on exit, even if exceptions occur.

    Args:
        on_access: Optional audit callback invoked when the context is entered.
                   Use this for compliance logging, e.g.:
                       with unmask_pii(on_access=lambda: audit.log("PII accessed")):
                           ...
    """
    state = get_state()
    token = _state_var.set(GhostState(strict_mode=state.strict_mode, unmasked=True))
    try:
        if on_access is not None:
            on_access()
        yield
    finally:
        _state_var.reset(token)
