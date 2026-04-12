import threading
from contextlib import contextmanager
from typing import Generator


class GhostState:
    def __init__(self) -> None:
        self.strict_mode = False
        self.unmasked = False


_local = threading.local()


def get_state() -> GhostState:
    if not hasattr(_local, "state"):
        _local.state = GhostState()
    return _local.state


def set_strict_mode(enabled: bool = True) -> None:
    """
    In Strict Mode, PII is ALWAYS redacted unless wrapped in unmask_pii().
    No stack inspection is performed.
    """
    get_state().strict_mode = enabled


@contextmanager
def unmask_pii() -> Generator[None, None, None]:
    """
    Temporarily allows PII to be revealed in the current thread.
    """
    state = get_state()
    old_unmasked = state.unmasked
    state.unmasked = True
    try:
        yield
    finally:
        state.unmasked = old_unmasked
