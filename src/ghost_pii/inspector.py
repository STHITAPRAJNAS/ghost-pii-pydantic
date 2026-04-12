import sys
import types
from typing import Optional

# Default list of modules that are considered "unsafe" for PII rendering.
# When GhostPII detects these in the call stack, it redacts.
DEFAULT_UNSAFE_MODULES = {
    "logging",
    "sys",
    "rich",
    "traceback",
    "builtins",  # for print()
    "pprint",
    "inspect",
    "pytest",
    "_pytest",
}


def is_unsafe_caller() -> bool:
    """
    Analyzes the current call stack to determine if the requester is an
    unauthorized or unsafe context (like a logger or print statement).

    Performance: This function uses fast-fail logic. It only walks the stack
    if necessary and limits the depth of inspection.
    """
    # Start at the frame that called the __str__ or __repr__ (usually level 2 or 3)
    try:
        frame = sys._getframe(2)
    except ValueError:
        return False

    # Track depth to avoid performance degradation in deep stacks
    depth = 0
    max_depth = 12

    current_frame: Optional[types.FrameType] = frame
    while current_frame and depth < max_depth:
        module_name = current_frame.f_globals.get("__name__", "")
        if module_name:
            # Check for the base module name (e.g., 'logging' from 'logging.handlers')
            base_module = module_name.split(".")[0]
            if base_module in inspector.unsafe_modules:
                return True

            # Special case for standard print() and sys.stdout access
            if module_name == "__main__" or module_name == "builtins":
                # If we're inside a print call or sys access, we redact
                return True

        current_frame = current_frame.f_back
        depth += 1

    return False


class Inspector:
    def __init__(self) -> None:
        self.unsafe_modules = DEFAULT_UNSAFE_MODULES.copy()

    def add_unsafe_module(self, name: str) -> None:
        self.unsafe_modules.add(name)


inspector = Inspector()
