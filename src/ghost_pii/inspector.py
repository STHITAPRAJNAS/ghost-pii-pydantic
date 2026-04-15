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

import sys
import types
from typing import Optional

# Default set of modules considered unsafe for PII rendering.
# When GhostPII detects any of these in the call stack it redacts.
DEFAULT_UNSAFE_MODULES = {
    # stdlib logging
    "logging",
    # stdlib display / tracing
    "sys",
    "traceback",
    "builtins",  # print()
    "pprint",
    "inspect",
    # popular structured-logging libraries
    "structlog",
    "loguru",
    # rich console / pretty-printing
    "rich",
    # test runners (prevent PII leaking into test output)
    "pytest",
    "_pytest",
}


def is_unsafe_caller() -> bool:
    """
    Walks the current call stack to determine whether the caller is an unsafe
    context (logger, print, traceback, etc.).

    Uses fast-fail logic — stops as soon as an unsafe module is found or the
    depth limit is reached, keeping overhead low for safe callers.
    """
    try:
        frame = sys._getframe(2)
    except ValueError:
        return False

    depth = 0
    max_depth = 12

    current_frame: Optional[types.FrameType] = frame
    while current_frame and depth < max_depth:
        module_name = current_frame.f_globals.get("__name__", "")
        if module_name:
            base_module = module_name.split(".")[0]
            if base_module in inspector.unsafe_modules:
                return True
            if module_name in ("__main__", "builtins"):
                return True

        current_frame = current_frame.f_back
        depth += 1

    return False


class Inspector:
    def __init__(self) -> None:
        self.unsafe_modules = DEFAULT_UNSAFE_MODULES.copy()

    def add_unsafe_module(self, name: str) -> None:
        """
        Register an additional module as unsafe so GhostPII redacts when
        it appears in the call stack.

        Use this to cover custom loggers, observability SDKs, or any other
        module that should never see plaintext PII::

            from ghost_pii import add_unsafe_module
            add_unsafe_module("opentelemetry")
            add_unsafe_module("datadog")
        """
        self.unsafe_modules.add(name)

    def remove_unsafe_module(self, name: str) -> None:
        """Remove a module from the unsafe set."""
        self.unsafe_modules.discard(name)


inspector = Inspector()


def add_unsafe_module(name: str) -> None:
    """Module-level convenience wrapper for ``inspector.add_unsafe_module``."""
    inspector.add_unsafe_module(name)


def remove_unsafe_module(name: str) -> None:
    """Module-level convenience wrapper for ``inspector.remove_unsafe_module``."""
    inspector.remove_unsafe_module(name)
