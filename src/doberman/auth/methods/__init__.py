"""Built-in :class:`~doberman.auth.approval.ApprovalMethod` backends.

:func:`builtin_methods` is the built-in half of the registry
(:func:`doberman.engine.registry.discover_approval_methods` also loads any
``doberman.approval_methods`` entry-point plugins). Adding a backend here — or as
a plugin — makes it selectable once the user enables it by name
(:mod:`doberman.auth.approval_config`).
"""

from __future__ import annotations

from doberman.auth.approval import ApprovalMethod
from doberman.auth.methods.windows_hello import WindowsHelloMethod


def builtin_methods() -> list[ApprovalMethod]:
    """The approval methods that ship in core. Order is not preference (the user's
    enabled list sets preference); it's just the catalogue of what exists."""
    return [WindowsHelloMethod()]
