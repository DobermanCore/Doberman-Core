"""Doberman — adaptive authorization layer for coding agents (open core)."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: the version declared in pyproject.toml, read back
    # from the installed distribution metadata — so __version__ can never drift
    # from what pip/PyPI shipped (a hardcoded literal here silently lied at
    # 0.12.0 while the package was already 0.15.0).
    __version__ = version("doberman-core")
except PackageNotFoundError:  # running from a source tree with no install
    __version__ = "0.0.0+unknown"
