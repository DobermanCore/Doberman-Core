"""Local dashboard (preview) - a localhost-only control surface for Doberman.

D1 (this slice) is the serving skeleton: an app factory, bearer-token auth,
and a single inline HTML shell. Later slices add the live decision feed
(SSE), summary stats, and approve/deny actions.

Only ever imported lazily, from the ``doberman dash`` CLI command - never at
module scope elsewhere - so ``import doberman`` and the rest of the CLI keep
working with the optional ``dash`` extra (``starlette``, ``uvicorn``) not
installed.
"""

from doberman.dash.app import create_app

__all__ = ["create_app"]
