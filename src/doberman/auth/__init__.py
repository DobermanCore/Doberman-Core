"""Tiered authentication and role elevation (Feature 7).

Turns an ``AUTH`` verdict from the decision engine into a real, action-specific
challenge (soft confirm → local auth → 2FA → role elevation) and grants narrow,
temporary, single-use role elevations. The active auth backend is pluggable via
the :class:`~doberman.auth.provider.AuthProvider` seam so SSO / hosted approvals
can attach later — core ships only the local provider.

This subpackage is policy-core-adjacent: it must never import ``doberman.proxy``
(enforced by import-linter). The proxy is the orchestrator that *uses* it.
"""
