"""The universal subjective layer (SL1–SL9).

The adaptive half of a decision: estimates whether an action is unusual or
unwanted *for this deployment* and can only ever RAISE risk. One mechanism for
every application type — generality comes from the action algebra, the generic
inference layer, and conservative defaults; sharpness comes from per-entity
baselines, per-deployment preferences, and optional refine-only adapters.

This package is policy core: it must never import ``doberman.proxy``.
"""
