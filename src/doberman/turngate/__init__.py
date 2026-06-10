"""The turn gate (Feature 11) — the decision engine's pre-inference invocation point.

This package is an *adapter* layer (sibling to :mod:`doberman.proxy`): it
normalizes an incoming turn into a :class:`~doberman.models.TurnObject`, routes
it through ``decide_turn`` before the model runs, and enforces the verdict. Like
the proxy, it may import the engine / auth / storage; the policy core must never
import it (enforced by import-linter).

Its guarantee is narrow and stated plainly: *no Tier-0-signature turn reaches the
model*. The action gate (core + subjective layer) remains the safety guarantee.
The gate requires a host pre-inference hook; where none exists (pure MCP-proxy
deployments) the gate is simply absent and the action gate carries everything.
"""
