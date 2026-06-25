"""Host-harness hook adapters — let a coding-agent *harness* (e.g. Claude Code)
invoke Doberman before/after every tool call, so protection does not depend on
the agent choosing to route its tools through Doberman.

This is a sibling *invocation adapter* to :mod:`doberman.proxy` (the MCP
chokepoint): it consumes the engine, and the policy core never imports it
(import-linter enforced). With only an objective, deterministic decision the hook
path stays fast enough to run on every tool call.
"""
