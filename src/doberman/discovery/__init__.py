"""Local capability discovery and risk mapping (Feature 5).

Read-only inspection of how much power an agent has — its tool capabilities plus
the sensitive surface of the repository — rendered as a local risk map. This
package never opens secret-file *contents* (it detects by name/existence) and
never writes outside ``.doberman/``.
"""
