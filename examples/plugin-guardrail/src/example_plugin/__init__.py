"""Tutorial custom Guardrail plugin for Doberman (issue #91).

Install with ``pip install -e examples/plugin-guardrail`` from a Doberman-Core
checkout (after installing ``doberman-core`` itself). Core discovers this package
through the ``doberman.rules`` entry-point group — no core import of this
package is required.

The entry point loads ``example_plugin.rules:ExampleRule`` directly; this
``__init__`` deliberately avoids an eager re-export so package import stays free
of import-time side effects.
"""

__all__ = ["ExampleRule"]


def __getattr__(name: str):
    if name == "ExampleRule":
        from example_plugin.rules import ExampleRule

        return ExampleRule
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
