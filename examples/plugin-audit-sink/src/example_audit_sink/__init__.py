"""Tutorial custom AuditSink plugin for Doberman (issue #442).

Install with ``pip install -e examples/plugin-audit-sink`` from a
Doberman-Core checkout (after installing ``doberman-core`` itself). Core
discovers this package through the ``doberman.audit_sinks`` entry-point group
— no core import of this package is required.

The entry point loads ``example_audit_sink.sinks:ExampleAuditSink`` directly;
this ``__init__`` deliberately avoids an eager re-export so package import
stays free of import-time side effects.
"""

__all__ = ["ExampleAuditSink"]


def __getattr__(name: str):
    if name == "ExampleAuditSink":
        from example_audit_sink.sinks import ExampleAuditSink

        return ExampleAuditSink
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
