"""Tutorial custom Detector plugin for Doberman (issue #200).

Install with ``pip install -e examples/plugin-detector`` from a Doberman-Core
checkout (after installing ``doberman-core`` itself). Core discovers this package
through the ``doberman.detectors`` entry-point group — no core import of this
package is required.

The entry point loads ``example_detector_plugin.detectors:ExampleDetector``
directly; this ``__init__`` deliberately avoids an eager re-export so package
import stays free of import-time side effects.
"""

__all__ = ["ExampleDetector"]


def __getattr__(name: str):
    if name == "ExampleDetector":
        from example_detector_plugin.detectors import ExampleDetector

        return ExampleDetector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
