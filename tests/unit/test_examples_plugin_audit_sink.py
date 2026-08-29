"""CI-visible checks for the tutorial plugin under examples/plugin-audit-sink (#442).

The example package is **opt-in** (``pip install -e examples/plugin-audit-sink``).
These tests never install its entry point into the active environment — that would
make ``discover_audit_sinks()`` non-empty for every other test in the suite,
including the standalone guarantee in ``test_core_is_standalone.py``.

They do prove:

* the package layout and ``doberman.audit_sinks`` entry-point declaration are correct;
* ``ExampleAuditSink`` satisfies the core ``AuditSink`` protocol;
* ``emit`` never raises, including on a malformed record;
* the sink's output never echoes a raw secret placed in the record.

Full entry-point discovery after a real install is covered by the example's own
tests (``examples/plugin-audit-sink/tests/``) and documented in its README.
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import tomllib
from pathlib import Path

import pytest

from doberman.engine.registry import discover_audit_sinks
from doberman.storage.sinks import AuditSink

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_ROOT = _REPO_ROOT / "examples" / "plugin-audit-sink"
_EXAMPLE_SRC = _EXAMPLE_ROOT / "src"
_EXAMPLE_PYPROJECT = _EXAMPLE_ROOT / "pyproject.toml"

_SAMPLE_RECORD = {
    "ts": "2026-08-21T12:00:00+00:00",
    "action_id": "act-001",
    "agent_role": "unknown",
    "action_type": "file_write",
    "target_path_class": "general",
    "risk": "low",
    "source_context": "unknown",
    "final_verdict": "PASS",
    "decided_layer": "guardrail",
    "reason_codes": [],
    "auth_required": False,
    "auth_result": None,
    "elevation_id": None,
    "entity_id": "hmac:abc123",
    "session_id": "sess-001",
}

_SECRET_MARKER = "SYNTHETIC-SECRET-9f3a"  # noqa: S105 — test fixture, not a real credential


@pytest.fixture(scope="module")
def example_sink_cls():
    """Import ExampleAuditSink from the checkout without installing the package."""
    assert _EXAMPLE_SRC.is_dir(), f"missing tutorial package at {_EXAMPLE_SRC}"
    inserted = str(_EXAMPLE_SRC)
    sys.path.insert(0, inserted)
    try:
        sys.modules.pop("example_audit_sink", None)
        sys.modules.pop("example_audit_sink.sinks", None)
        module = importlib.import_module("example_audit_sink.sinks")
        return module.ExampleAuditSink
    finally:
        # Leave the module importable for the rest of this module's tests, but
        # drop the path entry so we do not permanently shadow site-packages.
        if sys.path and sys.path[0] == inserted:
            sys.path.pop(0)


def test_example_package_layout_exists():
    assert (_EXAMPLE_ROOT / "README.md").is_file()
    assert (_EXAMPLE_SRC / "example_audit_sink" / "sinks.py").is_file()
    assert (_EXAMPLE_ROOT / "tests" / "test_example_sink.py").is_file()
    assert _EXAMPLE_PYPROJECT.is_file()


def test_example_pyproject_declares_doberman_audit_sinks_entry_point():
    data = tomllib.loads(_EXAMPLE_PYPROJECT.read_text(encoding="utf-8"))
    eps = data["project"]["entry-points"]["doberman.audit_sinks"]
    assert eps["example_sink"] == "example_audit_sink.sinks:ExampleAuditSink"
    # Mirror the core package name so ``pip install -e`` resolves against this repo.
    assert "doberman-core" in data["project"]["dependencies"]


def test_example_sink_satisfies_audit_sink_protocol(example_sink_cls):
    assert isinstance(example_sink_cls(), AuditSink)


def test_example_sink_emit_never_raises(example_sink_cls, tmp_path, monkeypatch):
    from example_audit_sink.sinks import SINK_FILE_ENV

    monkeypatch.setenv(SINK_FILE_ENV, str(tmp_path / "audit.jsonl"))
    sink = example_sink_cls()
    sink.emit(dict(_SAMPLE_RECORD))  # well-formed record
    sink.emit({})  # malformed / empty record — must not raise
    sink.emit({"unexpected": object()})  # non-JSON-native value — must not raise


def test_example_sink_failure_log_never_echoes_a_secret(
    example_sink_cls, tmp_path, monkeypatch, caplog
):
    """On a failed write the sink logs a WARNING (never raises) — that log line
    is the only side channel besides the JSONL file, and it must not echo the
    record's content, secret or not.

    ``Path.open`` is patched to force the failure deterministically (a real
    permission-denied path is OS-specific and unreliable on the Windows CI leg).
    """
    from example_audit_sink.sinks import SINK_FILE_ENV

    monkeypatch.setenv(SINK_FILE_ENV, str(tmp_path / "audit.jsonl"))

    def _raise(*_args, **_kwargs):
        raise OSError("simulated unwritable sink")

    monkeypatch.setattr(pathlib.Path, "open", _raise)
    sink = example_sink_cls()
    record = dict(_SAMPLE_RECORD, entity_id=_SECRET_MARKER)
    with caplog.at_level("WARNING"):
        sink.emit(record)  # write fails; must not raise

    assert _SECRET_MARKER not in caplog.text


def test_sys_path_import_does_not_register_the_entry_point(example_sink_cls):
    """Importing via sys.path (this module's approach) must not make the tutorial
    discoverable — only a real ``pip install`` populates importlib.metadata."""
    assert discover_audit_sinks() == []
