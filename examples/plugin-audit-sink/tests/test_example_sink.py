"""Prove the tutorial sink discovers, emits correctly, and never raises.

Run after installing core + this package (from the Doberman-Core checkout)::

    pip install -e .
    pip install -e examples/plugin-audit-sink
    pytest examples/plugin-audit-sink/tests -q

"""

from __future__ import annotations

import json
import pathlib

import pytest
from doberman.engine.registry import AUDIT_SINK_GROUP, discover_audit_sinks

from example_audit_sink.sinks import SINK_FILE_ENV, ExampleAuditSink

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


@pytest.fixture()
def sink_file(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Point the sink at a temp file and return its path."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(SINK_FILE_ENV, str(path))
    return path


# ---------------------------------------------------------------------------
# A: Discovery
# ---------------------------------------------------------------------------


def test_entry_point_is_discoverable_after_install():
    """``pip install -e`` registers the entry point; discover_audit_sinks finds it."""
    sinks = discover_audit_sinks()
    assert any(isinstance(s, ExampleAuditSink) for s in sinks), (
        f"ExampleAuditSink not discovered via {AUDIT_SINK_GROUP!r}; "
        "install with: pip install -e examples/plugin-audit-sink"
    )


# ---------------------------------------------------------------------------
# B: emit writes exactly the dict it was handed
# ---------------------------------------------------------------------------


def test_emit_writes_one_json_line(sink_file: pathlib.Path):
    sink = ExampleAuditSink()
    sink.emit(_SAMPLE_RECORD)

    lines = sink_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    written = json.loads(lines[0])
    assert written == _SAMPLE_RECORD


def test_emit_appends_multiple_records(sink_file: pathlib.Path):
    sink = ExampleAuditSink()
    records = [dict(_SAMPLE_RECORD, action_id=f"act-{i}") for i in range(3)]
    for r in records:
        sink.emit(r)

    lines = sink_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for i, line in enumerate(lines):
        assert json.loads(line)["action_id"] == f"act-{i}"


def test_emit_record_is_unchanged(sink_file: pathlib.Path):
    """emit must treat the record as read-only; the original dict is untouched."""
    original = dict(_SAMPLE_RECORD)
    sink = ExampleAuditSink()
    sink.emit(original)
    assert original == _SAMPLE_RECORD


# ---------------------------------------------------------------------------
# C: emit never raises — a sink that throws must not break a decision
# ---------------------------------------------------------------------------


def test_emit_never_raises_on_unwritable_path(monkeypatch: pytest.MonkeyPatch):
    """Point the sink at an unwritable path; emit must swallow the error."""
    monkeypatch.setenv(SINK_FILE_ENV, "/proc/doberman_no_such_dir/audit.jsonl")
    sink = ExampleAuditSink()
    # Must not raise — a failing sink is never allowed to propagate into core.
    sink.emit(_SAMPLE_RECORD)


def test_emit_never_raises_on_empty_record(sink_file: pathlib.Path):
    sink = ExampleAuditSink()
    sink.emit({})  # minimal record — still valid JSON, must not raise


def test_emit_never_raises_on_non_serialisable_value(sink_file: pathlib.Path):
    """json.dumps uses default=str; objects that are not JSON-native still land."""
    record = dict(_SAMPLE_RECORD, extra=object())
    sink = ExampleAuditSink()
    sink.emit(record)  # must not raise


# ---------------------------------------------------------------------------
# D: sink does not add fields the record did not contain
# ---------------------------------------------------------------------------


def test_emit_does_not_add_extra_fields(sink_file: pathlib.Path):
    """The written line must contain no keys beyond what was in the input record."""
    sink = ExampleAuditSink()
    sink.emit(_SAMPLE_RECORD)

    written = json.loads(sink_file.read_text(encoding="utf-8").splitlines()[0])
    extra_keys = set(written.keys()) - set(_SAMPLE_RECORD.keys())
    assert extra_keys == set(), f"sink added unexpected fields: {extra_keys}"


# ---------------------------------------------------------------------------
# E: env-var path override
# ---------------------------------------------------------------------------


def test_env_var_controls_output_path(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    custom = tmp_path / "subdir" / "custom.jsonl"
    monkeypatch.setenv(SINK_FILE_ENV, str(custom))
    ExampleAuditSink().emit(_SAMPLE_RECORD)
    assert custom.exists()
    assert json.loads(custom.read_text(encoding="utf-8").strip()) == _SAMPLE_RECORD


def test_default_path_used_when_env_var_absent(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """When DOBERMAN_AUDIT_SINK_FILE is unset the sink writes to the system temp dir."""
    monkeypatch.delenv(SINK_FILE_ENV, raising=False)
    from example_audit_sink.sinks import _default_sink_path

    default = _default_sink_path()
    # Point tempfile at tmp_path so we don't litter the real temp dir.
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    # Re-resolve after monkeypatching gettempdir.
    resolved = _default_sink_path()
    ExampleAuditSink().emit(_SAMPLE_RECORD)
    assert resolved.exists() or default.exists()  # one of the two paths must exist


# ---------------------------------------------------------------------------
# F: thread safety — concurrent emits produce valid, non-interleaved lines
# ---------------------------------------------------------------------------


def test_concurrent_emits_produce_valid_lines(sink_file: pathlib.Path):
    import threading

    sink = ExampleAuditSink()
    errors: list[Exception] = []

    def _emit(i: int) -> None:
        try:
            sink.emit(dict(_SAMPLE_RECORD, action_id=f"act-{i}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_emit, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"emit raised in thread: {errors}"
    lines = sink_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 20
    for line in lines:
        parsed = json.loads(line)  # must be valid JSON
        assert "action_id" in parsed
