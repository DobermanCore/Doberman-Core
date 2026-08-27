"""`doberman memory --json` (#438)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app

runner = CliRunner()


def _seed(tmp_path):
    """Run the scripted demo through the real engine so memory has rows to summarize."""
    seed = runner.invoke(app, ["demo", "--path", str(tmp_path), "--fast"])
    assert seed.exit_code == 0


def test_memory_json_is_one_compact_document(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["memory", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    # The four documented keys, nothing more.
    assert set(payload) == {"decisions", "verdicts", "top_path_classes", "secrets_seen"}
    # The JSON path exposes counts and classes only, and stays consistent with
    # what the demo seeded: the verdict mix must account for every decision.
    assert payload["decisions"] > 0
    assert sum(payload["verdicts"].values()) == payload["decisions"]
    assert isinstance(payload["secrets_seen"], int)
    # Compact separators (same style as ``scan --json``): no spaces after the
    # "," / ":" separators anywhere in the document.
    assert ", " not in result.stdout
    assert '": ' not in result.stdout
    # Deterministic across runs of the same store.
    again = runner.invoke(app, ["memory", "--path", str(tmp_path), "--json"])
    assert again.exit_code == 0
    assert again.stdout == result.stdout


def test_memory_default_is_text_not_json(tmp_path):
    _seed(tmp_path)
    result = runner.invoke(app, ["memory", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Doberman learned memory" in result.stdout
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stdout)


def test_memory_json_empty_store(tmp_path):
    # No demo seed: an empty store is still exactly one JSON document, not a
    # traceback and not empty stdout.
    result = runner.invoke(app, ["memory", "--path", str(tmp_path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload == {
        "decisions": 0,
        "verdicts": {},
        "top_path_classes": [],
        "secrets_seen": 0,
    }
