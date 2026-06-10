"""Slice 6.2 — review + persist policy via the CLI.

Covers: `doberman review --yes` saves a valid policies.yaml; read-only review
does not write; mode set/get round-trips; an unknown mode is rejected; a core
hard block is not disableable; status reports role+mode; and a persisted toggle
survives a reload.
"""

import pytest
from typer.testing import CliRunner

from doberman import config
from doberman.cli.main import app
from doberman.policy.checklist import recommend_policy

runner = CliRunner()


def test_review_yes_saves_policy(tmp_path):
    result = runner.invoke(app, ["review", "--path", str(tmp_path), "--yes"])
    assert result.exit_code == 0
    assert (tmp_path / ".doberman" / "policies.yaml").exists()
    doc = config.load_policy(str(tmp_path))
    assert doc is not None
    assert any(it.core for it in doc.items)


def test_review_readonly_does_not_save(tmp_path):
    result = runner.invoke(app, ["review", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert not (tmp_path / ".doberman" / "policies.yaml").exists()


def test_mode_set_then_get_round_trips(tmp_path):
    assert runner.invoke(app, ["mode", "strict", "--path", str(tmp_path)]).exit_code == 0
    assert config.load_mode(str(tmp_path)) == "strict"
    shown = runner.invoke(app, ["mode", "--path", str(tmp_path)])
    assert "strict" in shown.output


def test_unknown_mode_is_rejected(tmp_path):
    result = runner.invoke(app, ["mode", "turbo", "--path", str(tmp_path)])
    assert result.exit_code == 2
    # The bad mode must not have created/changed a policy file.
    assert config.load_mode(str(tmp_path)) == "balanced"


def test_core_block_not_disableable_via_api():
    doc = recommend_policy()
    core_id = next(it.id for it in doc.items if it.core)
    with pytest.raises(ValueError):
        doc.with_item_enabled(core_id, False)


def test_status_reports_role_and_mode(tmp_path):
    runner.invoke(app, ["mode", "paranoid", "--path", str(tmp_path)])
    result = runner.invoke(app, ["status", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "paranoid" in result.output
    assert "Role" in result.output


def test_persisted_toggle_survives_reload(tmp_path):
    doc = recommend_policy().with_item_enabled("step_up.bulk_operation", False)
    config.save_policy(doc, str(tmp_path))
    reloaded = config.load_policy(str(tmp_path))
    assert reloaded is not None
    assert reloaded.get("step_up.bulk_operation").enabled is False
