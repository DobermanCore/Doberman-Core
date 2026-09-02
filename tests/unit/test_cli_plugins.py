"""CLI controls for the opt-in-by-name plugins allowlist (``doberman plugins``)."""

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.engine import plugin_config

runner = CliRunner()


@pytest.fixture
def plugins_cfg(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    return tmp_path


def test_list_with_nothing_enabled(plugins_cfg):
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0, result.output
    assert "(none)" in result.output


def test_enable_disable_round_trip(plugins_cfg):
    enabled = runner.invoke(app, ["plugins", "enable", "my_rule"])
    assert enabled.exit_code == 0, enabled.output
    assert "my_rule" in enabled.output
    assert plugin_config.enabled_plugins() == ["my_rule"]

    listed = runner.invoke(app, ["plugins", "list"])
    assert listed.exit_code == 0, listed.output
    assert "my_rule" in listed.output

    disabled = runner.invoke(app, ["plugins", "disable", "my_rule"])
    assert disabled.exit_code == 0, disabled.output
    assert plugin_config.enabled_plugins() == []


def test_enable_rejects_malformed_name(plugins_cfg):
    result = runner.invoke(app, ["plugins", "enable", "bad name;rm"])
    assert result.exit_code == 1
    assert plugin_config.enabled_plugins() == []


def test_disable_never_enabled_is_a_no_op(plugins_cfg):
    result = runner.invoke(app, ["plugins", "disable", "never-enabled"])
    assert result.exit_code == 0, result.output
    assert plugin_config.enabled_plugins() == []


def test_list_shows_installed_entry_points_without_loading(plugins_cfg, monkeypatch):
    """Listing must never import an entry point just to show it's present."""
    from doberman.engine import registry

    class _FakeEP:
        name = "untrusted"

        def load(self):
            raise AssertionError("listing must never load an entry point")

    class _FakeEPs:
        def select(self, *, group):
            return [_FakeEP()] if group == registry.RULE_GROUP else []

    monkeypatch.setattr(registry, "entry_points", lambda: _FakeEPs())
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0, result.output
    assert "untrusted" in result.output
    assert "disabled" in result.output


def test_list_marks_an_enabled_installed_entry_point(plugins_cfg, monkeypatch):
    from doberman.engine import registry

    class _FakeEP:
        name = "trusted_rule"

        def load(self):
            raise AssertionError("listing must never load an entry point")

    class _FakeEPs:
        def select(self, *, group):
            return [_FakeEP()] if group == registry.RULE_GROUP else []

    monkeypatch.setattr(registry, "entry_points", lambda: _FakeEPs())
    runner.invoke(app, ["plugins", "enable", "trusted_rule"])
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0, result.output
    assert "ENABLED" in result.output
