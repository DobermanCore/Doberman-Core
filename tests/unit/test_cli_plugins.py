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
    enabled = runner.invoke(app, ["plugins", "enable", "my_rule", "--group", "rules"])
    assert enabled.exit_code == 0, enabled.output
    assert "my_rule" in enabled.output
    assert plugin_config.enabled_plugins() == ["doberman.rules:my_rule"]

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


# --- #638: `plugins enable` records the group --------------------------------


def _install(monkeypatch, by_group):
    from doberman.engine import registry

    class _FakeEP:
        def __init__(self, name):
            self.name = name

        def load(self):
            raise AssertionError("enabling must never load an entry point")

    monkeypatch.setattr(
        registry,
        "_iter_entry_points",
        lambda group: iter([_FakeEP(n) for n in by_group.get(group, [])]),
    )


def test_enable_takes_the_group_from_the_installed_entry_point(plugins_cfg, monkeypatch):
    from doberman.engine import registry

    _install(monkeypatch, {registry.DETECTOR_GROUP: ["my_detector"]})
    result = runner.invoke(app, ["plugins", "enable", "my_detector"])
    assert result.exit_code == 0, result.output
    assert plugin_config.enabled_plugins() == ["doberman.detectors:my_detector"]
    assert "warning:" not in result.output


def test_enable_asks_for_a_group_when_the_name_is_in_several(plugins_cfg, monkeypatch):
    from doberman.engine import registry

    _install(monkeypatch, {registry.RULE_GROUP: ["shared"], registry.AUDIT_SINK_GROUP: ["shared"]})
    result = runner.invoke(app, ["plugins", "enable", "shared"])
    assert result.exit_code == 1
    assert "pass --group" in result.output
    assert plugin_config.enabled_plugins() == []

    chosen = runner.invoke(app, ["plugins", "enable", "shared", "--group", "audit_sinks"])
    assert chosen.exit_code == 0, chosen.output
    assert plugin_config.enabled_plugins() == ["doberman.audit_sinks:shared"]


def test_enable_without_a_group_refuses_a_name_nothing_provides(plugins_cfg, monkeypatch):
    _install(monkeypatch, {})
    result = runner.invoke(app, ["plugins", "enable", "not_installed"])
    assert result.exit_code == 1
    assert "pass --group" in result.output
    assert plugin_config.enabled_plugins() == []


def test_enable_rejects_an_unknown_group(plugins_cfg):
    result = runner.invoke(app, ["plugins", "enable", "x", "--group", "nope"])
    assert result.exit_code == 1
    assert "unknown plugin group" in result.output
    assert plugin_config.enabled_plugins() == []


def test_list_flags_a_legacy_bare_entry(plugins_cfg):
    (plugins_cfg / "plugins.json").write_text('{"enabled": ["old_rule"]}', encoding="utf-8")
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0, result.output
    assert "'old_rule' has no group" in result.output
