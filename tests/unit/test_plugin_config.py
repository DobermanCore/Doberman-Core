"""The opt-in-by-name plugins allowlist (:mod:`doberman.engine.plugin_config`).

Mirrors ``tests/unit/test_approval.py``'s coverage of ``approval_config``:
read/write/malformed/env-override, plus the one property unique to this
module — the process snapshot does not widen mid-run.
"""

import pytest

from doberman.engine import plugin_config


@pytest.fixture(autouse=True)
def _reset_snapshot_around_each_test():
    """This module pokes the process-wide snapshot directly (not via the
    ``enable_plugins`` conftest fixture); reset before and after so no test
    here leaks cached state into a later test file in the same session."""
    plugin_config.reset_snapshot()
    yield
    plugin_config.reset_snapshot()


def test_no_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "missing.json"))
    assert plugin_config.enabled_plugins() == []


def test_enable_then_read_back(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.enable("my_rule")
    assert plugin_config.enabled_plugins() == ["my_rule"]
    plugin_config.enable("my_sink")
    assert plugin_config.enabled_plugins() == ["my_rule", "my_sink"]


def test_enable_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.enable("dup")
    plugin_config.enable("dup")
    assert plugin_config.enabled_plugins() == ["dup"]


def test_disable_removes(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.enable("a")
    plugin_config.enable("b")
    plugin_config.disable("a")
    assert plugin_config.enabled_plugins() == ["b"]


def test_disable_missing_is_a_no_op(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    assert plugin_config.disable("never-enabled") == []


def test_enable_rejects_malformed_name(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    for bad in ("bad name;rm", "", "../../etc/passwd", "a" * 65):
        try:
            plugin_config.enable(bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad!r}")


def test_malformed_file_yields_empty(tmp_path, monkeypatch):
    path = tmp_path / "plugins.json"
    path.write_text("not json", encoding="utf-8")
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    assert plugin_config.enabled_plugins() == []


def test_non_dict_json_yields_empty(tmp_path, monkeypatch):
    path = tmp_path / "plugins.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    assert plugin_config.enabled_plugins() == []


def test_malformed_entries_are_filtered_not_raised(tmp_path, monkeypatch):
    path = tmp_path / "plugins.json"
    path.write_text('{"enabled": ["good_one", 42, "bad name;rm", "good_one"]}', encoding="utf-8")
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    # Well-formed, de-duplicated, order-preserving; the int and the malformed
    # string are silently dropped (reads never raise).
    assert plugin_config.enabled_plugins() == ["good_one"]


def test_env_override_points_at_a_different_file(tmp_path, monkeypatch):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(a))
    plugin_config.enable("in-a")
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(b))
    assert plugin_config.enabled_plugins() == []
    plugin_config.enable("in-b")
    assert plugin_config.enabled_plugins() == ["in-b"]
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(a))
    assert plugin_config.enabled_plugins() == ["in-a"]


# --- the snapshot: the one property that has no approval_config analog -------


def test_snapshot_does_not_widen_until_reset(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.reset_snapshot()
    assert plugin_config.allowed_plugin_names() == ()  # first read: nothing enabled

    plugin_config.enable("late")
    # A live read sees it...
    assert plugin_config.enabled_plugins() == ["late"]
    # ...but the process snapshot, taken once, does NOT — that is the whole
    # point: nothing loaded after discovery starts can widen the allowlist.
    assert plugin_config.allowed_plugin_names() == ()

    plugin_config.reset_snapshot()
    assert plugin_config.allowed_plugin_names() == ("late",)


def test_snapshot_is_cached_across_repeated_calls(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "plugins.json"))
    plugin_config.enable("x")
    plugin_config.reset_snapshot()
    first = plugin_config.allowed_plugin_names()
    plugin_config.enable("y")  # mutate the file after the snapshot was taken
    assert plugin_config.allowed_plugin_names() is first  # identical cached tuple


# --- #638: entries are group:name; legacy bare names keep working -------------

_RULES = "doberman.rules"
_DETECTORS = "doberman.detectors"


def test_enable_with_a_group_records_group_and_name(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "p.json"))
    assert plugin_config.enable("my-rule", _RULES) == ["doberman.rules:my-rule"]
    assert plugin_config.enabled_plugins() == ["doberman.rules:my-rule"]


def test_is_allowed_matches_only_the_enabled_group(tmp_path, monkeypatch):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "p.json"))
    allowed = plugin_config.enable("my-rule", _RULES)
    assert plugin_config.is_allowed(_RULES, "my-rule", allowed)
    assert not plugin_config.is_allowed(_DETECTORS, "my-rule", allowed)
    assert plugin_config.names_for_group(_RULES, allowed) == ["my-rule"]
    assert plugin_config.names_for_group(_DETECTORS, allowed) == []


def test_an_old_bare_name_file_keeps_its_plugins_enabled(tmp_path, monkeypatch):
    path = tmp_path / "p.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    path.write_text('{"enabled": ["my-rule"]}', encoding="utf-8")
    allowed = plugin_config.enabled_plugins()
    assert allowed == ["my-rule"]
    assert plugin_config.legacy_entries(allowed) == ["my-rule"]
    assert plugin_config.is_allowed(_RULES, "my-rule", allowed)
    assert plugin_config.is_allowed(_DETECTORS, "my-rule", allowed)


def test_enabling_a_legacy_name_for_a_group_narrows_it(tmp_path, monkeypatch):
    path = tmp_path / "p.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    path.write_text('{"enabled": ["my-rule", "other"]}', encoding="utf-8")
    names = plugin_config.enable("my-rule", _RULES)
    assert names == ["other", "doberman.rules:my-rule"]
    assert not plugin_config.is_allowed(_DETECTORS, "my-rule", names)


def test_disable_without_a_group_removes_every_entry_for_the_name(tmp_path, monkeypatch):
    path = tmp_path / "p.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    path.write_text(
        '{"enabled": ["doberman.rules:x", "doberman.detectors:x", "x", "y"]}', encoding="utf-8"
    )
    assert plugin_config.disable("x") == ["y"]


def test_disable_with_a_group_removes_only_that_entry(tmp_path, monkeypatch):
    path = tmp_path / "p.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    path.write_text('{"enabled": ["doberman.rules:x", "doberman.detectors:x"]}', encoding="utf-8")
    assert plugin_config.disable("x", _DETECTORS) == ["doberman.rules:x"]


@pytest.mark.parametrize("group", ["rules", "doberman.", "other.rules", "doberman.Rules"])
def test_enable_rejects_a_malformed_group(tmp_path, monkeypatch, group):
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(tmp_path / "p.json"))
    with pytest.raises(ValueError, match="invalid plugin group"):
        plugin_config.enable("x", group)
    assert plugin_config.enabled_plugins() == []


def test_malformed_group_entries_in_the_file_are_dropped(tmp_path, monkeypatch):
    path = tmp_path / "p.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    path.write_text('{"enabled": ["evil:x", "doberman.rules:ok", "a:b:c"]}', encoding="utf-8")
    assert plugin_config.enabled_plugins() == ["doberman.rules:ok"]
