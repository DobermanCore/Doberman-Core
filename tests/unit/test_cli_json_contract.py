"""Contract tests for CLI machine-readable --json output guarantees (CLI.md:109-119, #718)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Callable

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import save_policy
from doberman.engine import plugin_config
from doberman.policy.checklist import recommend_policy
from doberman.storage.policy_catalogue import read_versions

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_plugins_file(tmp_path, monkeypatch) -> Path:
    """Keep `plugins` commands off the real per-user allowlist."""
    path = tmp_path / "plugins.json"
    monkeypatch.setenv(plugin_config.PLUGINS_FILE_ENV, str(path))
    return path


@pytest.fixture
def seeded_repo(tmp_path) -> str:
    root = str(tmp_path)
    save_policy(recommend_policy().with_mode("strict"), root)
    save_policy(recommend_policy().with_mode("balanced"), root)
    return root


@pytest.mark.parametrize(
    "command_args_fn",
    [
        lambda root: ["status", "--path", root, "--json"],
        lambda root: ["scan", "--path", root, "--json"],
        lambda root: ["doctor", "--path", root, "--json"],
        lambda root: ["policy-history", "--path", root, "--json"],
        lambda root: ["policy-versions", "--path", root, "--json"],
        lambda root: [
            "policy-versions",
            "--path",
            root,
            "--show",
            read_versions(root)[0]["version"],
            "--json",
        ],
        lambda root: ["tune", "--path", root, "--json"],
        lambda root: ["plugins", "list", "--json"],
    ],
    ids=[
        "status",
        "scan",
        "doctor",
        "policy-history",
        "policy-versions",
        "policy-versions-show",
        "tune",
        "plugins-list",
    ],
)
def test_cli_json_modes_satisfy_contract(
    seeded_repo: str, command_args_fn: Callable[[str], list[str]]
) -> None:
    args = command_args_fn(seeded_repo)
    result = runner.invoke(app, args)
    assert result.stdout, f"Empty stdout for {args}"
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 1, (
        f"Expected compact single-line JSON, got {len(lines)} lines: {result.stdout}"
    )

    # Parses as JSON
    data = json.loads(result.stdout)
    assert isinstance(data, (dict, list))

    # Compact separators: no whitespace around delimiters
    assert '", "' not in result.stdout
    assert '": "' not in result.stdout

    # Deterministic sorted keys and compact separators
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    assert result.stdout.strip() == canonical

    # Determinism: byte-for-byte identical on a rerun
    rerun = runner.invoke(app, args)
    assert rerun.stdout == result.stdout


# --- #805: `plugins list --json` lists entry points by name, never loads them ----

_SENTINEL_MODULE = "doberman_805_sentinel_plugin"


@pytest.fixture
def sentinel_plugin(tmp_path, monkeypatch) -> Path:
    """Install a real `doberman.rules` entry point whose module, if ever imported,
    writes a sentinel file. Returns the sentinel path (which must never appear)."""
    site = tmp_path / "site"
    sentinel = tmp_path / "imported.sentinel"
    (site / f"{_SENTINEL_MODULE}.py").parent.mkdir(parents=True)
    (site / f"{_SENTINEL_MODULE}.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('imported')\n"
        "class Rule:\n    pass\n",
        encoding="utf-8",
    )
    dist_info = site / "doberman_805_sentinel-0.0.1.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: doberman-805-sentinel\nVersion: 0.0.1\n",
        encoding="utf-8",
    )
    (dist_info / "entry_points.txt").write_text(
        f"[doberman.rules]\nsentinel_rule = {_SENTINEL_MODULE}:Rule\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.delitem(sys.modules, _SENTINEL_MODULE, raising=False)
    return sentinel


def _plugins_list_json() -> dict:
    result = runner.invoke(app, ["plugins", "list", "--json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout)


def test_plugins_list_json_shape_and_never_imports_plugin(sentinel_plugin: Path) -> None:
    data = _plugins_list_json()
    assert set(data) == {"enabled", "installed"}
    assert data["enabled"] == []
    assert {"group": "doberman.rules", "name": "sentinel_rule", "state": "disabled"} in data[
        "installed"
    ]
    for row in data["installed"]:
        assert set(row) == {"group", "name", "state"}
        assert row["state"] in {"enabled", "disabled"}
    assert not sentinel_plugin.exists(), "listing imported the plugin's code"
    assert _SENTINEL_MODULE not in sys.modules


def test_plugins_list_json_marks_enabled_without_importing(sentinel_plugin: Path) -> None:
    enabled = runner.invoke(app, ["plugins", "enable", "sentinel_rule"])
    assert enabled.exit_code == 0, enabled.output

    data = _plugins_list_json()
    assert data["enabled"] == ["doberman.rules:sentinel_rule"]
    assert {"group": "doberman.rules", "name": "sentinel_rule", "state": "enabled"} in data[
        "installed"
    ]
    assert not sentinel_plugin.exists(), "listing imported an enabled plugin's code"
    assert _SENTINEL_MODULE not in sys.modules


def test_plugins_list_json_sends_legacy_note_to_stderr(isolated_plugins_file: Path) -> None:
    isolated_plugins_file.write_text(json.dumps({"enabled": ["bare_name"]}), encoding="utf-8")
    result = runner.invoke(app, ["plugins", "list", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["enabled"] == ["bare_name"]
    assert "note:" not in result.stdout
    assert "bare_name" in result.stderr
