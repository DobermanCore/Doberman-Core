"""Contract tests for CLI machine-readable --json output guarantees (CLI.md:109-119, #718)."""

from __future__ import annotations

import json
from typing import Callable

import pytest
from typer.testing import CliRunner

from doberman.cli.main import app
from doberman.config import save_policy
from doberman.policy.checklist import recommend_policy
from doberman.storage.policy_catalogue import read_versions

runner = CliRunner()


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
    ],
    ids=[
        "status",
        "scan",
        "doctor",
        "policy-history",
        "policy-versions",
        "policy-versions-show",
        "tune",
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
