from __future__ import annotations

import os
import subprocess
import venv
from collections.abc import Iterator
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PLUGIN_ROOT = _REPO_ROOT / "examples" / "plugin-guardrail"
_PLUGIN_DISTRIBUTION = "doberman-example-plugin-guardrail"
_PACKAGE_NOT_FOUND_EXIT_CODE = 23
_PIP_REDIRECTION_ENVIRONMENT_VARIABLES = (
    "PIP_INSTALL_OPTION",
    "PIP_PREFIX",
    "PIP_ROOT",
    "PIP_TARGET",
    "PIP_USER",
    "PYTHONUSERBASE",
)

_DISCOVERY_CHECK = """
from datetime import datetime, timezone

from doberman.engine import plugin_config
plugin_config.enable("example_rule")  # opt-in by name: discovery is opt-in now

from doberman.engine.registry import discover_rules
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

matches = [
    rule
    for rule in discover_rules()
    if type(rule).__module__ == "example_plugin.rules"
    and type(rule).__name__ == "ExampleRule"
]
assert len(matches) == 1, f"expected one installed ExampleRule, found {matches!r}"

action = SecurityObject(
    id="real-plugin-install",
    ts=datetime.now(timezone.utc),
    agent_role="unknown",
    action_type=ActionType.file_write,
    tool_name="write_file",
    target="SECRETS_TODO.md",
)
result = matches[0].evaluate(
    action,
    EvalContext(metadata={"raw_arguments": {"path": "SECRETS_TODO.md"}}),
)
assert result.verdict is Verdict.AUTH
assert ReasonCode.sensitive_path_access in result.reason_codes
"""

_INSTALLATION_STATE_CHECK = f"""
from importlib.metadata import PackageNotFoundError, version
from sys import exit

try:
    version({_PLUGIN_DISTRIBUTION!r})
except PackageNotFoundError:
    exit({_PACKAGE_NOT_FOUND_EXIT_CODE})
"""


def _run(
    python: Path, *args: str, cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for variable in _PIP_REDIRECTION_ENVIRONMENT_VARIABLES:
        environment.pop(variable, None)
    result = subprocess.run(  # noqa: S603 - the interpreter and arguments are test-controlled
        [str(python), *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"command failed with return code {result.returncode}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _plugin_is_installed(python: Path, cwd: Path) -> bool:
    result = _run(python, "-c", _INSTALLATION_STATE_CHECK, cwd=cwd, check=False)
    if result.returncode == 0:
        return True
    if result.returncode == _PACKAGE_NOT_FOUND_EXIT_CODE:
        return False
    raise AssertionError(
        f"installation-state probe failed with return code {result.returncode}\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )


@pytest.fixture
def installed_plugin_python(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    env_dir = tmp_path / "plugin-env"
    venv.EnvBuilder(with_pip=True, system_site_packages=True).create(env_dir)
    python = env_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    monkeypatch.setenv("PIP_TARGET", str(tmp_path / "redirected-install"))
    # Discovery is opt-in by name now (plugin_config); point the subprocess at
    # a throwaway plugins file so `_DISCOVERY_CHECK`'s `enable()` call never
    # touches this machine's real per-user allowlist.
    monkeypatch.setenv("DOBERMAN_PLUGINS_FILE", str(tmp_path / "plugins.json"))
    assert not _plugin_is_installed(python, cwd=tmp_path)
    try:
        _run(
            python,
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-input",
            "install",
            "--no-deps",
            "-e",
            str(_PLUGIN_ROOT),
            cwd=tmp_path,
        )
        assert _plugin_is_installed(python, cwd=tmp_path)
        yield python
    finally:
        if _plugin_is_installed(python, cwd=tmp_path):
            _run(
                python,
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "--no-input",
                "uninstall",
                "-y",
                _PLUGIN_DISTRIBUTION,
                cwd=tmp_path,
            )
        assert not _plugin_is_installed(python, cwd=tmp_path)


def test_installed_plugin_is_discovered_and_fires_despite_pip_target(
    installed_plugin_python: Path, tmp_path: Path
) -> None:
    _run(installed_plugin_python, "-c", _DISCOVERY_CHECK, cwd=tmp_path)
