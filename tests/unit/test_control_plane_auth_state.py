"""The per-user auth state is control plane: shell commands naming it are blocked.

``doberman.auth.totp`` and ``doberman.auth.password`` keep the TOTP seed, its
lockout counter, and the password hash in a per-user config dir
(``%LOCALAPPDATA%`` / ``$XDG_CONFIG_HOME`` / ``~/.config``, then ``doberman/``) —
deliberately **outside** any repository so they are never committed. That same
property put them past :func:`doberman.canonical.canonicalize`'s repo-root
confinement, so the repo-relative ``CONTROL_PLANE_GLOBS`` could never reach them
and every one of these commands PASSed with no reason code at all.

What that bought an agent:

* ``rm .../doberman/totp.secret`` — un-enrols 2FA, so every "TOTP if enrolled"
  gate silently degrades to confirm-only.
* ``rm .../doberman/totp.secret.lockout`` — resets the consecutive-failure
  counter, removing the brake on TOTP guessing.
* overwriting either secret — hands the attacker the possession factor itself.

ADR 0065.
"""

from datetime import datetime, timezone

import pytest

from doberman.engine.rules.commands import DestructiveCommandRule
from doberman.engine.rules.paths import names_control_plane
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

RULE = DestructiveCommandRule()


def _cmd(command, *, root="."):
    action = SecurityObject(
        id="cp-auth-1",
        ts=datetime(2026, 8, 6, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.shell_exec,
        tool_name="Bash",
        target=command,
        metadata={},
    )
    ctx = EvalContext(metadata={"raw_arguments": {"command": command}, "repo_root": root})
    return RULE.evaluate(action, ctx)


# --- the auth-state files, named in a shell command → BLOCK ---


@pytest.mark.parametrize(
    "command",
    [
        # POSIX default location ($XDG_CONFIG_HOME unset → ~/.config)
        "rm ~/.config/doberman/totp.secret",
        "rm ~/.config/doberman/totp.secret.lockout",
        "rm ~/.config/doberman/password.hash",
        # Windows default location (%LOCALAPPDATA%)
        "rm ~/AppData/Local/doberman/totp.secret",
        "rm ~/AppData/Local/doberman/password.hash",
        "rm %LOCALAPPDATA%/doberman/totp.secret",
        # absolute, fully spelled out
        "rm /home/dev/.config/doberman/totp.secret",
        "rm C:/Users/dev/AppData/Local/doberman/totp.secret",
    ],
)
def test_deleting_an_auth_state_file_is_blocked(command):
    result = _cmd(command)
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.protected_path_blocked in result.reason_codes


@pytest.mark.parametrize(
    "command",
    [
        "echo AAAAAAAAAAAAAAAA > ~/.config/doberman/totp.secret",
        "echo x >> ~/AppData/Local/doberman/password.hash",
        "cp /tmp/mine.secret ~/.config/doberman/totp.secret",
    ],
)
def test_overwriting_an_auth_state_file_is_blocked(command):
    """Replacing the seed is worse than deleting it — the attacker then knows the
    factor. Redirect targets and copy destinations both have to be caught."""
    assert _cmd(command).verdict is Verdict.BLOCK


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ~/.config/doberman",
        "rm -rf ~/AppData/Local/doberman",
        "rm -rf /home/dev/.config/doberman",
    ],
)
def test_deleting_the_whole_auth_state_dir_is_blocked(command):
    """The per-file globs alone would miss a recursive delete of the directory."""
    assert _cmd(command).verdict is Verdict.BLOCK


def test_reading_the_totp_seed_is_blocked():
    """Reading the seed is enough to generate valid codes forever."""
    assert _cmd("cat ~/.config/doberman/totp.secret").verdict is Verdict.BLOCK


# --- the regression that pins the narrow glob choice ---


@pytest.mark.parametrize(
    "command",
    [
        # A checkout of this very project is a directory named `doberman`. A bare
        # `**/doberman` glob would have blocked ordinary work on it.
        "rm ~/src/doberman/README.md",
        "rm -rf ~/Documents/GitHub/Doberman/build",
        "cat ~/code/doberman/pyproject.toml",
        # ...and an unrelated file that merely lives under a config dir.
        "rm ~/.config/someapp/settings.json",
        "rm ~/notes.txt",
    ],
)
def test_ordinary_work_on_a_doberman_checkout_is_not_blocked(command):
    """The auth-state globs are deliberately narrow: they name the state dir's
    real parents (`appdata/local`, `.config`) and the three real filenames, never
    a bare `**/doberman`. Widening them would make this project unworkable."""
    assert _cmd(command).verdict is not Verdict.BLOCK


def test_explanation_does_not_echo_the_auth_state_path():
    """Prime Directive 3: the reason names the category, never the path."""
    result = _cmd("rm /home/dev/.config/doberman/totp.secret")
    blob = f"{result.explanation} {' '.join(str(c) for c in result.reason_codes)}"
    assert "/home/dev" not in blob
    assert "totp.secret" not in blob


# --- the glob predicate itself, independent of the command rule ---


@pytest.mark.parametrize(
    "path",
    [
        "~/.config/doberman/totp.secret",
        "~/.config/doberman/totp.secret.lockout",
        "~/.config/doberman/password.hash",
        "C:/Users/dev/AppData/Local/doberman/totp.secret",
        "C:\\Users\\dev\\AppData\\Local\\doberman\\totp.secret",
        "%LOCALAPPDATA%\\doberman\\password.hash",
    ],
)
def test_names_control_plane_recognises_the_auth_state(path):
    assert names_control_plane(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "~/src/doberman/README.md",
        "~/Documents/GitHub/Doberman/pyproject.toml",
        "~/.config/someapp/settings.json",
        "totp.secret",  # a bare filename in the repo is not the per-user state
    ],
)
def test_names_control_plane_leaves_ordinary_paths_alone(path):
    assert names_control_plane(path) is False
