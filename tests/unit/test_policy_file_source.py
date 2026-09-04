"""Issue #147 — policy-as-code: a repo-committed ``doberman.policy.yaml``
resolved through ``PolicySource``, layered raise-only over a local pin.

Covers: the seam stays dormant with no file/plugin (byte-identical to
today); a file's blocked/sensitive globs reach real BLOCK/AUTH end to end,
combined with a role that independently blocks the same target; adding a
glob applies immediately and rewrites the pin; dropping a glob keeps the
dropped glob enforced, leaves the pin untouched, and warns exactly once
across repeated loads of the same file state; a deleted/malformed file
after adoption behaves the same way, never raises; a file under
``.doberman/`` is ignored; ``effective_policy`` memoizes discovery; and the
``doberman policy-file --accept`` gate (mirrors ``doberman mode`` /
``doberman memory reset``).
"""

from __future__ import annotations

import asyncio
import json
import logging

import pyotp
import pytest
import yaml
from typer.testing import CliRunner

from doberman.auth import password, totp
from doberman.cli import main as cli_main
from doberman.cli.main import app
from doberman.hosthooks import spine
from doberman.models import ReasonCode, Verdict
from doberman.policy.drift import read_policy_changes
from doberman.policy.sources import (
    PolicySnapshot,
    _glob_state_map,
    _load_raw_file,
    effective_policy,
    load_file_policy,
)

runner = CliRunner()

_PASSWORD = "correct horse battery staple"  # noqa: S105 — synthetic test credential


def _write_policy_file(repo_root, *, blocked=(), sensitive=(), version=1, text=None) -> None:
    path = repo_root / "doberman.policy.yaml"
    if text is not None:
        path.write_text(text, encoding="utf-8")
        return
    doc: dict = {}
    if version is not None:
        doc["version"] = version
    if blocked:
        doc["blocked"] = list(blocked)
    if sensitive:
        doc["sensitive"] = list(sensitive)
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _pin_path(repo_root):
    return repo_root / ".doberman" / "policy_file_pin.json"


# --- 1. dormant with nothing configured -------------------------------------


def test_no_file_no_plugins_neither_builder_sets_resolved_policy(tmp_path):
    assert effective_policy(str(tmp_path)).is_empty
    result = spine.evaluate_action(
        "fs_write", {"path": "app/notes.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.PASS
    assert ReasonCode.policy_source_blocked not in result.decision.reason_codes
    assert ReasonCode.policy_source_sensitive not in result.decision.reason_codes


# --- 2. end-to-end BLOCK/AUTH, plus a role combined with the file -----------


def test_file_blocked_glob_reaches_block_end_to_end(tmp_path):
    _write_policy_file(tmp_path, blocked=["myteamsecrets/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteamsecrets/key.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK
    assert ReasonCode.policy_source_blocked in result.decision.reason_codes


def test_file_sensitive_glob_reaches_auth_end_to_end(tmp_path):
    _write_policy_file(tmp_path, sensitive=["myteaminfra/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteaminfra/network.conf"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.AUTH
    assert ReasonCode.policy_source_sensitive in result.decision.reason_codes


def test_role_block_plus_file_sensitive_on_same_path_is_block(tmp_path):
    # The role hard-blocks the path; the file only marks it sensitive (AUTH).
    # max_verdict()/combine() must still land on the stricter BLOCK.
    (tmp_path / ".doberman").mkdir()
    (tmp_path / ".doberman" / "role.yaml").write_text(
        yaml.safe_dump({"blocked": ["myteamshared/**"]}), encoding="utf-8"
    )
    _write_policy_file(tmp_path, sensitive=["myteamshared/**"])
    result = spine.evaluate_action(
        "fs_read", {"path": "myteamshared/secret.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK


# --- 2b. a category change is a pure tighten/weaken, never "mixed" ---------


def test_sensitive_to_blocked_is_a_pure_tighten_applies_immediately(tmp_path):
    _write_policy_file(tmp_path, sensitive=["catmove/**"])
    load_file_policy(str(tmp_path))  # adopt: pinned as sensitive

    _write_policy_file(tmp_path, blocked=["catmove/**"])  # promote to blocked
    src = load_file_policy(str(tmp_path))
    assert src.snapshot().blocked_globs == ("catmove/**",)
    assert "catmove/**" not in src.snapshot().sensitive_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["catmove/**"]  # pin rewritten -- auto-tighten, no gate
    assert pin["sensitive"] == []

    result = runner.invoke(app, ["policy-file", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Pending" not in result.stdout  # nothing pending: it already applied


def test_blocked_to_sensitive_is_held_until_accept_block_still_wins(tmp_path):
    _write_policy_file(tmp_path, blocked=["catmove/**"])
    load_file_policy(str(tmp_path))  # adopt: pinned as blocked

    _write_policy_file(tmp_path, sensitive=["catmove/**"])  # demote to sensitive
    src = load_file_policy(str(tmp_path))
    # The pin's blocked entry stays in force -- BLOCK still wins even though
    # the file itself now only asks for AUTH.
    assert "catmove/**" in src.snapshot().blocked_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["catmove/**"]  # unchanged -- held, not auto-applied

    result = spine.evaluate_action(
        "fs_read", {"path": "catmove/secret.txt"}, cwd=str(tmp_path), raw_session_id=None
    )
    assert result.acted is Verdict.BLOCK

    # --accept still sees this as a pending weaken (never a no-op).
    from doberman.policy.drift import Classification, classify_change

    pin_snapshot = PolicySnapshot(blocked_globs=pin["blocked"], sensitive_globs=pin["sensitive"])
    file_snapshot, _ = _load_raw_file(str(tmp_path))
    assert (
        classify_change(_glob_state_map(pin_snapshot), _glob_state_map(file_snapshot))
        is Classification.weaken
    )


# --- 3. adding a glob applies immediately and rewrites the pin --------------


def test_adding_a_glob_applies_immediately_and_rewrites_pin(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"])
    src1 = load_file_policy(str(tmp_path))
    assert src1.snapshot().blocked_globs == ("a/**",)
    pin1 = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin1["blocked"] == ["a/**"]

    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    src2 = load_file_policy(str(tmp_path))
    assert set(src2.snapshot().blocked_globs) == {"a/**", "b/**"}
    pin2 = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin2["blocked"]) == {"a/**", "b/**"}


# --- 4. dropping a glob: still enforced, pin unchanged, one warning --------


def test_dropping_a_glob_keeps_it_blocked_pin_unchanged_warns_once(tmp_path, caplog):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src1 = load_file_policy(str(tmp_path))
        src2 = load_file_policy(str(tmp_path))  # repeated load of the SAME file state

    assert "b/**" in src1.snapshot().blocked_globs  # still enforced
    assert "b/**" in src2.snapshot().blocked_globs

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}  # unchanged

    drop_warnings = [r for r in caplog.records if "drops" in r.message]
    assert len(drop_warnings) == 1


# --- 5. deleted/malformed file after adoption: pin still applies, no crash -


def _corrupt_file(tmp_path, corrupt: str) -> None:
    path = tmp_path / "doberman.policy.yaml"
    if corrupt == "deleted":
        path.unlink()
    else:
        path.write_text(corrupt, encoding="utf-8")


@pytest.mark.parametrize(
    "corrupt",
    [
        "deleted",
        "not: valid: yaml: [",
        "- just\n- a\n- list\n",
        'version: 2\nblocked: ["a/**"]\n',
        'blocked: "a/**"\n',
    ],
    ids=["deleted", "malformed-yaml", "non-mapping", "bad-version", "blocked-not-a-list"],
)
def test_bad_file_state_after_adoption_pin_still_applies_one_warning(tmp_path, caplog, corrupt):
    _write_policy_file(tmp_path, blocked=["a/**"])
    load_file_policy(str(tmp_path))  # adopt

    _corrupt_file(tmp_path, corrupt)

    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))

    assert src is not None
    assert "a/**" in src.snapshot().blocked_globs  # pin still applies
    assert len(caplog.records) == 1  # no exception, exactly one warning


def test_unknown_top_level_key_warns_but_known_keys_still_apply(tmp_path, caplog):
    _write_policy_file(
        tmp_path, text=yaml.safe_dump({"version": 1, "blocked": ["a/**"], "mystery": "x"})
    )
    with caplog.at_level(logging.WARNING, logger="doberman.policy.sources"):
        src = load_file_policy(str(tmp_path))
    assert src.snapshot().blocked_globs == ("a/**",)
    assert any("unknown key" in r.message for r in caplog.records)


# --- 6. `doberman policy-file --accept` ------------------------------------


class _Approve:
    def __init__(self, code="999999"):
        self._code = code

    def confirm(self, message):
        return True

    def read_code(self, message):
        return self._code


class _Decline:
    def confirm(self, message):
        return False

    def read_code(self, message):  # pragma: no cover — never reached after a decline
        raise AssertionError("read_code must not be reached after a declined confirm")


def _use_prompter(monkeypatch, prompter_factory):
    # `policy_file()` constructs the already-imported top-level `CliPrompter`
    # name in `cli.main`, not a lazy re-import -- patch that binding directly
    # (mirrors test_cli_memory_reset.py / test_cli_taint_clear.py).
    monkeypatch.setattr(cli_main, "CliPrompter", prompter_factory)


def _enrolled_code() -> str:
    totp.enroll()
    secret = totp._read_secret()
    assert secret is not None
    return pyotp.TOTP(secret).now()


def test_accept_nothing_pending_exits_zero(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**"])
    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "nothing to accept" in result.stdout


def test_accept_with_valid_factor_rewrites_pin_and_ledgers_weaken(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))  # adopt both

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve(_PASSWORD))

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 0

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert pin["blocked"] == ["a/**"]  # b/** accepted as dropped

    rows = asyncio.run(read_policy_changes(str(tmp_path)))
    assert rows[0]["classification"] == "weaken"
    assert rows[0]["approved"] == 1
    assert rows[0]["approval_method"] == "password"


def test_accept_denied_leaves_pin_unchanged_and_ledgers_denial(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))

    _write_policy_file(tmp_path, blocked=["a/**"])  # drop b/**
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, lambda: _Approve("wrong password"))

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1

    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}  # unchanged

    rows = asyncio.run(read_policy_changes(str(tmp_path)))
    assert rows[0]["approved"] == 0
    assert rows[0]["classification"] == "weaken"


def test_accept_declined_confirm_leaves_pin_unchanged(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))

    _write_policy_file(tmp_path, blocked=["a/**"])
    password.enroll(_PASSWORD)
    _use_prompter(monkeypatch, _Decline)

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}


def test_accept_with_no_factor_enrolled_fails_closed(tmp_path):
    # Neither TOTP nor password enrolled (conftest isolates both to empty temp
    # paths): the accept must fail closed, no confirm-only fallback.
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))
    _write_policy_file(tmp_path, blocked=["a/**"])

    result = runner.invoke(app, ["policy-file", "--accept", "--path", str(tmp_path)])
    assert result.exit_code == 1
    assert "enrolled possession factor" in result.output
    pin = json.loads(_pin_path(tmp_path).read_text(encoding="utf-8"))
    assert set(pin["blocked"]) == {"a/**", "b/**"}


def test_status_shows_pending_drop(tmp_path):
    _write_policy_file(tmp_path, blocked=["a/**", "b/**"])
    load_file_policy(str(tmp_path))
    _write_policy_file(tmp_path, blocked=["a/**"])

    result = runner.invoke(app, ["policy-file", "--path", str(tmp_path)])
    assert result.exit_code == 0
    assert "Pending" in result.stdout
    assert "b/**" in result.stdout


# --- 7. a file under .doberman/ is ignored ----------------------------------


def test_file_under_dot_doberman_is_ignored(tmp_path):
    ddir = tmp_path / ".doberman"
    ddir.mkdir()
    (ddir / "doberman.policy.yaml").write_text(
        yaml.safe_dump({"version": 1, "blocked": ["a/**"]}), encoding="utf-8"
    )
    assert load_file_policy(str(tmp_path)) is None
    assert effective_policy(str(tmp_path)).is_empty


# --- 8. memoization ----------------------------------------------------------


def test_effective_policy_memoizes_discovery(tmp_path, monkeypatch):
    _write_policy_file(tmp_path, blocked=["a/**"])

    from doberman.engine import registry

    calls = {"n": 0}
    real = registry.discover_policy_sources

    def _counting():
        calls["n"] += 1
        return real()

    monkeypatch.setattr(registry, "discover_policy_sources", _counting)

    effective_policy(str(tmp_path))
    effective_policy(str(tmp_path))
    assert calls["n"] == 1

    # Changing the file busts the cache: discovery runs again.
    _write_policy_file(tmp_path, blocked=["a/**", "c/**"])
    effective_policy(str(tmp_path))
    assert calls["n"] == 2
