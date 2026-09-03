"""DependencyAdmissionRule (C3, v1 offline, name-only) — package-manager
install-command parsing, known-malicious BLOCK, typosquat AUTH.

Covers: argv -> (ecosystem, package names) extraction across every supported
package manager, chained/substituted commands, opaque-command abstention,
known-malicious BLOCK, typosquat AUTH with its false-positive guards, no
filesystem/network I/O in evaluate(), bounded time on an oversized name,
redaction (the package name/argv text never appears in an explanation), and
(Task 4) registration in BUILTIN_RULE_TYPES + no-I/O and bounded-time
property tests.

Extraction tests use FIXTURE lists only (never the real shipped JSON) so
they do not churn when the bundled lists are updated.
"""

import builtins
import os
import pathlib
import random
import socket
from datetime import datetime, timezone

import pytest

from doberman.engine.objective import ObjectiveGuardrail
from doberman.engine.rules.commands import walk_command
from doberman.engine.rules.dependency_admission import (
    DependencyAdmissionRule,
    _ecosystem_and_names,
    _is_installable_name,
    _within_edit_distance_one,
)
from doberman.models import ActionType, EvalContext, ReasonCode, SecurityObject, Verdict

# ── argv -> (ecosystem, names) extraction ────────────────────────────────


@pytest.mark.parametrize(
    "command,ecosystem,names",
    [
        ("pip install reqeusts", "pypi", ["reqeusts"]),
        ("pip3 install reqeusts", "pypi", ["reqeusts"]),
        ("pipx install reqeusts", "pypi", ["reqeusts"]),
        ("python -m pip install reqeusts", "pypi", ["reqeusts"]),
        ("python3 -m pip install reqeusts", "pypi", ["reqeusts"]),
        ("uv add reqeusts", "pypi", ["reqeusts"]),
        ("poetry add reqeusts", "pypi", ["reqeusts"]),
        ("npm install reqeusts", "npm", ["reqeusts"]),
        ("npm i reqeusts", "npm", ["reqeusts"]),
        ("pnpm add reqeusts", "npm", ["reqeusts"]),
        ("yarn add reqeusts", "npm", ["reqeusts"]),
        ("bun add reqeusts", "npm", ["reqeusts"]),
        ("cargo add reqeusts", "cargo", ["reqeusts"]),
        ("gem install reqeusts", "rubygems", ["reqeusts"]),
        ("go get reqeusts", "go", ["reqeusts"]),
    ],
)
def test_ecosystem_verb_table_covers_every_package_manager(command, ecosystem, names):
    segments, _, _ = walk_command(command)
    assert len(segments) == 1
    assert _ecosystem_and_names(segments[0]) == (ecosystem, names)


def test_version_pin_and_extras_are_stripped():
    segments, _, _ = walk_command("pip install requests==2.31.0")
    assert _ecosystem_and_names(segments[0]) == ("pypi", ["requests"])
    segments, _, _ = walk_command("pip install requests[security]")
    assert _ecosystem_and_names(segments[0]) == ("pypi", ["requests"])
    segments, _, _ = walk_command("npm install left-pad@1.3.0")
    assert _ecosystem_and_names(segments[0]) == ("npm", ["left-pad"])
    segments, _, _ = walk_command("go get golang.org/x/tools@v0.1.0")
    assert _ecosystem_and_names(segments[0]) == ("go", ["golang.org/x/tools"])


def test_scoped_npm_package_keeps_its_leading_at_sign():
    segments, _, _ = walk_command("npm install @myorg/utils@2.0.0")
    assert _ecosystem_and_names(segments[0]) == ("npm", ["@myorg/utils"])


def test_multiple_packages_in_one_invocation():
    segments, _, _ = walk_command("npm install left-pad is-odd")
    assert _ecosystem_and_names(segments[0]) == ("npm", ["left-pad", "is-odd"])


def test_requirements_file_flag_is_skipped_not_read():
    segments, _, _ = walk_command("pip install -r requirements.txt")
    assert _ecosystem_and_names(segments[0]) is None  # no name, no file read


def test_local_and_vcs_and_url_operands_are_not_names():
    for cmd in (
        "pip install -e .",
        "pip install git+https://github.com/x/y.git",
        "pip install https://example.test/pkg.whl",
    ):
        segments, _, _ = walk_command(cmd)
        assert _ecosystem_and_names(segments[0]) is None, cmd


def test_windows_local_path_names_are_rejected():
    # A backslash anywhere, or a drive prefix (e.g. "C:"), marks a local
    # filesystem path rather than a registry package name — never installable.
    assert _is_installable_name("c:\\users\\me\\pkg") is False
    assert _is_installable_name("..\\relative\\pkg") is False
    assert _is_installable_name("c:/users/me/pkg") is False
    assert _is_installable_name("requests") is True


def test_bare_install_with_no_operand_abstains():
    segments, _, _ = walk_command("npm install")
    assert _ecosystem_and_names(segments[0]) is None


def test_unrecognized_verb_returns_none():
    segments, _, _ = walk_command("echo hello")
    assert _ecosystem_and_names(segments[0]) is None


def test_publish_subcommand_is_not_an_install_admission_point():
    # npm publish / cargo publish / twine upload are C6's table, not C3's.
    segments, _, _ = walk_command("npm publish")
    assert _ecosystem_and_names(segments[0]) is None


# ── edit-distance-1 primitive ─────────────────────────────────────────────


def test_within_edit_distance_one_substitution():
    assert _within_edit_distance_one("requestx", "requests") is True


def test_within_edit_distance_one_insertion_and_deletion():
    assert _within_edit_distance_one("request", "requests") is True
    assert _within_edit_distance_one("requests", "request") is True


def test_within_edit_distance_one_identical():
    assert _within_edit_distance_one("requests", "requests") is True


def test_within_edit_distance_one_rejects_distance_two():
    assert _within_edit_distance_one("requestsxx", "requests") is False
    assert _within_edit_distance_one("rqeusts", "requests") is False  # transposition, distance 2


def test_within_edit_distance_one_rejects_length_gap_over_one():
    assert _within_edit_distance_one("re", "requests") is False


# ── DependencyAdmissionRule classification ────────────────────────────────

FIXTURE_KNOWN_MALICIOUS = {"pypi": frozenset({"evilpkg-fixture"}), "npm": frozenset()}
FIXTURE_POPULAR_BY_LEN = {
    "pypi": {8: frozenset({"requests"})},
    "npm": {7: frozenset({"request"})},
}
RULE = DependencyAdmissionRule(
    known_malicious=FIXTURE_KNOWN_MALICIOUS, popular_by_len=FIXTURE_POPULAR_BY_LEN
)


def _action(action_type=ActionType.shell_exec):
    return SecurityObject(
        id="dep-1",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=action_type,
        tool_name="run",
    )


def _ctx(command: str) -> EvalContext:
    return EvalContext(metadata={"raw_arguments": {"command": command}})


def test_known_malicious_name_blocks():
    result = RULE.evaluate(_action(), _ctx("pip install evilpkg-fixture"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.dependency_known_malicious in result.reason_codes


def test_typosquat_of_popular_name_requires_auth():
    # "requestx" is a one-character substitution away from the fixture's "requests".
    result = RULE.evaluate(_action(), _ctx("pip install requestx"))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.dependency_name_typosquat in result.reason_codes


def test_popular_name_itself_passes():
    result = RULE.evaluate(_action(), _ctx("pip install requests"))
    assert result.verdict is Verdict.PASS


def test_npm_request_is_popular_not_a_typosquat_of_itself():
    # The load-bearing FP guard: npm's real "request" package must pass,
    # not be flagged as a typosquat of anything.
    result = RULE.evaluate(_action(), _ctx("npm install request"))
    assert result.verdict is Verdict.PASS


def test_scoped_internal_package_passes():
    result = RULE.evaluate(_action(), _ctx("npm install @myorg/utils"))
    assert result.verdict is Verdict.PASS


def test_short_names_are_never_distance_checked():
    for name in ("re", "abc"):
        result = RULE.evaluate(_action(), _ctx(f"pip install {name}"))
        assert result.verdict is Verdict.PASS, name


def test_unrelated_name_passes():
    result = RULE.evaluate(_action(), _ctx("pip install some-totally-unrelated-package"))
    assert result.verdict is Verdict.PASS


def test_opaque_shell_payload_abstains_not_crashes():
    # commands.py's own DestructiveCommandRule already raises opaque_command
    # (AUTH) for this shape; this rule correctly abstains rather than
    # duplicating that reason code.
    result = RULE.evaluate(_action(), _ctx('bash -c "pip install evilpkg-fixture"'))
    assert result.verdict is Verdict.PASS


def test_unparseable_command_abstains():
    result = RULE.evaluate(_action(), _ctx("pip install 'unterminated"))
    assert result.verdict is Verdict.PASS


def test_chained_command_still_catches_the_installed_segment():
    result = RULE.evaluate(_action(), _ctx("echo hi && pip install evilpkg-fixture"))
    assert result.verdict is Verdict.BLOCK


def test_non_command_action_type_does_not_misread_target_as_a_command():
    action = SecurityObject(
        id="dep-2",
        ts=datetime(2026, 9, 2, tzinfo=timezone.utc),
        agent_role="unknown",
        action_type=ActionType.file_read,
        tool_name="read_file",
        target="pip install evilpkg-fixture",  # a file NAME, not a command
    )
    result = RULE.evaluate(action, EvalContext())
    assert result.verdict is Verdict.PASS


def test_explanation_never_contains_the_package_name():
    result = RULE.evaluate(_action(), _ctx("pip install evilpkg-fixture"))
    assert "evilpkg-fixture" not in result.explanation
    result = RULE.evaluate(_action(), _ctx("pip install requestx"))
    assert "requestx" not in result.explanation


def test_bundled_data_files_load_and_contain_seed_entries():
    # Smoke-tests the REAL shipped JSON (not the fixtures above) — proves
    # pyproject.toml needs no package-data change (see the plan's Files
    # section) and that the seed names below actually made it into the
    # committed data.
    #
    # NOTE: the known-malicious PyPI list is a controller-verified seed
    # override (C3-seed-verified.md, binding) — the candidates the planner
    # first proposed (colourama, python3-dateutil) returned no live OSV
    # advisory, so v1 ships an EMPTY pypi known-malicious list rather than
    # an unverifiable one; only the npm list (a real, OSV-verified 2017
    # typosquat campaign) is populated.
    from doberman.engine.rules.dependency_admission import (
        _DEFAULT_KNOWN_MALICIOUS,
        _DEFAULT_POPULAR_BY_LEN,
    )

    assert _DEFAULT_KNOWN_MALICIOUS["pypi"] == frozenset()
    assert "crossenv" in _DEFAULT_KNOWN_MALICIOUS["npm"]
    popular_pypi_all = {n for bucket in _DEFAULT_POPULAR_BY_LEN["pypi"].values() for n in bucket}
    assert "requests" in popular_pypi_all
    popular_npm_all = {n for bucket in _DEFAULT_POPULAR_BY_LEN["npm"].values() for n in bucket}
    assert "request" in popular_npm_all


# ── Task 4: registration + no-I/O + bounded-time property tests ──────────


def test_rule_is_registered_in_builtin_rule_types():
    from doberman.engine.rules import BUILTIN_RULE_TYPES

    assert DependencyAdmissionRule in BUILTIN_RULE_TYPES


def test_objective_guardrail_reaches_block_via_the_real_registration():
    # Uses the REAL bundled data (not fixtures) — proves end-to-end wiring
    # through ObjectiveGuardrail, not just direct RULE.evaluate() calls.
    #
    # DEVIATION FROM BRIEF (documented, not improvised): the brief's literal
    # example used "pip install colourama", but colourama was already
    # rejected by the Task 3 controller-verified seed decision (see
    # C3-seed-verified.md, and this file's own
    # test_bundled_data_files_load_and_contain_seed_entries below) — v1
    # ships an EMPTY pypi known-malicious list, so colourama matches
    # nothing in real data. Swapped to npm/"crossenv", the one entry this
    # file already asserts is real and OSV-verified, to keep the test's
    # actual intent (prove BLOCK via the real bundled data, not fixtures).
    guardrail = ObjectiveGuardrail(load_plugins=False)
    result = guardrail.evaluate(_action(), _ctx("npm install crossenv"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.dependency_known_malicious in result.reason_codes


def test_no_filesystem_or_network_io_in_evaluate(monkeypatch):
    # Construct the rule from FIXTURES (no I/O at construction either) so
    # the assertion is airtight: the module's own import-time data load
    # already happened before this test runs (pytest collection imports
    # the module), and this rule instance never touches the real files.
    #
    # The monkeypatches below are applied AFTER
    # doberman.engine.rules.dependency_admission was already imported (at
    # collection time, via the module-level imports above), so they cannot
    # interfere with the module's own import-time `_load_json_lists()` call
    # — only with I/O performed inside evaluate() itself.
    rule = DependencyAdmissionRule(
        known_malicious=FIXTURE_KNOWN_MALICIOUS, popular_by_len=FIXTURE_POPULAR_BY_LEN
    )

    def _forbidden(*_a, **_k):
        raise AssertionError("evaluate() performed forbidden I/O")

    monkeypatch.setattr(builtins, "open", _forbidden)
    monkeypatch.setattr(pathlib.Path, "read_text", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)
    monkeypatch.setattr(os, "environ", {})

    verbs = ["pip install", "npm install", "cargo add", "go get", "gem install"]
    names = ["requestx", "requests", "evilpkg-fixture", "left-pad", "@myorg/utils", "a", ""]
    rng = random.Random(1337)  # noqa: S311 — fuzz-input generator, not cryptographic
    for _ in range(200):
        cmd = f"{rng.choice(verbs)} {rng.choice(names)}{rng.randint(0, 999)}"
        rule.evaluate(_action(), _ctx(cmd))  # must not raise, must not touch patched I/O


def test_bounded_time_on_an_oversized_candidate_name(monkeypatch):
    # Non-vacuous: run against the REAL bundled popular list (not the tiny
    # fixture, which could "pass" this test even without bucketing, simply
    # because there is little to scan) and prove the length-bucket lookup
    # short-circuits BEFORE any edit-distance call — a call counter, not
    # just a time budget, so a regression that removes bucketing fails
    # deterministically instead of just "usually" being fast.
    import doberman.engine.rules.dependency_admission as dep_mod

    rule = DependencyAdmissionRule()  # real bundled known-malicious + popular lists
    calls = 0
    real_within_edit_distance_one = dep_mod._within_edit_distance_one

    def _counting(a: str, b: str) -> bool:
        nonlocal calls
        calls += 1
        return real_within_edit_distance_one(a, b)

    monkeypatch.setattr(dep_mod, "_within_edit_distance_one", _counting)

    huge_name = "a" * 4096  # 4KB name — must not scan the full popular list per-char
    result = rule.evaluate(_action(), _ctx(f"pip install {huge_name}"))
    assert result.verdict is Verdict.PASS  # no bucket at that length; abstains cheaply
    assert calls == 0  # bucketing short-circuits before any edit-distance call
