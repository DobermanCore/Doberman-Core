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


# ── #554: popular-seed expansion hygiene ──────────────────────────────────


def test_popular_seed_is_sorted_deduped_and_has_no_denylist_collision():
    # Reads the raw shipped JSON directly (not the loaded frozensets, which
    # would hide ordering/duplicate issues) — guards the two provenance
    # rules data/README.md commits to: the file stays sorted/deduped, and
    # no popular name ever also appears on the known-malicious list for the
    # same ecosystem (that would make a package simultaneously "exempt from
    # the typosquat check" and "instant BLOCK", a self-contradiction).
    import json as _json
    from importlib.resources import files as _files

    data = _files("doberman.engine.rules.data")
    popular = _json.loads(data.joinpath("popular_packages.json").read_text(encoding="utf-8"))
    malicious = _json.loads(
        data.joinpath("known_malicious_packages.json").read_text(encoding="utf-8")
    )

    # Only the three ecosystems #554 actually expanded are alphabetically
    # sorted; rubygems/go are untouched curated lists from the original
    # seed and keep their original (non-alphabetical) order — reordering
    # data this slice never touched would be pure diff noise.
    sorted_ecosystems = {"pypi", "npm", "cargo"}
    for ecosystem, names in popular.items():
        if ecosystem == "generated_at":
            continue
        if ecosystem in sorted_ecosystems:
            assert names == sorted(names), f"{ecosystem} popular list is not sorted"
        assert len(names) == len(set(names)), f"{ecosystem} popular list has duplicates"
        collisions = set(names) & set(malicious.get(ecosystem, []))
        assert not collisions, f"{ecosystem} popular/known-malicious collision: {collisions}"


@pytest.mark.parametrize(
    "command",
    [
        "pip install pydantic",
        "npm install cross-env",
        "cargo add hashbrown",
    ],
)
def test_new_seed_entries_are_recognized_as_known(command):
    # Representative new entries from the #554 expansion (real bundled
    # data) evaluate to the "known popular package" outcome: PASS, not
    # AUTH — same shape as the pre-existing
    # test_npm_vuex_is_popular_not_a_typosquat_of_vue-style assertions
    # above.
    result = DependencyAdmissionRule().evaluate(_action(), _ctx(command))
    assert result.verdict is Verdict.PASS


# ── per-ecosystem value-flag regression ───────────────────────────────────
# CRITICAL fix (whole-branch review): pip's -r/-c/-i/--index-url/--extra-
# index-url used to be ONE global value-flag set applied to every
# ecosystem, so e.g. `npm i -i crossenv` swallowed the malicious operand as
# "-i"'s value and silently PASSed. Each ecosystem now carries its own real
# value-flag set (npm --registry/--prefix/-w, cargo --git/--path/--registry/
# --features/--rename/-p, gem -v/-s/-i where -i really is gem's
# --install-dir) so none of -i/-r/-c/--index-url is misread as a real npm,
# yarn, pnpm, bun, or cargo flag.

_VALUE_FLAG_PROBE_MALICIOUS = {"npm": frozenset({"crossenv"}), "cargo": frozenset({"crossenv"})}
_VALUE_FLAG_PROBE_RULE = DependencyAdmissionRule(
    known_malicious=_VALUE_FLAG_PROBE_MALICIOUS, popular_by_len={}
)


@pytest.mark.parametrize(
    "command",
    [
        "npm i -i crossenv",
        "npm i -r crossenv",
        "npm i --index-url crossenv",
        "yarn add -i crossenv",
        "pnpm add -c crossenv",
        "bun add -r crossenv",
        "cargo add -r crossenv",
    ],
)
def test_pip_value_flags_no_longer_leak_into_other_ecosystems(command):
    result = _VALUE_FLAG_PROBE_RULE.evaluate(_action(), _ctx(command))
    assert result.verdict is Verdict.BLOCK, command


def test_gem_install_dir_is_a_real_gem_flag_and_still_consumes_its_value():
    # The mirror image: gem's `-i` really IS `--install-dir` on gem's own
    # CLI, so this one command correctly swallows its operand and never
    # reaches classification at all — "evilgem" is also not on any bundled
    # list, so even if it did reach classification it would PASS, but the
    # honest reason here is abstention, not a lucky miss.
    result = _VALUE_FLAG_PROBE_RULE.evaluate(_action(), _ctx("gem install -i evilgem"))
    assert result.verdict is Verdict.PASS


def test_npm_known_malicious_flagship_blocks_via_real_bundled_data():
    # One end-to-end proof against the REAL shipped npm known-malicious
    # list (not the fixture above) that the value-flag fix reaches
    # production data, not just a test fixture.
    rule = DependencyAdmissionRule()
    result = rule.evaluate(_action(), _ctx("npm i -i crossenv"))
    assert result.verdict is Verdict.BLOCK
    assert ReasonCode.dependency_known_malicious in result.reason_codes


# ── pnpm/yarn boolean-flag regression (`-w`/`-W` are NOT npm's `-w`) ──────
# CRITICAL fix: pnpm's `-w`/`--workspace-root` and yarn classic's
# `-W`/`--ignore-workspace-root-check` are BOOLEAN flags on those tools —
# unlike npm's own `-w`/`--workspace <name>`, which takes a value. Applying
# npm's value-flag set to pnpm/yarn swallowed the next operand as the
# flag's "value" and silently PASSed (`pnpm add -w crossenv`, `pnpm install
# -w crossenv`), a fail-closed regression introduced alongside the
# per-ecosystem value-flag split in 67d8a8d.


@pytest.mark.parametrize(
    "command",
    [
        "pnpm add -w crossenv",
        "pnpm install -w crossenv",
        "pnpm add -F app crossenv",  # pnpm's real value flag still consumes its value
        "yarn add -W crossenv",
        "npm i -w app crossenv",  # npm's own -w DOES take a value; crossenv still extracted
        "bun add crossenv",
    ],
)
def test_npm_family_boolean_flags_are_not_misread_as_value_flags(command):
    rule = DependencyAdmissionRule()  # real bundled known-malicious data
    result = rule.evaluate(_action(), _ctx(command))
    assert result.verdict is Verdict.BLOCK, command
    assert ReasonCode.dependency_known_malicious in result.reason_codes


def test_npm_install_cross_env_passes():
    # Sanity: a legit package is unaffected by the pnpm/yarn boolean-flag fix.
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("npm install cross-env"))
    assert result.verdict is Verdict.PASS


def test_pnpm_add_react_passes():
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("pnpm add react"))
    assert result.verdict is Verdict.PASS


# ── uv's pip-compatible shim subcommand ───────────────────────────────────
# IMPORTANT fix: v1 only mapped `uv add` (uv's own verb); `uv pip install X`
# is uv's pip-compatible shim subcommand and used to fall through unmatched
# (`uv`'s verb table only recognized "add"), so it silently PASSed. Mirrors
# the existing `python -m pip` peel.


def test_uv_pip_install_is_treated_as_a_pip_invocation():
    segments, _, _ = walk_command("uv pip install reqests")
    assert _ecosystem_and_names(segments[0]) == ("pypi", ["reqests"])


def test_uv_pip_install_inherits_pips_value_flags():
    segments, _, _ = walk_command("uv pip install -r requirements.txt")
    assert _ecosystem_and_names(segments[0]) is None  # no name, no file read


# ── popular-seed false-positive guards (IMPORTANT) ────────────────────────
# The small starter seed itself manufactured false positives: these four
# real, legitimate package names were each one edit away from an existing
# popular-list entry and not themselves on the list, so they stepped up to
# AUTH. Adding them to the popular seed is a security-relevant data change
# (see data/README.md), not a code change.


def test_npm_vuex_is_popular_not_a_typosquat_of_vue():
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("npm install vuex"))
    assert result.verdict is Verdict.PASS


def test_npm_nest_is_popular_not_a_typosquat_of_next_or_jest():
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("npm install nest"))
    assert result.verdict is Verdict.PASS


def test_pypi_boto_is_popular_not_a_typosquat_of_boto3():
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("pip install boto"))
    assert result.verdict is Verdict.PASS


def test_pypi_request_is_popular_not_a_typosquat_of_requests():
    result = DependencyAdmissionRule().evaluate(_action(), _ctx("pip install request"))
    assert result.verdict is Verdict.PASS


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

    class _ExplodingEnviron:
        """A mapping stand-in for `os.environ` whose read methods raise —
        an empty dict ({}) would pass this test even if evaluate() DID read
        an env var (an absent key just raises KeyError either way), so it
        never actually proved anything. This fails loudly on any read."""

        def __getitem__(self, key):
            raise AssertionError("evaluate() performed forbidden I/O (os.environ[...])")

        def get(self, *_a, **_k):
            raise AssertionError("evaluate() performed forbidden I/O (os.environ.get(...))")

    monkeypatch.setattr(builtins, "open", _forbidden)
    monkeypatch.setattr(pathlib.Path, "read_text", _forbidden)
    monkeypatch.setattr(socket, "socket", _forbidden)

    verbs = ["pip install", "npm install", "cargo add", "go get", "gem install"]
    names = ["requestx", "requests", "evilpkg-fixture", "left-pad", "@myorg/utils", "a", ""]
    rng = random.Random(1337)  # noqa: S311 — fuzz-input generator, not cryptographic

    # A vacuous fuzz loop: every generated name gets a random digit suffix
    # appended, so the exact known-malicious fixture name never matches and
    # the BLOCK branch was never actually exercised here. One exact-name
    # call first, asserted, closes that gap.
    exact_hit = rule.evaluate(_action(), _ctx("pip install evilpkg-fixture"))
    assert exact_hit.verdict is Verdict.BLOCK

    # os.environ is patched with a manual save/restore (NOT `monkeypatch`)
    # scoped tightly around just this loop: pytest's own progress reporting
    # reads `os.environ["COLUMNS"]` for terminal-width detection between
    # the test's call phase and its teardown phase — i.e. while a
    # `monkeypatch`-fixture-scoped patch (undone only at teardown) would
    # still be active — and a KeyError there is normal/handled, but our
    # AssertionError is not, crashing the test run itself.
    real_environ = os.environ
    os.environ = _ExplodingEnviron()  # noqa: B003 — stand-in object, not real env mutation
    try:
        for _ in range(200):
            cmd = f"{rng.choice(verbs)} {rng.choice(names)}{rng.randint(0, 999)}"
            rule.evaluate(_action(), _ctx(cmd))  # must not raise, must not touch patched I/O
    finally:
        os.environ = real_environ  # noqa: B003 — restoring the real object, not clearing it


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


def test_bounded_on_a_one_megabyte_command():
    # Not a performance guarantee: `walk_command`'s own shlex-based parse
    # has a pre-existing, non-linear cost on an oversized single-token
    # payload that this rule does not fix (out of this slice's scope) —
    # measured ~25s locally for a 1 MB command. This only proves
    # `DependencyAdmissionRule.evaluate()` completes rather than hangs.
    # The hang guard is CI's per-test `--timeout`, not a wall-clock bound here:
    # a 90 s bound failed at 97 s on a slow Windows runner (#588).
    rule = DependencyAdmissionRule()
    huge_command = "pip install " + ("a" * (1024 * 1024))
    result = rule.evaluate(_action(), _ctx(huge_command))
    assert result.verdict is Verdict.PASS
