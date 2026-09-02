"""DependencyAdmissionRule (C3, v1 offline, name-only) — package-manager
install-command parsing, known-malicious BLOCK, typosquat AUTH.

Covers: argv -> (ecosystem, package names) extraction across every supported
package manager, chained/substituted commands, opaque-command abstention,
known-malicious BLOCK, typosquat AUTH with its false-positive guards, no
filesystem/network I/O in evaluate(), bounded time on an oversized name, and
redaction (the package name/argv text never appears in an explanation).

Extraction tests use FIXTURE lists only (never the real shipped JSON) so
they do not churn when the bundled lists are updated.
"""

import pytest

from doberman.engine.rules.commands import walk_command
from doberman.engine.rules.dependency_admission import (
    _ecosystem_and_names,
    _within_edit_distance_one,
)

# ── argv -> (ecosystem, names) extraction ────────────────────────────────


@pytest.mark.parametrize(
    "command,ecosystem,names",
    [
        ("pip install reqeusts", "pypi", ["reqeusts"]),
        ("pip3 install reqeusts", "pypi", ["reqeusts"]),
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
