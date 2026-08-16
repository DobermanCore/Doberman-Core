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


def test_git_pull_and_fetch_stay_gated():
    # Excluded by design (ADR 0075): the route is the configured remote, which
    # static parsing cannot know. Both remain AUTH with the egress reason.
    for command in ("git pull", "git fetch origin"):
        action = normalize("shell_exec", {"command": command})
        result = RULE.evaluate(action, EvalContext(mode="balanced"))
        assert result.verdict is Verdict.AUTH
        assert ReasonCode.egress_requires_auth in result.reason_codes
