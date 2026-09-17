"""Issue #237 (FM.2) — "a dead daemon changes nothing about inline protection."

The policy core (engine/roles/policy/storage/auth/subjective/egress) must never
depend on ``doberman.monitor`` — the contract in ``pyproject.toml`` (declared
alongside FM.1, PR #512) is what actually makes that hard rule true: if the
live decision path cannot even *import* the ambient monitor, the monitor's
liveness — running, crashed, or never started — cannot change what that path
does. This file turns that contract into a test-suite-visible, CI-enforced
invariant, the same way ``test_import_boundaries.py`` does for the
objective-rules/ML boundary:

* the contract in ``pyproject.toml`` hasn't been silently narrowed (raise-only
  applies to CI guards too) since FM.1 added it;
* the "forbidden" mechanism actually catches both a direct import and an
  indirect/transitive chain (some policy-core module reaching
  ``doberman.monitor`` through an intermediary), not just the obvious case;
* the real codebase — including this issue's new ``doberman.monitor.daemon`` —
  keeps the contract KEPT.
"""

import grimp
import importlinter.api  # noqa: F401 -- import configures importlinter's app settings
from importlinter.api import read_configuration
from importlinter.contracts.forbidden import ForbiddenContract

CONTRACT_NAME = "Policy core must not depend on the ambient monitor"


def _contract_options() -> dict:
    cfg = read_configuration()
    for options in cfg["contracts_options"]:
        if options["name"] == CONTRACT_NAME:
            return options
    raise AssertionError(f"contract {CONTRACT_NAME!r} is missing from pyproject.toml")


def test_contract_is_declared_with_the_exact_source_and_forbidden_sets():
    options = _contract_options()
    assert options["type"] == "forbidden"
    assert set(options["source_modules"]) == {
        "doberman.engine",
        "doberman.roles",
        "doberman.policy",
        "doberman.storage",
        "doberman.auth",
        "doberman.subjective",
        "doberman.egress",
    }
    assert set(options["forbidden_modules"]) == {"doberman.monitor"}


def test_contract_is_kept_against_the_real_codebase():
    """The concrete proof: as shipped, including this issue's new
    ``doberman.monitor.daemon``, no policy-core module imports it — so the
    live gate cannot depend on this daemon's liveness, structurally."""
    cfg = read_configuration()
    session_options = cfg["session_options"]
    graph = grimp.build_graph(*session_options["root_packages"], include_external_packages=True)
    contract = ForbiddenContract(
        name=CONTRACT_NAME, session_options=session_options, contract_options=_contract_options()
    )
    check = contract.check(graph, verbose=False)
    assert check.kept, (
        "the real codebase must not let the policy core depend on the ambient monitor"
    )


def _synthetic_graph(*modules: str) -> grimp.ImportGraph:
    graph = grimp.ImportGraph()
    for module in modules:
        graph.add_module(module)
    return graph


def test_contract_catches_a_direct_forbidden_import():
    # Models the regression this contract guards against: a policy-core
    # module reaches straight for doberman.monitor (e.g. "just this once" to
    # read a status field) instead of staying independent of it. Every
    # declared source_module must exist in the graph for ForbiddenContract to
    # check it at all - most are irrelevant to this scenario and carry no
    # imports of their own.
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.engine.leaky",
        "doberman.roles",
        "doberman.policy",
        "doberman.storage",
        "doberman.auth",
        "doberman.subjective",
        "doberman.egress",
        "doberman.monitor",
        "doberman.monitor.daemon",
    )
    graph.add_import(importer="doberman.engine.leaky", imported="doberman.monitor.daemon")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is False


def test_contract_catches_an_indirect_forbidden_import_chain():
    # The riskier case: a policy-core module doesn't import doberman.monitor
    # directly, it imports some OTHER module that does. The "forbidden"
    # contract must still catch this (allow_indirect_imports defaults to
    # False, i.e. indirect chains count).
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.roles",
        "doberman.policy",
        "doberman.storage",
        "doberman.storage.helper",
        "doberman.auth",
        "doberman.subjective",
        "doberman.egress",
        "doberman.some_other_helper",
        "doberman.monitor",
    )
    graph.add_import(importer="doberman.storage.helper", imported="doberman.some_other_helper")
    graph.add_import(importer="doberman.some_other_helper", imported="doberman.monitor")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is False


def test_contract_permits_the_monitor_depending_on_the_policy_core():
    # The dependency only ever runs the other way: doberman.monitor.daemon
    # legitimately imports doberman.engine/storage/policy to score what it
    # observes (see the module's own docstring). A contract that (wrongly)
    # forbade this direction too would break the daemon's entire reason for
    # existing.
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.engine.decision_engine",
        "doberman.roles",
        "doberman.policy",
        "doberman.storage",
        "doberman.auth",
        "doberman.subjective",
        "doberman.egress",
        "doberman.monitor",
        "doberman.monitor.daemon",
    )
    graph.add_import(importer="doberman.monitor.daemon", imported="doberman.engine.decision_engine")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is True
