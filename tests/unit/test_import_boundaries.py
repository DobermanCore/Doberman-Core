"""Issue #324 — the objective-rules hot path must stay free of the subjective
layer's ML import chain (numpy/scipy/river).

Host hooks rebuild ``ObjectiveGuardrail`` (``doberman.engine.rules`` /
``doberman.engine.objective`` / ``doberman.engine.trifecta``) on *every* tool
call, in a cold-start CLI process. Before this slice, staying clear of
numpy/scipy/river was a convention (see the ``doberman.engine.trifecta``
module docstring) that only code review enforced. This file turns the
``import-linter`` "forbidden" contract declared in ``pyproject.toml`` into a
test-suite-visible, CI-enforced invariant, covering three things ``lint-imports``
alone wouldn't make obvious from a red/green CI badge:

* the contract in ``pyproject.toml`` hasn't been silently narrowed (raise-only
  applies to CI guards too);
* the "forbidden" mechanism itself actually catches both a direct import and an
  indirect/transitive chain (a plugin's own dependency reaching numpy/river),
  matching the exact regression this issue is guarding against;
* the mechanism does NOT over-constrain ``doberman.engine.registry`` — the
  legitimate, ML-free discovery seam that ``engine.objective`` shares with the
  subjective side (see the issue's "check before finalizing the source list").
"""

import grimp
import importlinter.api  # noqa: F401 -- import configures importlinter's app settings
from importlinter.api import read_configuration
from importlinter.contracts.forbidden import ForbiddenContract

CONTRACT_NAME = "Objective-rules hot path must not depend on the subjective ML import chain"


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
        "doberman.engine.rules",
        "doberman.engine.trifecta",
        "doberman.engine.objective",
    }
    assert set(options["forbidden_modules"]) == {
        "doberman.engine.subjective",
        "doberman.engine.detectors",
        "numpy",
        "scipy",
        "river",
    }


def test_contract_is_kept_against_the_real_codebase():
    cfg = read_configuration()
    session_options = cfg["session_options"]
    graph = grimp.build_graph(*session_options["root_packages"], include_external_packages=True)
    contract = ForbiddenContract(
        name=CONTRACT_NAME, session_options=session_options, contract_options=_contract_options()
    )
    check = contract.check(graph, verbose=False)
    assert check.kept, "the real codebase must not violate the objective-rules ML boundary"


def _synthetic_graph(*modules: str) -> grimp.ImportGraph:
    graph = grimp.ImportGraph()
    for module in modules:
        graph.add_module(module)
    return graph


def test_contract_catches_a_direct_forbidden_import():
    # Models the exact regression this issue guards against: a new rule module
    # reaches straight for numpy instead of staying a pure/models-only leaf.
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.engine.rules",
        "doberman.engine.rules.leaky",
        "doberman.engine.trifecta",
        "doberman.engine.objective",
        "numpy",
    )
    graph.add_import(importer="doberman.engine.rules.leaky", imported="numpy")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is False


def test_contract_catches_an_indirect_forbidden_import_chain():
    # The riskier case: a rule doesn't import river directly, it imports some
    # OTHER module that does. The "forbidden" contract must still catch this
    # (allow_indirect_imports defaults to False, i.e. indirect chains count).
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.engine.rules",
        "doberman.engine.rules.helper",
        "doberman.engine.trifecta",
        "doberman.engine.objective",
        "doberman.some_other_helper",
        "river",
    )
    graph.add_import(importer="doberman.engine.rules.helper", imported="doberman.some_other_helper")
    graph.add_import(importer="doberman.some_other_helper", imported="river")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is False


def test_contract_permits_the_shared_registry_dependency():
    # engine.objective legitimately imports engine.registry (discover_rules) to
    # run plugin rules alongside the built-ins. registry.py itself is a thin,
    # ML-free entry-point loader (its ML-adjacent discovery functions, e.g. for
    # algebra adapters, import their targets lazily and are never reached from
    # the objective path) so it is deliberately NOT in forbidden_modules. A
    # contract that (wrongly) treated registry as tainted would break this
    # legitimate, everyday import.
    graph = _synthetic_graph(
        "doberman",
        "doberman.engine",
        "doberman.engine.rules",
        "doberman.engine.trifecta",
        "doberman.engine.objective",
        "doberman.engine.registry",
    )
    graph.add_import(importer="doberman.engine.objective", imported="doberman.engine.registry")
    contract = ForbiddenContract(
        name=CONTRACT_NAME,
        session_options={"root_packages": ["doberman"], "include_external_packages": True},
        contract_options=_contract_options(),
    )
    assert contract.check(graph, verbose=False).kept is True
